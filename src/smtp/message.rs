/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use std::{
    borrow::Cow,
    fmt::{Debug, Display},
};

#[cfg(feature = "builder")]
use mail_builder::{
    MessageBuilder,
    headers::{HeaderType, address},
};
use smtp_proto::Response;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::SmtpClient;

#[derive(Debug, Default, Clone)]
pub struct Message<'x> {
    pub mail_from: Address<'x>,
    pub rcpt_to: Vec<Address<'x>>,
    pub body: Cow<'x, [u8]>,
}

#[derive(Debug, Default, Clone)]
pub struct Address<'x> {
    pub email: Cow<'x, str>,
    pub parameters: Parameters<'x>,
}

#[derive(Debug, Default, Clone)]
pub struct Parameters<'x> {
    params: Vec<Parameter<'x>>,
}

#[derive(Debug, Default, Clone)]
pub struct Parameter<'x> {
    key: Cow<'x, str>,
    value: Option<Cow<'x, str>>,
}

impl<T: AsyncRead + AsyncWrite + Unpin> SmtpClient<T> {
    /// Sends a message to the server.
    pub async fn send<'x>(
        &mut self,
        message: impl IntoMessage<'x>,
    ) -> crate::Result<Response<String>> {
        // Send mail-from
        let message = message.into_message()?;
        self.mail_from(
            message.mail_from.email.as_ref(),
            &message.mail_from.parameters,
        )
        .await?;

        // Send rcpt-to
        for rcpt in &message.rcpt_to {
            self.rcpt_to(rcpt.email.as_ref(), &rcpt.parameters).await?;
        }

        // Send message
        self.data(message.body.as_ref()).await
    }

    /// Sends a message to the server.
    #[cfg(feature = "dkim")]
    pub async fn send_signed<'x, V: mail_auth::crypto::SigningKey>(
        &mut self,
        message: impl IntoMessage<'x>,
        signer: &mail_auth::dkim::DkimSigner<V, mail_auth::signer::Ready>,
    ) -> crate::Result<Response<String>> {
        use mail_auth::headers::HeaderWriter;

        // Send mail-from
        let message = message.into_message()?;
        self.mail_from(
            message.mail_from.email.as_ref(),
            &message.mail_from.parameters,
        )
        .await?;

        // Send rcpt-to
        for rcpt in &message.rcpt_to {
            self.rcpt_to(rcpt.email.as_ref(), &rcpt.parameters).await?;
        }

        // Sign message
        let signature = signer
            .sign(message.body.as_ref())
            .map_err(|_| crate::Error::MissingCredentials)?;
        let mut signed_message = Vec::with_capacity(message.body.len() + 64);
        signature.write_header(&mut signed_message);
        signed_message.extend_from_slice(message.body.as_ref());

        // Send message
        self.data(&signed_message).await
    }

    /// Sends a message to the server, signing it with DKIM2.
    #[cfg(feature = "dkim")]
    pub async fn send_signed_dkim2<'x>(
        &mut self,
        message: impl IntoMessage<'x>,
        signer: &mail_auth::dkim2::Dkim2Signer<mail_auth::signer::Ready>,
    ) -> crate::Result<Response<String>> {
        use mail_auth::dkim2::Hop;

        // Send mail-from
        let message = message.into_message()?;
        self.mail_from(
            message.mail_from.email.as_ref(),
            &message.mail_from.parameters,
        )
        .await?;

        // Send rcpt-to
        for rcpt in &message.rcpt_to {
            self.rcpt_to(rcpt.email.as_ref(), &rcpt.parameters).await?;
        }

        // Sign message, binding the signature to this SMTP hop
        let signed = signer
            .sign(
                message.body.as_ref(),
                Hop::real(
                    message.mail_from.email.as_ref(),
                    message.rcpt_to.iter().map(|rcpt| rcpt.email.as_ref()),
                ),
                None,
            )
            .map_err(|_| crate::Error::MissingCredentials)?;
        let mut signed_message = Vec::with_capacity(message.body.len() + 64);
        signed.write(&mut signed_message);
        signed_message.extend_from_slice(message.body.as_ref());

        // Send message
        self.data(&signed_message).await
    }

    pub async fn write_message(&mut self, message: &[u8]) -> tokio::io::Result<()> {
        // Transparency procedure
        let mut is_cr_or_lf = false;

        // As per RFC 5322bis, section 2.3:
        // CR and LF MUST only occur together as CRLF; they MUST NOT appear
        // independently in the body.
        // For this reason, we apply the transparency procedure when there is
        // a CR or LF followed by a dot.

        let mut last_pos = 0;
        for (pos, byte) in message.iter().enumerate() {
            if *byte == b'.' && is_cr_or_lf {
                if let Some(bytes) = message.get(last_pos..pos) {
                    self.stream.write_all(bytes).await?;
                    self.stream.write_all(b".").await?;
                    last_pos = pos;
                }
                is_cr_or_lf = false;
            } else {
                is_cr_or_lf = *byte == b'\n' || *byte == b'\r';
            }
        }
        if let Some(bytes) = message.get(last_pos..) {
            self.stream.write_all(bytes).await?;
        }
        self.stream.write_all("\r\n.\r\n".as_bytes()).await?;
        self.stream.flush().await
    }
}

impl<'x> Message<'x> {
    /// Create a new message
    pub fn new<T, U, V>(from: T, to: U, body: V) -> Self
    where
        T: Into<Address<'x>>,
        U: IntoIterator<Item = T>,
        V: Into<Cow<'x, [u8]>>,
    {
        Message {
            mail_from: from.into(),
            rcpt_to: to.into_iter().map(Into::into).collect(),
            body: body.into(),
        }
    }

    /// Create a new empty message.
    pub fn empty() -> Self {
        Message {
            mail_from: Address::default(),
            rcpt_to: Vec::new(),
            body: Default::default(),
        }
    }

    /// Set the sender of the message.
    pub fn from(mut self, address: impl Into<Address<'x>>) -> Self {
        self.mail_from = address.into();
        self
    }

    /// Add a message recipient.
    pub fn to(mut self, address: impl Into<Address<'x>>) -> Self {
        self.rcpt_to.push(address.into());
        self
    }

    /// Set the message body.
    pub fn body(mut self, body: impl Into<Cow<'x, [u8]>>) -> Self {
        self.body = body.into();
        self
    }
}

impl<'x> From<&'x str> for Address<'x> {
    fn from(email: &'x str) -> Self {
        Address {
            email: email.into(),
            parameters: Parameters::default(),
        }
    }
}

impl From<String> for Address<'_> {
    fn from(email: String) -> Self {
        Address {
            email: email.into(),
            parameters: Parameters::default(),
        }
    }
}

impl<'x> Address<'x> {
    pub fn new(email: impl Into<Cow<'x, str>>, parameters: Parameters<'x>) -> Self {
        Address {
            email: email.into(),
            parameters,
        }
    }
}

impl<'x> Parameters<'x> {
    pub fn new() -> Self {
        Self { params: Vec::new() }
    }

    pub fn add(&mut self, param: impl Into<Parameter<'x>>) -> &mut Self {
        self.params.push(param.into());
        self
    }
}

impl<'x> From<&'x str> for Parameter<'x> {
    fn from(value: &'x str) -> Self {
        Parameter {
            key: value.into(),
            value: None,
        }
    }
}

impl<'x> From<(&'x str, &'x str)> for Parameter<'x> {
    fn from(value: (&'x str, &'x str)) -> Self {
        Parameter {
            key: value.0.into(),
            value: Some(value.1.into()),
        }
    }
}

impl From<(String, String)> for Parameter<'_> {
    fn from(value: (String, String)) -> Self {
        Parameter {
            key: value.0.into(),
            value: Some(value.1.into()),
        }
    }
}

impl From<String> for Parameter<'_> {
    fn from(value: String) -> Self {
        Parameter {
            key: value.into(),
            value: None,
        }
    }
}

impl Display for Parameters<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if !self.params.is_empty() {
            for param in &self.params {
                f.write_str(" ")?;
                Display::fmt(&param, f)?;
            }
        }
        Ok(())
    }
}

impl Display for Parameter<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(value) = &self.value {
            write!(f, "{}={}", self.key, value)
        } else {
            f.write_str(&self.key)
        }
    }
}

pub trait IntoMessage<'x> {
    fn into_message(self) -> crate::Result<Message<'x>>;
}

impl<'x> IntoMessage<'x> for Message<'x> {
    fn into_message(self) -> crate::Result<Message<'x>> {
        Ok(self)
    }
}

#[cfg(feature = "builder")]
impl<'x> IntoMessage<'x> for MessageBuilder<'_> {
    fn into_message(self) -> crate::Result<Message<'x>> {
        let mut mail_from = None;
        let mut rcpt_to = std::collections::HashSet::new();

        for (key, value) in self.headers.iter() {
            if key.eq_ignore_ascii_case("from") {
                if let HeaderType::Address(address::Address::Address(addr)) = value {
                    let email = addr.email.trim();
                    if !email.is_empty() {
                        mail_from = email.to_string().into();
                    }
                }
            } else if (key.eq_ignore_ascii_case("to")
                || key.eq_ignore_ascii_case("cc")
                || key.eq_ignore_ascii_case("bcc"))
                && let HeaderType::Address(addr) = value
            {
                match addr {
                    address::Address::Address(addr) => {
                        let email = addr.email.trim();
                        if !email.is_empty() {
                            rcpt_to.insert(email.to_string());
                        }
                    }
                    address::Address::Group(group) => {
                        for addr in &group.addresses {
                            if let address::Address::Address(addr) = addr {
                                let email = addr.email.trim();
                                if !email.is_empty() {
                                    rcpt_to.insert(email.to_string());
                                }
                            }
                        }
                    }
                    address::Address::List(list) => {
                        for addr in list {
                            if let address::Address::Address(addr) = addr {
                                let email = addr.email.trim();
                                if !email.is_empty() {
                                    rcpt_to.insert(email.to_string());
                                }
                            }
                        }
                    }
                }
            }
        }

        if rcpt_to.is_empty() {
            return Err(crate::Error::MissingRcptTo);
        }

        Ok(Message {
            mail_from: mail_from.ok_or(crate::Error::MissingMailFrom)?.into(),
            rcpt_to: rcpt_to
                .into_iter()
                .map(|email| Address {
                    email: email.into(),
                    parameters: Parameters::default(),
                })
                .collect(),
            body: self.write_to_vec()?.into(),
        })
    }
}

#[cfg(feature = "parser")]
impl<'x> IntoMessage<'x> for &'x mail_parser::Message<'_> {
    fn into_message(self) -> crate::Result<Message<'x>> {
        let root = self.root();
        let non_empty = |mailbox: mail_parser::Mailbox<'x>| {
            mailbox
                .address()
                .map(str::trim)
                .filter(|address| !address.is_empty())
        };

        let mail_from = root
            .from()
            .and_then(|from| from.mailboxes().find_map(non_empty))
            .ok_or(crate::Error::MissingMailFrom)?;

        let mut seen = std::collections::HashSet::new();
        let rcpt_to: Vec<Address<'x>> = root
            .all_to()
            .chain(root.all_cc())
            .chain(root.all_bcc())
            .flat_map(|list| list.mailboxes().filter_map(non_empty))
            .filter(|email| seen.insert(*email))
            .map(Address::from)
            .collect();

        if rcpt_to.is_empty() {
            return Err(crate::Error::MissingRcptTo);
        }

        Ok(Message {
            mail_from: mail_from.into(),
            rcpt_to,
            body: Cow::Borrowed(self.raw()),
        })
    }
}

#[cfg(all(test, feature = "parser"))]
mod test {
    use mail_parser::MessageParser;

    use super::IntoMessage;

    // Parsed messages yield a borrowed envelope with deduplicated recipients, groups flattened.
    #[test]
    fn parsed_message_envelope() {
        let raw = concat!(
            "From: \"Joe\" <joe@example.com>\r\n",
            "To: jane@example.org, Team: ann@example.org, jane@example.org;\r\n",
            "Cc: <bob@example.net>\r\n",
            "Bcc: ann@example.org\r\n",
            "Subject: hi\r\n\r\nbody\r\n"
        );
        let parsed = MessageParser::new().parse(raw).unwrap();
        let message = (&parsed).into_message().unwrap();

        assert_eq!(message.mail_from.email, "joe@example.com");
        assert_eq!(
            message
                .rcpt_to
                .iter()
                .map(|rcpt| rcpt.email.as_ref())
                .collect::<Vec<_>>(),
            ["jane@example.org", "ann@example.org", "bob@example.net"]
        );
        assert_eq!(message.body.as_ref(), raw.as_bytes());
    }
}

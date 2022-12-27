/*
 * Copyright Stalwart Labs Ltd.
 *
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 */

use std::{
    borrow::Cow,
    fmt::{Debug, Display},
};

#[cfg(feature = "builder")]
use mail_builder::{
    headers::{address, HeaderType},
    MessageBuilder,
};
use smtp_proto::{EhloResponse, EXT_CHUNKING};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::SmtpClient;

#[derive(Debug, Default)]
pub struct Message<'x> {
    pub mail_from: Address<'x>,
    pub rcpt_to: Vec<Address<'x>>,
    pub body: Cow<'x, [u8]>,
}

#[derive(Debug, Default)]
pub struct Address<'x> {
    pub email: Cow<'x, str>,
    pub parameters: Parameters<'x>,
}

#[derive(Debug, Default)]
pub struct Parameters<'x> {
    params: Vec<Parameter<'x>>,
}

#[derive(Debug, Default)]
pub struct Parameter<'x> {
    key: Cow<'x, str>,
    value: Option<Cow<'x, str>>,
}

impl<T: AsyncRead + AsyncWrite + Unpin> SmtpClient<T, EhloResponse<String>> {
    /// Sends a message to the server.
    pub async fn send<'x>(&mut self, message: impl IntoMessage<'x>) -> crate::Result<()> {
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
        if self.capabilities.has_capability(EXT_CHUNKING)
            && self.bdat(message.body.as_ref()).await.is_ok()
        {
            return Ok(());
        }
        self.data(message.body.as_ref()).await
    }

    /// Sends a message to the server.
    #[cfg(feature = "dkim")]
    pub async fn send_signed<'x>(
        &mut self,
        message: impl IntoMessage<'x>,
        with_key: &impl mail_auth::common::crypto::SigningKey,
        signature: mail_auth::dkim::Signature<'_>,
    ) -> crate::Result<()> {
        // Send mail-from

        use mail_auth::common::headers::HeaderWriter;
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
        let signature = signature
            .sign(message.body.as_ref(), with_key)
            .map_err(|_| crate::Error::MissingCredentials)?;
        let mut signed_message = Vec::with_capacity(message.body.len() + 64);
        signature.write_header(&mut signed_message);
        signed_message.extend_from_slice(message.body.as_ref());

        // Send message
        if self.capabilities.has_capability(EXT_CHUNKING)
            && self.bdat(&signed_message).await.is_ok()
        {
            return Ok(());
        }
        self.data(&signed_message).await
    }

    pub(crate) async fn write_message(&mut self, message: &[u8]) -> tokio::io::Result<()> {
        // Transparency procedure
        #[derive(Debug)]
        enum State {
            Cr,
            CrLf,
            Init,
        }

        let mut state = State::Init;
        let mut last_pos = 0;
        for (pos, byte) in message.iter().enumerate() {
            if *byte == b'.' && matches!(state, State::CrLf) {
                if let Some(bytes) = message.get(last_pos..pos) {
                    self.stream.write_all(bytes).await?;
                    self.stream.write_all(b".").await?;
                    last_pos = pos;
                }
                state = State::Init;
            } else if *byte == b'\r' {
                state = State::Cr;
            } else if *byte == b'\n' && matches!(state, State::Cr) {
                state = State::CrLf;
            } else {
                state = State::Init;
            }
        }
        if let Some(bytes) = message.get(last_pos..) {
            self.stream.write_all(bytes).await?;
        }
        self.stream.write_all("\r\n.\r\n".as_bytes()).await
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

impl<'x> From<String> for Address<'x> {
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

impl<'x> From<(String, String)> for Parameter<'x> {
    fn from(value: (String, String)) -> Self {
        Parameter {
            key: value.0.into(),
            value: Some(value.1.into()),
        }
    }
}

impl<'x> From<String> for Parameter<'x> {
    fn from(value: String) -> Self {
        Parameter {
            key: value.into(),
            value: None,
        }
    }
}

impl<'x> Display for Parameters<'x> {
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

impl<'x> Display for Parameter<'x> {
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
impl<'x, 'y> IntoMessage<'x> for MessageBuilder<'y> {
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
            } else if key.eq_ignore_ascii_case("to")
                || key.eq_ignore_ascii_case("cc")
                || key.eq_ignore_ascii_case("bcc")
            {
                if let HeaderType::Address(addr) = value {
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

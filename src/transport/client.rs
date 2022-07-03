/*
 * Copyright Stalwart Labs Ltd. See the COPYING
 * file at the top-level directory of this distribution.
 *
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 */

use std::{borrow::Cow, convert::TryInto, time::Duration};

use tokio::{io::AsyncReadExt, net::TcpStream, time};

#[cfg(feature = "dkim")]
use crate::dkim::DKIM;
use crate::{
    smtp::{
        auth::{Credentials, Mechanism},
        capability::{Capability, Capabilties},
        message::{IntoMessage, Parameters},
        reply::{self, Reply, ReplyParser, Severity},
    },
    Connected, Disconnected, Transport,
};

use super::stream::Stream;

impl<'x> Clone for Transport<'x, Disconnected> {
    fn clone(&self) -> Self {
        Self {
            _state: self._state,
            stream: Stream::None,
            timeout: self.timeout,
            credentials: self.credentials.clone(),
            dkim: self.dkim.clone(),
            allow_invalid_certs: self.allow_invalid_certs,
            hostname: self.hostname.clone(),
            port: self.port,
        }
    }
}

impl<'x> Transport<'x, Disconnected> {
    /// Creates a new SMTP client instance.
    pub fn new(hostname: impl Into<Cow<'x, str>>) -> Self {
        Transport {
            stream: Stream::None,
            timeout: Duration::from_secs(60 * 60),
            allow_invalid_certs: false,
            credentials: None,
            #[cfg(feature = "dkim")]
            dkim: None,
            hostname: hostname.into(),
            port: 0,
            _state: std::marker::PhantomData,
        }
    }

    /// Sets the SMTP port.
    pub fn port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    /// Sets the SMTP connection timeout.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Authentication credentials.
    pub fn credentials(
        mut self,
        username: impl Into<Cow<'x, str>>,
        secret: impl Into<Cow<'x, str>>,
    ) -> Self {
        self.credentials = Some(Credentials::new(username, secret));
        self
    }

    /// DKIM signer to use on outgoing messages.
    #[cfg(feature = "dkim")]
    pub fn dkim(mut self, dkim: DKIM<'x>) -> Self {
        self.dkim = Some(dkim);
        self
    }

    pub async fn connect(self) -> crate::Result<Transport<'x, Connected>> {
        time::timeout(self.timeout, async {
            // Connect to the server
            let stream = Stream::Basic(
                TcpStream::connect(format!(
                    "{}:{}",
                    self.hostname,
                    if self.port > 0 { self.port } else { 587 }
                ))
                .await?,
            );

            // Build Transport
            let mut client: Transport<Connected> = Transport {
                stream,
                timeout: self.timeout,
                allow_invalid_certs: self.allow_invalid_certs,
                credentials: self.credentials,
                #[cfg(feature = "dkim")]
                dkim: self.dkim,
                hostname: self.hostname,
                port: self.port,
                _state: std::marker::PhantomData,
            };

            // Read greeting
            client
                .read()
                .await?
                .assert_severity(Severity::PositiveCompletion)?;

            // Authenticate and upgrade to TLS if possible
            client.init().await?;

            Ok(client)
        })
        .await
        .map_err(|_| crate::Error::Timeout)?
    }
}

impl<'x> Transport<'x, Connected> {
    pub(crate) async fn read(&mut self) -> crate::Result<Reply> {
        let mut buf = vec![0u8; 1024];
        let mut parser = ReplyParser::new();

        loop {
            let br = match &mut self.stream {
                Stream::Basic(stream) => stream.read(&mut buf).await?,
                Stream::Tls(stream) => stream.read(&mut buf).await?,
                _ => unreachable!(),
            };

            if br == 0 {
                return Err(crate::Error::UnparseableReply(
                    reply::Error::IncompleteReply,
                ));
            }

            //println!("+ {:?}", String::from_utf8_lossy(&buf[..br]));

            match parser.parse(&buf[..br]) {
                Ok(reply) => return Ok(reply),
                Err(err) => match err {
                    reply::Error::NeedsMoreData => (),
                    err => {
                        return Err(err.into());
                    }
                },
            }
        }
    }

    /// Sends a command to the SMTP server and waits for a reply.
    pub async fn cmd(&mut self, bytes: &[u8]) -> crate::Result<Reply> {
        //println!("+ {:?}", String::from_utf8_lossy(bytes));

        time::timeout(self.timeout, async {
            self.stream.write_all(bytes).await?;
            self.read().await
        })
        .await
        .map_err(|_| crate::Error::Timeout)?
    }

    /// Sends a EHLO command to the server.
    pub async fn ehlo(&mut self) -> crate::Result<Capabilties> {
        self.cmd(
            format!(
                "EHLO {}\r\n",
                gethostname::gethostname().to_str().unwrap_or("[127.0.0.1]")
            )
            .as_bytes(),
        )
        .await
        .and_then(TryInto::try_into)
    }

    /// Sends a NOOP command to the server.
    pub async fn noop(&mut self) -> crate::Result<Reply> {
        self.cmd(b"NOOP\r\n").await
    }

    pub(crate) async fn auth(&mut self, mechanism: Mechanism) -> crate::Result<()> {
        let mut reply = self
            .cmd(format!("AUTH {}\r\n", mechanism).as_bytes())
            .await?;

        for _ in 0..3 {
            match reply.code() {
                334 => {
                    reply = self
                        .cmd(
                            format!(
                                "{}\r\n",
                                self.credentials
                                    .as_ref()
                                    .ok_or(crate::Error::MissingCredentials)?
                                    .encode(
                                        mechanism,
                                        reply.message().first().map_or("", |s| s.as_str())
                                    )?
                            )
                            .as_bytes(),
                        )
                        .await?;
                }
                235 => {
                    return Ok(());
                }
                _ => {
                    return Err(crate::Error::UnexpectedReply(reply));
                }
            }
        }

        Err(crate::Error::UnexpectedReply(reply))
    }

    /// Sends a MAIL FROM command to the server.
    pub async fn mail_from(&mut self, addr: &str, params: &Parameters<'x>) -> crate::Result<()> {
        self.cmd(format!("MAIL FROM:<{}>{}\r\n", addr, params).as_bytes())
            .await?
            .assert_severity(Severity::PositiveCompletion)
    }

    /// Sends a RCPT TO command to the server.
    pub async fn rcpt_to(&mut self, addr: &str, params: &Parameters<'x>) -> crate::Result<()> {
        self.cmd(format!("RCPT TO:<{}>{}\r\n", addr, params).as_bytes())
            .await?
            .assert_severity(Severity::PositiveCompletion)
    }

    /// Sends a DATA command to the server.
    pub async fn data(&mut self, message: &[u8]) -> crate::Result<()> {
        self.cmd(b"DATA\r\n")
            .await?
            .assert_severity(Severity::PositiveIntermediate)?;
        time::timeout(self.timeout, async {
            // Sign message
            #[cfg(feature = "dkim")]
            if let Some(dkim) = &self.dkim {
                self.stream
                    .write_all(dkim.sign(message)?.to_header().as_bytes())
                    .await?;
            }

            // Write message
            self.stream.write_message(message).await?;

            self.read().await
        })
        .await
        .map_err(|_| crate::Error::Timeout)??
        .assert_severity(Severity::PositiveCompletion)
    }

    /// Sends a RSET command to the server.
    pub async fn rset(&mut self) -> crate::Result<()> {
        self.cmd(b"RSET\r\n")
            .await?
            .assert_severity(Severity::PositiveCompletion)
    }

    /// Sends a QUIT command to the server.
    pub async fn quit(&mut self) -> crate::Result<()> {
        self.cmd(b"QUIT\r\n")
            .await?
            .assert_severity(Severity::PositiveCompletion)
    }

    pub(crate) async fn init(&mut self) -> crate::Result<()> {
        // Obtain server capabilities
        let mut capabilities = self.ehlo().await?;

        // Upgrade to TLS if this is an insecure connection
        if !self.is_secure() && capabilities.has_capability(&Capability::StartTLS) {
            self.start_tls().await?;
            capabilities = self.ehlo().await?;
        }

        // Authenticate if required
        if self.credentials.is_some() {
            if let Some(mechanisms) = capabilities.auth() {
                // Try authenticating from most secure to least secure
                let mut has_err = None;
                for mechanism in mechanisms {
                    match self.auth(*mechanism).await {
                        Ok(_) => {
                            has_err = None;
                            break;
                        }
                        Err(err) => match err {
                            crate::Error::UnexpectedReply(reply) => {
                                has_err = reply.into();
                            }
                            _ => return Err(err),
                        },
                    }
                }

                if let Some(has_err) = has_err {
                    return Err(crate::Error::AuthenticationFailed(has_err));
                }
            } else {
                return Err(crate::Error::UnsupportedAuthMechanism);
            }
        }
        Ok(())
    }

    /// Sends a message to the server. This is a convenience function that
    /// signs the message using the provided DKIM signer, authenticates the user
    /// using the provided credentials, and finally sends the message.
    pub async fn send(&mut self, message: impl IntoMessage<'x>) -> crate::Result<()> {
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
}

#[cfg(test)]
mod test {

    use super::{Stream, Transport};

    #[tokio::test]
    async fn smtp_basic() {
        // StartTLS test
        let mut client = Transport::new("mail.smtp2go.com")
            .port(2525)
            .connect()
            .await
            .unwrap();
        client.ehlo().await.unwrap();
        client.start_tls().await.unwrap();
        client.ehlo().await.unwrap();
        client.quit().await.unwrap();

        // Say hello to Google over TLS and quit
        let mut client = Transport::new("smtp.gmail.com")
            .connect_tls()
            .await
            .unwrap();
        client.ehlo().await.unwrap();
        client.quit().await.unwrap();
    }

    #[tokio::test]
    async fn transparency_procedure() {
        for (test, result) in [
            (
                "A: b\r\n.\r\n".to_string(),
                "A: b\r\n..\r\n\r\n.\r\n".to_string(),
            ),
            ("A: b\r\n.".to_string(), "A: b\r\n..\r\n.\r\n".to_string()),
            (
                "A: b\r\n..\r\n".to_string(),
                "A: b\r\n...\r\n\r\n.\r\n".to_string(),
            ),
            ("A: ...b".to_string(), "A: ...b\r\n.\r\n".to_string()),
        ] {
            let mut stream = Stream::Debug(Vec::new());
            stream.write_message(test.as_bytes()).await.unwrap();
            if let Stream::Debug(bytes) = stream {
                assert_eq!(String::from_utf8(bytes).unwrap(), result);
            }
        }
    }
}

use std::{borrow::Cow, convert::TryInto, time::Duration};

use tokio::{io::AsyncReadExt, net::TcpStream, time};

use super::{
    auth::{Credentials, Mechanism},
    capability::Capabilties,
    dkim::DKIM,
    reply::{self, Reply, ReplyParser, Severity},
    stream::SmtpStream,
    Params,
};

pub struct SmtpClient<'x> {
    pub stream: SmtpStream,
    pub timeout: Duration,
    credentials: Option<Credentials<'x>>,
    dkim: Option<DKIM<'x>>,
    pub allow_invalid_certs: bool,
    pub hostname: Cow<'x, str>,
    pub port: u16,
}

impl<'x> SmtpClient<'x> {
    pub fn new(hostname: impl Into<Cow<'x, str>>) -> Self {
        SmtpClient {
            stream: SmtpStream::None,
            timeout: Duration::from_secs(60 * 60),
            allow_invalid_certs: false,
            credentials: None,
            dkim: None,
            hostname: hostname.into(),
            port: 0,
        }
    }

    pub fn port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn credentials(
        mut self,
        username: impl Into<Cow<'x, str>>,
        secret: impl Into<Cow<'x, str>>,
    ) -> Self {
        self.credentials = Some(Credentials::new(username, secret));
        self
    }

    pub fn dkim(mut self, dkim: DKIM<'x>) -> Self {
        self.dkim = Some(dkim);
        self
    }

    pub async fn connect(&mut self) -> super::Result<()> {
        time::timeout(self.timeout, async {
            // Connect to the server
            self.stream = SmtpStream::Basic(
                TcpStream::connect(format!(
                    "{}:{}",
                    self.hostname,
                    if self.port > 0 { self.port } else { 587 }
                ))
                .await?,
            );

            // Read greeting
            self.read()
                .await?
                .assert_severity(Severity::PositiveCompletion)
        })
        .await
        .map_err(|_| super::Error::Timeout)?
    }

    pub async fn read(&mut self) -> super::Result<Reply> {
        let mut buf = vec![0u8; 1024];
        let mut parser = ReplyParser::new();

        loop {
            let br = match &mut self.stream {
                SmtpStream::Basic(stream) => stream.read(&mut buf).await?,
                SmtpStream::Tls(stream) => stream.read(&mut buf).await?,
                _ => unreachable!(),
            };

            if br == 0 {
                return Err(super::Error::Reply(reply::Error::IncompleteReply));
            }

            println!("-> {:?}", String::from_utf8_lossy(&buf[..br]));

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

    pub async fn send(&mut self, bytes: &[u8]) -> super::Result<Reply> {
        println!("-> {:?}", String::from_utf8_lossy(bytes));

        time::timeout(self.timeout, async {
            self.stream.write_all(bytes).await?;
            self.read().await
        })
        .await
        .map_err(|_| super::Error::Timeout)?
    }

    pub async fn ehlo(&mut self) -> super::Result<Capabilties> {
        self.send(
            format!(
                "EHLO {}\r\n",
                gethostname::gethostname().to_str().unwrap_or("[127.0.0.1]")
            )
            .as_bytes(),
        )
        .await
        .and_then(TryInto::try_into)
    }

    pub async fn noop(&mut self) -> super::Result<Reply> {
        self.send(b"NOOP\r\n").await
    }

    pub async fn auth(&mut self, mechanism: Mechanism) -> super::Result<()> {
        let mut reply = self
            .send(format!("AUTH {}\r\n", mechanism).as_bytes())
            .await?;

        for _ in 0..3 {
            match reply.code() {
                334 => {
                    reply = self
                        .send(
                            format!(
                                "{}\r\n",
                                self.credentials
                                    .as_ref()
                                    .ok_or(super::Error::MissingCredentials)?
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
                    return Err(super::Error::UnexpectedReply(reply));
                }
            }
        }

        Err(super::Error::UnexpectedReply(reply))
    }

    pub async fn mail_from(&mut self, addr: &str, params: &Params<'x>) -> super::Result<()> {
        self.send(format!("MAIL FROM:<{}>{}\r\n", addr, params).as_bytes())
            .await?
            .assert_severity(Severity::PositiveCompletion)
    }

    pub async fn rcpt_to(&mut self, addr: &str, params: &Params<'x>) -> super::Result<()> {
        self.send(format!("RCPT TO:<{}>{}\r\n", addr, params).as_bytes())
            .await?
            .assert_severity(Severity::PositiveCompletion)
    }

    pub async fn data(&mut self, message: &[u8]) -> super::Result<()> {
        self.send(b"DATA\r\n")
            .await?
            .assert_severity(Severity::PositiveIntermediate)?;
        time::timeout(self.timeout, async {
            // Sign message
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
        .map_err(|_| super::Error::Timeout)??
        .assert_severity(Severity::PositiveCompletion)
    }

    pub async fn quit(&mut self) -> super::Result<()> {
        self.send(b"QUIT")
            .await?
            .assert_severity(Severity::PositiveCompletion)
    }
}

#[cfg(test)]
mod test {
    use crate::smtp::auth::Mechanism;

    use super::{SmtpClient, SmtpStream};

    #[tokio::test]
    async fn smtp_basic() {
        /*let mut client = SmtpClient::new("mail.smtp2go.com").port(2525);
        client.connect().await.unwrap();
        println!("{:?}", client.ehlo().await.unwrap());
        client.start_tls().await.unwrap();
        println!("{:?}", client.ehlo().await.unwrap());*/
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
            let mut stream = SmtpStream::Debug(Vec::new());
            stream.write_message(test.as_bytes()).await.unwrap();
            if let SmtpStream::Debug(bytes) = stream {
                assert_eq!(String::from_utf8(bytes).unwrap(), result);
            }
        }
    }
}

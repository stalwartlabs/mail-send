/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use super::{AssertReply, message::Parameters};
use crate::SmtpClient;
use smtp_proto::Response;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

impl<T: AsyncRead + AsyncWrite + Unpin> SmtpClient<T> {
    /// Sends a MAIL FROM command to the server.
    pub async fn mail_from(&mut self, addr: &str, params: &Parameters<'_>) -> crate::Result<()> {
        self.cmd(format!("MAIL FROM:<{addr}>{params}\r\n").as_bytes())
            .await?
            .assert_positive_completion()
    }

    /// Sends a RCPT TO command to the server.
    pub async fn rcpt_to(&mut self, addr: &str, params: &Parameters<'_>) -> crate::Result<()> {
        self.cmd(format!("RCPT TO:<{addr}>{params}\r\n").as_bytes())
            .await?
            .assert_positive_completion()
    }

    /// Sends a DATA command to the server.
    pub async fn data(&mut self, message: impl AsRef<[u8]>) -> crate::Result<Response<String>> {
        self.cmd(b"DATA\r\n").await?.assert_code(354)?;
        tokio::time::timeout(self.timeout, async {
            // Write message
            self.write_message(message.as_ref()).await?;
            self.read().await
        })
        .await
        .map_err(|_| crate::Error::Timeout)??
        .into_positive_completion()
    }

    /// Sends a BDAT command to the server.
    pub async fn bdat(&mut self, message: impl AsRef<[u8]>) -> crate::Result<Response<String>> {
        let message = message.as_ref();
        tokio::time::timeout(self.timeout, async {
            self.stream
                .write_all(format!("BDAT {} LAST\r\n", message.len()).as_bytes())
                .await?;
            self.stream.write_all(message).await?;
            self.stream.flush().await?;
            self.read().await
        })
        .await
        .map_err(|_| crate::Error::Timeout)??
        .into_positive_completion()
    }

    /// Sends a RSET command to the server.
    pub async fn rset(&mut self) -> crate::Result<()> {
        self.cmd(b"RSET\r\n").await?.assert_positive_completion()
    }

    /// Sends a NOOP command to the server.
    pub async fn noop(&mut self) -> crate::Result<()> {
        self.cmd(b"NOOP\r\n").await?.assert_positive_completion()
    }

    /// Sends a QUIT command to the server.
    pub async fn quit(mut self) -> crate::Result<()> {
        self.cmd(b"QUIT\r\n").await?.assert_positive_completion()
    }
}

#[cfg(test)]
mod test {
    use std::time::Duration;

    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, duplex};

    use crate::{Error, SmtpClient, smtp::message::Message};

    async fn send_with_final_reply(final_reply: &'static str) -> crate::Result<String> {
        let (client_stream, server_stream) = duplex(4096);
        let server = tokio::spawn(async move {
            let (reader, mut writer) = tokio::io::split(server_stream);
            let mut reader = BufReader::new(reader);
            let mut line = String::new();
            let mut in_data = false;
            while reader.read_line(&mut line).await.unwrap_or(0) > 0 {
                let reply = match (in_data, line.as_str()) {
                    (false, "DATA\r\n") => {
                        in_data = true;
                        Some("354 Start mail input\r\n")
                    }
                    (false, _) => Some("250 OK\r\n"),
                    (true, ".\r\n") => {
                        in_data = false;
                        Some(final_reply)
                    }
                    (true, _) => None,
                };
                if let Some(reply) = reply {
                    writer.write_all(reply.as_bytes()).await.unwrap();
                }
                line.clear();
            }
        });

        let mut client = SmtpClient {
            stream: client_stream,
            timeout: Duration::from_secs(5),
        };
        let result = client
            .send(Message::new(
                "sender@example.com",
                ["rcpt@example.org"],
                b"Subject: test\r\n\r\nHello\r\n".as_slice(),
            ))
            .await
            .map(|response| response.message);
        drop(client);
        server.await.unwrap();
        result
    }

    // send() returns the final DATA reply so callers can log the queue ID.
    #[tokio::test]
    async fn send_returns_data_reply() {
        assert_eq!(
            send_with_final_reply("250 2.0.0 Ok: queued as 224B824BD40\r\n")
                .await
                .unwrap(),
            "Ok: queued as 224B824BD40"
        );
        assert!(matches!(
            send_with_final_reply("554 5.7.1 Rejected\r\n").await,
            Err(Error::UnexpectedReply(response)) if response.code == 554
        ));
    }
}

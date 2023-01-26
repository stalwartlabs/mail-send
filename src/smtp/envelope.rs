/*
 * Copyright Stalwart Labs Ltd.
 *
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 */

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::SmtpClient;

use super::{message::Parameters, AssertReply};

impl<T: AsyncRead + AsyncWrite + Unpin> SmtpClient<T> {
    /// Sends a MAIL FROM command to the server.
    pub async fn mail_from(&mut self, addr: &str, params: &Parameters<'_>) -> crate::Result<()> {
        self.cmd(format!("MAIL FROM:<{}>{}\r\n", addr, params).as_bytes())
            .await?
            .assert_positive_completion()
    }

    /// Sends a RCPT TO command to the server.
    pub async fn rcpt_to(&mut self, addr: &str, params: &Parameters<'_>) -> crate::Result<()> {
        self.cmd(format!("RCPT TO:<{}>{}\r\n", addr, params).as_bytes())
            .await?
            .assert_positive_completion()
    }

    /// Sends a DATA command to the server.
    pub async fn data(&mut self, message: impl AsRef<[u8]>) -> crate::Result<()> {
        self.cmd(b"DATA\r\n").await?.assert_code(354)?;
        tokio::time::timeout(self.timeout, async {
            // Write message
            self.write_message(message.as_ref()).await?;
            self.read().await
        })
        .await
        .map_err(|_| crate::Error::Timeout)??
        .assert_positive_completion()
    }

    /// Sends a BDAT command to the server.
    pub async fn bdat(&mut self, message: impl AsRef<[u8]>) -> crate::Result<()> {
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
        .assert_positive_completion()
    }

    /// Sends a RSET command to the server.
    pub async fn rset(&mut self) -> crate::Result<()> {
        self.cmd(b"RSET\r\n").await?.assert_positive_completion()
    }

    /// Sends a QUIT command to the server.
    pub async fn quit(mut self) -> crate::Result<()> {
        self.cmd(b"QUIT\r\n").await?.assert_positive_completion()
    }
}

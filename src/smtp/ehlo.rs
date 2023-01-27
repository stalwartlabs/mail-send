/*
 * Copyright Stalwart Labs Ltd.
 *
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 */

use smtp_proto::{
    response::parser::{ResponseReceiver, MAX_REPONSE_LENGTH},
    EhloResponse,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::SmtpClient;

impl<T: AsyncRead + AsyncWrite + Unpin> SmtpClient<T> {
    /// Sends a EHLO command to the server.
    pub async fn ehlo(&mut self, hostname: &str) -> crate::Result<EhloResponse<String>> {
        tokio::time::timeout(self.timeout, async {
            self.stream
                .write_all(format!("EHLO {hostname}\r\n").as_bytes())
                .await?;
            self.stream.flush().await?;
            self.read_ehlo().await
        })
        .await
        .map_err(|_| crate::Error::Timeout)?
    }

    /// Sends a EHLO command to the server.
    pub async fn lhlo(&mut self, hostname: &str) -> crate::Result<EhloResponse<String>> {
        tokio::time::timeout(self.timeout, async {
            self.stream
                .write_all(format!("LHLO {hostname}\r\n").as_bytes())
                .await?;
            self.stream.flush().await?;
            self.read_ehlo().await
        })
        .await
        .map_err(|_| crate::Error::Timeout)?
    }

    pub async fn read_ehlo(&mut self) -> crate::Result<EhloResponse<String>> {
        let mut buf = vec![0u8; 1024];
        let mut buf_concat = Vec::with_capacity(0);

        loop {
            let br = self.stream.read(&mut buf).await?;

            if br == 0 {
                return Err(crate::Error::UnparseableReply);
            }
            let mut iter = if buf_concat.is_empty() {
                buf[..br].iter()
            } else if br + buf_concat.len() < MAX_REPONSE_LENGTH {
                buf_concat.extend_from_slice(&buf[..br]);
                buf_concat.iter()
            } else {
                return Err(crate::Error::UnparseableReply);
            };

            match EhloResponse::parse(&mut iter) {
                Ok(reply) => return Ok(reply),
                Err(err) => match err {
                    smtp_proto::Error::NeedsMoreData { .. } => {
                        if buf_concat.is_empty() {
                            buf_concat = buf.to_vec();
                        }
                    }
                    smtp_proto::Error::InvalidResponse { code } => {
                        match ResponseReceiver::from_code(code).parse(&mut iter) {
                            Ok(response) => {
                                return Err(crate::Error::UnexpectedReply(response));
                            }
                            Err(smtp_proto::Error::NeedsMoreData { .. }) => {
                                if buf_concat.is_empty() {
                                    buf_concat = buf.to_vec();
                                }
                            }
                            Err(_) => return Err(crate::Error::UnparseableReply),
                        }
                    }
                    _ => {
                        return Err(crate::Error::UnparseableReply);
                    }
                },
            }
        }
    }
}

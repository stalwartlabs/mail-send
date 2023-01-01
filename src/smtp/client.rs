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
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use smtp_proto::{response::parser::ResponseReceiver, Response};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpSocket, TcpStream},
};

use crate::SmtpClient;

impl<T: AsyncRead + AsyncWrite + Unpin> SmtpClient<T> {
    pub async fn read(&mut self) -> crate::Result<Response<String>> {
        let mut buf = vec![0u8; 1024];
        let mut parser = ResponseReceiver::default();

        loop {
            let br = self.stream.read(&mut buf).await?;

            if br > 0 {
                match parser.parse(&mut buf[..br].iter()) {
                    Ok(reply) => return Ok(reply),
                    Err(err) => match err {
                        smtp_proto::Error::NeedsMoreData { .. } => (),
                        _ => {
                            return Err(crate::Error::UnparseableReply);
                        }
                    },
                }
            } else {
                return Err(crate::Error::UnparseableReply);
            }
        }
    }

    pub(crate) async fn read_many(&mut self, num: usize) -> crate::Result<Vec<Response<String>>> {
        let mut buf = vec![0u8; 1024];
        let mut response = Vec::with_capacity(num);
        let mut parser = ResponseReceiver::default();

        'outer: loop {
            let br = self.stream.read(&mut buf).await?;

            if br > 0 {
                let mut iter = buf[..br].iter();

                loop {
                    match parser.parse(&mut iter) {
                        Ok(reply) => {
                            response.push(reply);
                            if response.len() != num {
                                parser.reset();
                            } else {
                                break 'outer;
                            }
                        }
                        Err(err) => match err {
                            smtp_proto::Error::NeedsMoreData { .. } => break,
                            _ => {
                                return Err(crate::Error::UnparseableReply);
                            }
                        },
                    }
                }
            } else {
                return Err(crate::Error::UnparseableReply);
            }
        }

        Ok(response)
    }

    /// Sends a command to the SMTP server and waits for a reply.
    pub async fn cmd(&mut self, cmd: impl AsRef<[u8]>) -> crate::Result<Response<String>> {
        tokio::time::timeout(self.timeout, async {
            self.stream.write_all(cmd.as_ref()).await?;
            self.read().await
        })
        .await
        .map_err(|_| crate::Error::Timeout)?
    }

    /// Pipelines multiple command to the SMTP server and waits for a reply.
    pub async fn cmds(
        &mut self,
        cmds: impl IntoIterator<Item = impl AsRef<[u8]>>,
    ) -> crate::Result<Vec<Response<String>>> {
        tokio::time::timeout(self.timeout, async {
            let mut num_replies = 0;
            for cmd in cmds {
                self.stream.write_all(cmd.as_ref()).await?;
                num_replies += 1;
            }
            self.read_many(num_replies).await
        })
        .await
        .map_err(|_| crate::Error::Timeout)?
    }
}

impl SmtpClient<TcpStream> {
    /// Connects to a remote host address
    pub async fn connect(remote_addr: SocketAddr, timeout: Duration) -> crate::Result<Self> {
        tokio::time::timeout(timeout, async {
            Ok(SmtpClient {
                stream: TcpStream::connect(remote_addr).await?,
                timeout,
            })
        })
        .await
        .map_err(|_| crate::Error::Timeout)?
    }

    /// Connects to a remote host address using the provided local IP
    pub async fn connect_using(
        local_ip: IpAddr,
        remote_addr: SocketAddr,
        timeout: Duration,
    ) -> crate::Result<Self> {
        tokio::time::timeout(timeout, async {
            let socket = if local_ip.is_ipv4() {
                TcpSocket::new_v4()?
            } else {
                TcpSocket::new_v6()?
            };
            socket.bind(SocketAddr::new(local_ip, 0))?;

            Ok(SmtpClient {
                stream: socket.connect(remote_addr).await?,
                timeout,
            })
        })
        .await
        .map_err(|_| crate::Error::Timeout)?
    }
}

#[cfg(test)]
mod test {
    use std::time::Duration;

    use tokio::io::{AsyncRead, AsyncWrite};

    use crate::{SmtpClient, SmtpClientBuilder};

    #[tokio::test]
    async fn smtp_basic() {
        // StartTLS test
        let client = SmtpClientBuilder::new("mail.smtp2go.com", 2525)
            .implicit_tls(false)
            .connect()
            .await
            .unwrap();
        client.quit().await.unwrap();

        // Say hello to Google over TLS and quit
        let client = SmtpClientBuilder::new("smtp.gmail.com", 465)
            .connect()
            .await
            .unwrap();
        client.quit().await.unwrap();
    }

    #[derive(Default)]
    struct AsyncBufWriter {
        buf: Vec<u8>,
    }

    impl AsyncRead for AsyncBufWriter {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            _buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            unreachable!()
        }
    }

    impl AsyncWrite for AsyncBufWriter {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<Result<usize, std::io::Error>> {
            self.buf.extend_from_slice(buf);
            std::task::Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), std::io::Error>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), std::io::Error>> {
            std::task::Poll::Ready(Ok(()))
        }
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
            let mut client = SmtpClient {
                stream: AsyncBufWriter::default(),
                timeout: Duration::from_secs(30),
            };
            client.write_message(test.as_bytes()).await.unwrap();
            assert_eq!(String::from_utf8(client.stream.buf).unwrap(), result);
        }
    }
}

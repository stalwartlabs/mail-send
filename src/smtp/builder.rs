/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use smtp_proto::{EhloResponse, EXT_START_TLS};
use std::hash::Hash;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::time::Duration;
use tokio::net::TcpSocket;
use tokio::{
    io,
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};
use tokio_rustls::client::TlsStream;

use crate::{Credentials, SmtpClient, SmtpClientBuilder};

use super::{tls::build_tls_connector, AssertReply};

impl<T: AsRef<str> + PartialEq + Eq + Hash> SmtpClientBuilder<T> {
    pub fn new(hostname: T, port: u16) -> Self {
        SmtpClientBuilder {
            addr: format!("{}:{}", hostname.as_ref(), port),
            timeout: Duration::from_secs(60 * 60),
            tls_connector: build_tls_connector(false),
            tls_hostname: hostname,
            tls_implicit: true,
            is_lmtp: false,
            local_host: gethostname::gethostname()
                .to_str()
                .unwrap_or("[127.0.0.1]")
                .to_string(),
            credentials: None,
            say_ehlo: true,
            local_ip: None,
        }
    }

    /// Allow invalid TLS certificates
    pub fn allow_invalid_certs(mut self) -> Self {
        self.tls_connector = build_tls_connector(true);
        self
    }

    /// Start connection in TLS or upgrade with STARTTLS
    pub fn implicit_tls(mut self, tls_implicit: bool) -> Self {
        self.tls_implicit = tls_implicit;
        self
    }

    /// Use LMTP instead of SMTP
    pub fn lmtp(mut self, is_lmtp: bool) -> Self {
        self.is_lmtp = is_lmtp;
        self
    }

    // Say EHLO/LHLO
    pub fn say_ehlo(mut self, say_ehlo: bool) -> Self {
        self.say_ehlo = say_ehlo;
        self
    }

    /// Set the EHLO/LHLO hostname
    pub fn helo_host(mut self, host: impl Into<String>) -> Self {
        self.local_host = host.into();
        self
    }

    /// Sets the authentication credentials
    pub fn credentials(mut self, credentials: impl Into<Credentials<T>>) -> Self {
        self.credentials = Some(credentials.into());
        self
    }

    /// Sets the SMTP connection timeout
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Sets the local IP to use while sending the email.
    ///
    /// This is useful if your machine has multiple public IPs assigned and you want to ensure
    /// that you are using the intended one. Using an IP with good repudiation is quite important
    /// when you want to ensure deliverability.
    ///
    /// *NOTE:* If the IP is not available on that machine, the [`connect`] and [`connect_plain`] will return and error
    pub fn local_ip(mut self, local_ip: IpAddr) -> Self {
        self.local_ip = Some(local_ip);
        self
    }

    async fn tcp_stream(&self) -> io::Result<TcpStream> {
        if let Some(local_addr) = self.local_ip {
            let remote_addrs = self.addr.to_socket_addrs()?;
            let mut last_err = None;

            for addr in remote_addrs {
                let local_addr = SocketAddr::new(local_addr, 0);
                let socket = match local_addr.ip() {
                    IpAddr::V4(_) => TcpSocket::new_v4()?,
                    IpAddr::V6(_) => TcpSocket::new_v6()?,
                };
                socket.bind(local_addr)?;

                match socket.connect(addr).await {
                    Ok(stream) => return Ok(stream),
                    Err(e) => last_err = Some(e),
                }
            }

            Err(last_err.unwrap_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "could not resolve to any address",
                )
            }))
        } else {
            TcpStream::connect(&self.addr).await
        }
    }

    /// Connect over TLS
    pub async fn connect(&self) -> crate::Result<SmtpClient<TlsStream<TcpStream>>> {
        tokio::time::timeout(self.timeout, async {
            let mut client = SmtpClient {
                stream: self.tcp_stream().await?,
                timeout: self.timeout,
            };

            let mut client = if self.tls_implicit {
                let mut client = client
                    .into_tls(&self.tls_connector, self.tls_hostname.as_ref())
                    .await?;
                // Read greeting
                client.read().await?.assert_positive_completion()?;
                client
            } else {
                // Read greeting
                client.read().await?.assert_positive_completion()?;

                // Send EHLO
                let response = if !self.is_lmtp {
                    client.ehlo(&self.local_host).await?
                } else {
                    client.lhlo(&self.local_host).await?
                };
                if response.has_capability(EXT_START_TLS) {
                    client
                        .start_tls(&self.tls_connector, self.tls_hostname.as_ref())
                        .await?
                } else {
                    return Err(crate::Error::MissingStartTls);
                }
            };

            if self.say_ehlo {
                // Obtain capabilities
                let capabilities = client.capabilities(&self.local_host, self.is_lmtp).await?;
                // Authenticate
                if let Some(credentials) = &self.credentials {
                    client.authenticate(&credentials, &capabilities).await?;
                }
            }

            Ok(client)
        })
        .await
        .map_err(|_| crate::Error::Timeout)?
    }

    /// Connect over clear text (should not be used)
    pub async fn connect_plain(&self) -> crate::Result<SmtpClient<TcpStream>> {
        let mut client = SmtpClient {
            stream: tokio::time::timeout(self.timeout, async { self.tcp_stream().await })
                .await
                .map_err(|_| crate::Error::Timeout)??,
            timeout: self.timeout,
        };

        // Read greeting
        client.read().await?.assert_positive_completion()?;

        if self.say_ehlo {
            // Obtain capabilities
            let capabilities = client.capabilities(&self.local_host, self.is_lmtp).await?;
            // Authenticate
            if let Some(credentials) = &self.credentials {
                client.authenticate(&credentials, &capabilities).await?;
            }
        }

        Ok(client)
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> SmtpClient<T> {
    pub async fn capabilities(
        &mut self,
        local_host: &str,
        is_lmtp: bool,
    ) -> crate::Result<EhloResponse<String>> {
        if !is_lmtp {
            self.ehlo(local_host).await
        } else {
            self.lhlo(local_host).await
        }
    }
}

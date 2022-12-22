/*
 * Copyright Stalwart Labs Ltd.
 *
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 */

use std::time::Duration;

use smtp_proto::{EhloResponse, EXT_START_TLS};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;

use crate::{SmtpClient, SmtpClientBuilder};

use super::{tls::build_tls_connector, AssertReply};

impl<T: AsRef<str>> SmtpClientBuilder<T> {
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
        }
    }

    /// Allow invalid TLS certificates
    pub fn allow_invalid_certs(mut self) {
        self.tls_connector = build_tls_connector(true);
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

    /// Set the EHLO/LHLO hostname
    pub fn helo_host(mut self, host: impl Into<String>) -> Self {
        self.local_host = host.into();
        self
    }

    /// Sets the SMTP connection timeout
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Connect over TLS
    pub async fn connect(
        &self,
    ) -> crate::Result<SmtpClient<TlsStream<TcpStream>, EhloResponse<String>>> {
        tokio::time::timeout(self.timeout, async {
            let mut client = SmtpClient {
                stream: TcpStream::connect(&self.addr).await?,
                timeout: self.timeout,
                capabilities: (),
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

            Ok(SmtpClient {
                capabilities: if !self.is_lmtp {
                    client.ehlo(&self.local_host).await?
                } else {
                    client.lhlo(&self.local_host).await?
                },
                stream: client.stream,
                timeout: client.timeout,
            })
        })
        .await
        .map_err(|_| crate::Error::Timeout)?
    }

    /// Connect over clear text (should not be used)
    pub async fn connect_plain(
        &self,
    ) -> crate::Result<SmtpClient<TcpStream, EhloResponse<String>>> {
        let mut client = SmtpClient {
            stream: tokio::time::timeout(self.timeout, async {
                TcpStream::connect(&self.addr).await
            })
            .await
            .map_err(|_| crate::Error::Timeout)??,
            timeout: self.timeout,
            capabilities: (),
        };
        Ok(SmtpClient {
            capabilities: if !self.is_lmtp {
                client.ehlo(&self.local_host).await?
            } else {
                client.lhlo(&self.local_host).await?
            },
            stream: client.stream,
            timeout: client.timeout,
        })
    }
}

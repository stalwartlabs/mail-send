/*
 * Copyright Stalwart Labs Ltd.
 *
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 */

use rustls::ClientConfig;
use smtp_proto::{EhloResponse, EXT_START_TLS};
use std::time::Duration;
use std::{hash::Hash, sync::Arc};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};
use tokio_rustls::{client::TlsStream, TlsConnector};

use crate::{Credentials, SmtpClient, SmtpClientBuilder};

use super::{tls::build_tls_config, AssertReply};

impl<T: AsRef<str> + PartialEq + Eq + Hash> SmtpClientBuilder<T> {
    pub fn new(hostname: T, port: u16) -> Self {
        Self::new_with_tls_config(hostname, port, build_tls_config(false))
    }

    pub fn new_with_tls_config(hostname: T, port: u16, cfg: impl Into<Arc<ClientConfig>>) -> Self {
        SmtpClientBuilder {
            addr: format!("{}:{}", hostname.as_ref(), port),
            timeout: Duration::from_secs(60 * 60),
            tls_connector: TlsConnector::from(cfg.into()),
            tls_hostname: hostname,
            tls_implicit: true,
            is_lmtp: false,
            local_host: gethostname::gethostname()
                .to_str()
                .unwrap_or("[127.0.0.1]")
                .to_string(),
            credentials: None,
            say_ehlo: true,
        }
    }

    /// Allow invalid TLS certificates
    pub fn allow_invalid_certs(mut self) -> Self {
        self.tls_connector = TlsConnector::from(Arc::new(build_tls_config(true)));
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

    /// Connect over TLS
    pub async fn connect(&self) -> crate::Result<SmtpClient<TlsStream<TcpStream>>> {
        tokio::time::timeout(self.timeout, async {
            let mut client = SmtpClient {
                stream: TcpStream::connect(&self.addr).await?,
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
            stream: tokio::time::timeout(self.timeout, async {
                TcpStream::connect(&self.addr).await
            })
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

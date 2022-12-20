/*
 * Copyright Stalwart Labs Ltd.
 *
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 */

use std::{sync::Arc, time::Duration};

use smtp_proto::{EhloResponse, Severity, EXT_START_TLS};
use tokio::net::TcpStream;
use tokio_rustls::{client::TlsStream, TlsConnector};

use crate::{SmtpClient, SmtpClientBuilder};

use super::{tls::default_tls_config, AssertReply};

impl Default for SmtpClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl SmtpClientBuilder {
    pub fn new() -> Self {
        SmtpClientBuilder {
            timeout: Duration::from_secs(60 * 60),
            tls: TlsConnector::from(Arc::new(default_tls_config(false))),
        }
    }

    /// Allow invalid TLS certificates
    pub fn allow_invalid_certs(&mut self) {
        self.tls = TlsConnector::from(Arc::new(default_tls_config(true)));
    }

    /// Sets the SMTP connection timeout
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Connect over TLS
    pub async fn connect_tls(
        &self,
        remote_host: &str,
        remote_port: u16,
    ) -> crate::Result<SmtpClient<TlsStream<TcpStream>, EhloResponse<String>>> {
        let stream = tokio::time::timeout(self.timeout, async {
            TcpStream::connect(format!("{}:{}", remote_host, remote_port)).await
        })
        .await
        .map_err(|_| crate::Error::Timeout)??;

        self.init_tls(
            stream,
            gethostname::gethostname().to_str().unwrap_or("[127.0.0.1]"),
            remote_host,
            true,
        )
        .await
    }

    /// Connect over a clear channel and upgrade to TLS
    pub async fn connect_starttls(
        &self,
        remote_host: &str,
        remote_port: u16,
    ) -> crate::Result<SmtpClient<TlsStream<TcpStream>, EhloResponse<String>>> {
        let stream = tokio::time::timeout(self.timeout, async {
            TcpStream::connect(format!("{}:{}", remote_host, remote_port)).await
        })
        .await
        .map_err(|_| crate::Error::Timeout)??;

        self.init_tls(
            stream,
            gethostname::gethostname().to_str().unwrap_or("[127.0.0.1]"),
            remote_host,
            false,
        )
        .await
    }

    /// Connect over clear text (should not be used)
    pub async fn connect_plain(
        &self,
        remote_host: &str,
        remote_port: u16,
    ) -> crate::Result<SmtpClient<TcpStream, EhloResponse<String>>> {
        let stream = tokio::time::timeout(self.timeout, async {
            TcpStream::connect(format!("{}:{}", remote_host, remote_port)).await
        })
        .await
        .map_err(|_| crate::Error::Timeout)??;

        self.init_plain(
            stream,
            gethostname::gethostname().to_str().unwrap_or("[127.0.0.1]"),
        )
        .await
    }

    /// Initialize TLS connection
    pub async fn init_tls(
        &self,
        stream: TcpStream,
        local_hostname: &str,
        tls_hostname: &str,
        tls_implicit: bool,
    ) -> crate::Result<SmtpClient<TlsStream<TcpStream>, EhloResponse<String>>> {
        tokio::time::timeout(self.timeout, async {
            let mut client = SmtpClient {
                stream,
                timeout: self.timeout,
                capabilities: (),
            };

            let mut client = if tls_implicit {
                let mut client = client.into_tls(&self.tls, tls_hostname).await?;
                // Read greeting
                client
                    .read()
                    .await?
                    .assert_severity(Severity::PositiveCompletion)?;
                client
            } else {
                // Read greeting
                client
                    .read()
                    .await?
                    .assert_severity(Severity::PositiveCompletion)?;

                // Send EHLO
                let response = client.ehlo(local_hostname).await?;
                if response.has_capability(EXT_START_TLS) {
                    client.start_tls(&self.tls, tls_hostname).await?
                } else {
                    return Err(crate::Error::MissingStartTls);
                }
            };

            Ok(SmtpClient {
                capabilities: client.ehlo(local_hostname).await?,
                stream: client.stream,
                timeout: client.timeout,
            })
        })
        .await
        .map_err(|_| crate::Error::Timeout)?
    }

    /// Initialize plain text connection
    pub async fn init_plain(
        &self,
        stream: TcpStream,
        local_hostname: &str,
    ) -> crate::Result<SmtpClient<TcpStream, EhloResponse<String>>> {
        let mut client = SmtpClient {
            stream,
            timeout: self.timeout,
            capabilities: (),
        };
        Ok(SmtpClient {
            capabilities: client.ehlo(local_hostname).await?,
            stream: client.stream,
            timeout: client.timeout,
        })
    }
}

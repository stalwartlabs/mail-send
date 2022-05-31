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

use std::{convert::TryFrom, sync::Arc};

use tokio::{net::TcpStream, time};

use crate::{smtp::reply::Severity, Connected, Disconnected, Transport};

use super::stream::Stream;

impl<'x, State> Transport<'x, State> {
    fn default_tls_config(&self) -> tokio_rustls::rustls::ClientConfig {
        let config = tokio_rustls::rustls::ClientConfig::builder().with_safe_defaults();

        if !self.allow_invalid_certs {
            let mut root_cert_store = tokio_rustls::rustls::RootCertStore::empty();

            root_cert_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(
                |ta| {
                    tokio_rustls::rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                        ta.subject,
                        ta.spki,
                        ta.name_constraints,
                    )
                },
            ));

            config.with_custom_certificate_verifier(Arc::new(rustls::client::WebPkiVerifier::new(
                root_cert_store,
                None,
            )))
        } else {
            config.with_custom_certificate_verifier(Arc::new(DummyVerifier {}))
        }
        .with_no_client_auth()
    }
}

impl<'x> Transport<'x, Disconnected> {
    /// Disables checking for certificate validity (dangerous and should not be used).
    pub fn allow_invalid_certs(mut self, allow_invalid_certs: bool) -> Self {
        self.allow_invalid_certs = allow_invalid_certs;
        self
    }

    /// Connects to the server over TLS.
    pub async fn connect_tls(self) -> crate::Result<Transport<'x, Connected>> {
        time::timeout(self.timeout, async {
            // Connect to the server
            let stream = Stream::Tls(
                tokio_rustls::TlsConnector::from(Arc::new(self.default_tls_config()))
                    .connect(
                        tokio_rustls::rustls::ServerName::try_from(self.hostname.as_ref())
                            .map_err(|_| crate::Error::InvalidTLSName)?,
                        TcpStream::connect(format!(
                            "{}:{}",
                            self.hostname,
                            if self.port > 0 { self.port } else { 465 }
                        ))
                        .await?,
                    )
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

            Ok(client)
        })
        .await
        .map_err(|_| crate::Error::Timeout)?
    }
}

impl<'x> Transport<'x, Connected> {
    /// Upgrade the connection to TLS.
    pub async fn start_tls(&mut self) -> crate::Result<()> {
        if matches!(self.stream, Stream::Basic(_)) {
            // Send STARTTLS command
            self.cmd(b"STARTTLS\r\n")
                .await?
                .assert_severity(Severity::PositiveCompletion)?;

            if let Stream::Basic(stream) = std::mem::take(&mut self.stream) {
                self.stream = Stream::Tls(
                    tokio_rustls::TlsConnector::from(Arc::new(self.default_tls_config()))
                        .connect(
                            tokio_rustls::rustls::ServerName::try_from(self.hostname.as_ref())
                                .map_err(|_| crate::Error::InvalidTLSName)?,
                            stream,
                        )
                        .await?,
                );
            }
        }
        Ok(())
    }

    pub fn is_secure(&self) -> bool {
        matches!(self.stream, Stream::Tls(_))
    }
}

#[doc(hidden)]
struct DummyVerifier;

impl rustls::client::ServerCertVerifier for DummyVerifier {
    fn verify_server_cert(
        &self,
        _e: &tokio_rustls::rustls::Certificate,
        _i: &[tokio_rustls::rustls::Certificate],
        _sn: &tokio_rustls::rustls::ServerName,
        _sc: &mut dyn Iterator<Item = &[u8]>,
        _o: &[u8],
        _n: std::time::SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::ServerCertVerified::assertion())
    }
}

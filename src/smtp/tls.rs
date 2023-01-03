/*
 * Copyright Stalwart Labs Ltd.
 *
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 */

use std::{convert::TryFrom, sync::Arc};

use rustls::{
    client::{ServerCertVerified, ServerCertVerifier, WebPkiVerifier},
    Certificate, ClientConfig, ClientConnection, OwnedTrustAnchor, RootCertStore, ServerName,
};
use tokio::net::TcpStream;
use tokio_rustls::{client::TlsStream, TlsConnector};

use crate::SmtpClient;

use super::AssertReply;

impl SmtpClient<TcpStream> {
    /// Upgrade the connection to TLS.
    pub async fn start_tls(
        mut self,
        tls_connector: &TlsConnector,
        hostname: &str,
    ) -> crate::Result<SmtpClient<TlsStream<TcpStream>>> {
        // Send STARTTLS command
        self.cmd(b"STARTTLS\r\n")
            .await?
            .assert_positive_completion()?;

        self.into_tls(tls_connector, hostname).await
    }

    pub async fn into_tls(
        self,
        tls_connector: &TlsConnector,
        hostname: &str,
    ) -> crate::Result<SmtpClient<TlsStream<TcpStream>>> {
        tokio::time::timeout(self.timeout, async {
            Ok(SmtpClient {
                stream: tls_connector
                    .connect(
                        ServerName::try_from(hostname).map_err(|_| crate::Error::InvalidTLSName)?,
                        self.stream,
                    )
                    .await?,
                timeout: self.timeout,
            })
        })
        .await
        .map_err(|_| crate::Error::Timeout)?
    }
}

impl SmtpClient<TlsStream<TcpStream>> {
    pub fn tls_connection(&self) -> &ClientConnection {
        self.stream.get_ref().1
    }
}

pub fn build_tls_connector(allow_invalid_certs: bool) -> TlsConnector {
    let config = ClientConfig::builder().with_safe_defaults();

    let config = if !allow_invalid_certs {
        let mut root_cert_store = RootCertStore::empty();

        root_cert_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(
            |ta| {
                OwnedTrustAnchor::from_subject_spki_name_constraints(
                    ta.subject,
                    ta.spki,
                    ta.name_constraints,
                )
            },
        ));

        config
            .with_custom_certificate_verifier(Arc::new(WebPkiVerifier::new(root_cert_store, None)))
    } else {
        config.with_custom_certificate_verifier(Arc::new(DummyVerifier {}))
    }
    .with_no_client_auth();

    TlsConnector::from(Arc::new(config))
}

#[doc(hidden)]
struct DummyVerifier;

impl ServerCertVerifier for DummyVerifier {
    fn verify_server_cert(
        &self,
        _e: &Certificate,
        _i: &[Certificate],
        _sn: &ServerName,
        _sc: &mut dyn Iterator<Item = &[u8]>,
        _o: &[u8],
        _n: std::time::SystemTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
}

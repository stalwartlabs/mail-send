/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use super::AssertReply;
use crate::{Error, SmtpClient};
use rustls::{
    ClientConfig, ClientConnection, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
};
use rustls_pki_types::ServerName;
use rustls_platform_verifier::BuilderVerifierExt;
use std::{convert::TryFrom, io, sync::Arc};
use tokio::net::TcpStream;
use tokio_rustls::{TlsConnector, client::TlsStream};

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
                        ServerName::try_from(hostname)
                            .map_err(|_| crate::Error::InvalidTLSName)?
                            .to_owned(),
                        self.stream,
                    )
                    .await
                    .map_err(|err| {
                        let kind = err.kind();
                        if let Some(inner) = err.into_inner() {
                            match inner.downcast::<rustls::Error>() {
                                Ok(error) => Error::Tls(error),
                                Err(error) => Error::Io(io::Error::new(kind, error)),
                            }
                        } else {
                            Error::Io(io::Error::new(kind, "Unspecified"))
                        }
                    })?,
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

pub fn build_tls_connector(allow_invalid_certs: bool) -> Result<TlsConnector, String> {
    let config = if !allow_invalid_certs {
        ClientConfig::builder()
            .with_platform_verifier()
            .map(|config| config.with_no_client_auth())
            .map_err(|err| format!("Failed to build platform verifier: {err}"))?
    } else {
        ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(DummyVerifier {}))
            .with_no_client_auth()
    };

    Ok(TlsConnector::from(Arc::new(config)))
}

#[doc(hidden)]
#[derive(Debug)]
struct DummyVerifier;

impl ServerCertVerifier for DummyVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls_pki_types::CertificateDer<'_>,
        _intermediates: &[rustls_pki_types::CertificateDer<'_>],
        _server_name: &rustls_pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls_pki_types::UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA1,
            SignatureScheme::ECDSA_SHA1_Legacy,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ]
    }
}

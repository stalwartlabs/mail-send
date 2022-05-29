use std::{convert::TryFrom, sync::Arc};

use tokio::{net::TcpStream, time};

use super::{client::SmtpClient, reply::Severity, stream::SmtpStream};

impl<'x> SmtpClient<'x> {
    pub fn allow_invalid_certs(mut self, allow_invalid_certs: bool) -> Self {
        self.allow_invalid_certs = allow_invalid_certs;
        self
    }

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

    pub async fn connect_tls(&mut self) -> super::Result<()> {
        time::timeout(self.timeout, async {
            // Connect to the server
            self.stream = SmtpStream::Tls(
                tokio_rustls::TlsConnector::from(Arc::new(self.default_tls_config()))
                    .connect(
                        tokio_rustls::rustls::ServerName::try_from(self.hostname.as_ref())
                            .map_err(|_| super::Error::InvalidTLSName)?,
                        TcpStream::connect(format!(
                            "{}:{}",
                            self.hostname,
                            if self.port > 0 { self.port } else { 465 }
                        ))
                        .await?,
                    )
                    .await?,
            );

            // Read greeting
            self.read()
                .await?
                .assert_severity(Severity::PositiveCompletion)
        })
        .await
        .map_err(|_| super::Error::Timeout)?
    }

    pub async fn start_tls(&mut self) -> super::Result<()> {
        if matches!(self.stream, SmtpStream::Basic(_)) {
            // Send STARTTLS command
            self.send(b"STARTTLS\r\n")
                .await?
                .assert_severity(Severity::PositiveCompletion)?;

            if let SmtpStream::Basic(stream) = std::mem::take(&mut self.stream) {
                self.stream = SmtpStream::Tls(
                    tokio_rustls::TlsConnector::from(Arc::new(self.default_tls_config()))
                        .connect(
                            tokio_rustls::rustls::ServerName::try_from(self.hostname.as_ref())
                                .map_err(|_| super::Error::InvalidTLSName)?,
                            stream,
                        )
                        .await?,
                );
            }
        }
        Ok(())
    }

    pub fn is_secure(&self) -> bool {
        matches!(self.stream, SmtpStream::Tls(_))
    }
}

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

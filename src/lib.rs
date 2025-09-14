/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

#![doc = include_str!("../README.md")]

pub mod smtp;
use std::net::IpAddr;
use std::{fmt::Display, hash::Hash, time::Duration};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::TlsConnector;

#[cfg(feature = "builder")]
pub use mail_builder;

#[cfg(feature = "dkim")]
pub use mail_auth;

#[derive(Debug)]
pub enum Error {
    /// I/O error
    Io(std::io::Error),

    /// TLS error
    Tls(Box<rustls::Error>),

    /// Base64 decode error
    Base64(base64::DecodeError),

    // SMTP authentication error.
    Auth(smtp::auth::Error),

    /// Failure parsing SMTP reply
    UnparseableReply,

    /// Unexpected SMTP reply.
    UnexpectedReply(smtp_proto::Response<String>),

    /// SMTP authentication failure.
    AuthenticationFailed(smtp_proto::Response<String>),

    /// Invalid TLS name provided.
    InvalidTLSName,

    /// Missing authentication credentials.
    MissingCredentials,

    /// Missing message sender.
    MissingMailFrom,

    /// Missing message recipients.
    MissingRcptTo,

    /// The server does no support any of the available authentication methods.
    UnsupportedAuthMechanism,

    /// Connection timeout.
    Timeout,

    /// STARTTLS not available
    MissingStartTls,
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(err) => err.source(),
            Error::Tls(err) => err.source(),
            Error::Base64(err) => err.source(),
            _ => None,
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// SMTP client builder
#[derive(Clone)]
pub struct SmtpClientBuilder<T: AsRef<str> + PartialEq + Eq + Hash> {
    pub timeout: Duration,
    pub tls_connector: TlsConnector,
    pub tls_hostname: T,
    pub tls_implicit: bool,
    pub credentials: Option<Credentials<T>>,
    pub addr: String,
    pub is_lmtp: bool,
    pub say_ehlo: bool,
    pub local_host: String,
    pub local_ip: Option<IpAddr>,
}

/// SMTP client builder
pub struct SmtpClient<T: AsyncRead + AsyncWrite> {
    pub stream: T,
    pub timeout: Duration,
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub enum Credentials<T: AsRef<str> + PartialEq + Eq + Hash> {
    Plain { username: T, secret: T },
    OAuthBearer { token: T },
    XOauth2 { username: T, secret: T },
}

impl Default for Credentials<String> {
    fn default() -> Self {
        Credentials::Plain {
            username: String::new(),
            secret: String::new(),
        }
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Io(e) => write!(f, "I/O error: {e}"),
            Error::Tls(e) => write!(f, "TLS error: {e}"),
            Error::Base64(e) => write!(f, "Base64 decode error: {e}"),
            Error::Auth(e) => write!(f, "SMTP authentication error: {e}"),
            Error::UnparseableReply => write!(f, "Unparseable SMTP reply"),
            Error::UnexpectedReply(e) => write!(f, "Unexpected reply: {e}"),
            Error::AuthenticationFailed(e) => write!(f, "Authentication failed: {e}"),
            Error::InvalidTLSName => write!(f, "Invalid TLS name provided"),
            Error::MissingCredentials => write!(f, "Missing authentication credentials"),
            Error::MissingMailFrom => write!(f, "Missing message sender"),
            Error::MissingRcptTo => write!(f, "Missing message recipients"),
            Error::UnsupportedAuthMechanism => write!(
                f,
                "The server does no support any of the available authentication methods"
            ),
            Error::Timeout => write!(f, "Connection timeout"),
            Error::MissingStartTls => write!(f, "STARTTLS extension unavailable"),
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::Io(err)
    }
}

impl From<base64::DecodeError> for Error {
    fn from(err: base64::DecodeError) -> Self {
        Error::Base64(err)
    }
}

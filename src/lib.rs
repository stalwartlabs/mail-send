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

#[cfg(feature = "http")]
pub mod http;
pub mod message;
#[cfg(feature = "smtp")]
pub mod smtp;

pub use mail_builder;

#[derive(Debug)]
pub enum Error {
    /// I/O error
    Io(std::io::Error),

    /// Base64 decode error
    Base64(base64::DecodeError),

    // SMTP authentication error.
    #[cfg(feature = "smtp")]
    Auth(smtp::auth::Error),

    /// DKIM signing error
    #[cfg(feature = "dkim")]
    DKIM(smtp::dkim::Error),

    /// Failure parsing SMTP reply
    #[cfg(feature = "smtp")]
    UnparseableReply(smtp::reply::Error),

    /// Unexpected SMTP reply.
    #[cfg(feature = "smtp")]
    UnexpectedReply(smtp::reply::Reply),

    /// SMTP authentication failure.
    #[cfg(feature = "smtp")]
    AuthenticationFailed(smtp::reply::Reply),

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

    /// Transport error
    Transport(String),
}

pub type Result<T> = std::result::Result<T, Error>;

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

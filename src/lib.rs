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

//! # mail-send
//!
//! [![crates.io](https://img.shields.io/crates/v/mail-send)](https://crates.io/crates/mail-send)
//! [![build](https://github.com/stalwartlabs/mail-send/actions/workflows/rust.yml/badge.svg)](https://github.com/stalwartlabs/mail-send/actions/workflows/rust.yml)
//! [![docs.rs](https://img.shields.io/docsrs/mail-send)](https://docs.rs/mail-send)
//! [![crates.io](https://img.shields.io/crates/l/mail-send)](http://www.apache.org/licenses/LICENSE-2.0)
//!
//! _mail-send_ is a Rust library to build, sign and send e-mail messages via SMTP. It includes the following features:
//!
//! - Generates **e-mail** messages conforming to the Internet Message Format standard (_RFC 5322_).
//! - Full **MIME** support (_RFC 2045 - 2049_) with automatic selection of the most optimal encoding for each message body part.
//! - DomainKeys Identified Mail (**DKIM**) Signatures (_RFC 6376_).
//! - Simple Mail Transfer Protocol (**SMTP**; _RFC 5321_) delivery.
//! - SMTP Service Extension for Secure SMTP over **TLS** (_RFC 3207_).
//! - SMTP Service Extension for Authentication (_RFC 4954_) with automatic mechanism negotiation (from most secure to least secure):
//!   - CRAM-MD5 (_RFC 2195_)
//!   - DIGEST-MD5 (_RFC 2831_; obsolete but still supported)
//!   - XOAUTH2 (Google proprietary)
//!   - LOGIN
//!   - PLAIN
//! - Full async (requires Tokio).
//!
//! ## Usage Example
//!
//! Send a message via an SMTP server that requires authentication:
//!
//! ```rust
//!     // Build a simple multipart message
//!     let message = MessageBuilder::new()
//!         .from(("John Doe", "john@example.com"))
//!         .to(vec![
//!             ("Jane Doe", "jane@example.com"),
//!             ("James Smith", "james@test.com"),
//!         ])
//!         .subject("Hi!")
//!         .html_body("<h1>Hello, world!</h1>")
//!         .text_body("Hello world!");
//!
//!     // Connect to an SMTP relay server over TLS and
//!     // authenticate using the provided credentials.
//!     Transport::new("smtp.gmail.com")
//!         .credentials("john", "p4ssw0rd")
//!         .connect_tls()
//!         .await
//!         .unwrap()
//!         .send(message)
//!         .await
//!         .unwrap();
//! ```
//!
//! Sign a message with DKIM and send it via an SMTP relay server:
//!
//! ```rust
//!     // Build a simple text message with a single attachment
//!     let message = MessageBuilder::new()
//!         .from(("John Doe", "john@example.com"))
//!         .to("jane@example.com")
//!         .subject("Howdy!")
//!         .text_body("These pretzels are making me thirsty.")
//!         .binary_attachment("image/png", "pretzels.png", [1, 2, 3, 4].as_ref());
//!
//!     // Set up DKIM signer
//!     let dkim = DKIM::from_pkcs1_pem_file("./cert.pem")
//!         .unwrap()
//!         .domain("example.com")
//!         .selector("2022")
//!         .headers(["From", "To", "Subject"]) // Headers to sign
//!         .expiration(60 * 60 * 7); // Number of seconds before this signature expires (optional)
//!
//!     // Connect to an SMTP relay server over TLS.
//!     // Signs each message with the configured DKIM signer.
//!     Transport::new("smtp.example.com")
//!         .dkim(dkim)
//!         .connect_tls()
//!         .await
//!         .unwrap()
//!         .send(message)
//!         .await
//!         .unwrap();
//! ```
//!
//! Send a message via an unsecured SMTP listening on port 2525. Mail-send will automatically upgrade the connection to TLS if the server advertises the STARTTLS extension:
//!
//! ```rust
//!     // Build a simple multipart message
//!     let message = MessageBuilder::new()
//!         .from(("John Doe", "john@example.com"))
//!         .to(vec![
//!             ("Jane Doe", "jane@example.com"),
//!             ("James Smith", "james@test.com"),
//!         ])
//!         .subject("Hi!")
//!         .html_body("<h1>Hello, world!</h1>")
//!         .text_body("Hello world!");
//!
//!     // Send the message
//!     Transport::new("unsecured.example.com")
//!         .port(2525)
//!         .connect()
//!         .await
//!         .unwrap()
//!         .send(message)
//!         .await
//!         .unwrap();
//! ```
//!
//! More examples of how to build messages are available in the [`mail-builder`](https://crates.io/crates/mail-builder) crate.
//! Please note that this library does not support parsing e-mail messages as this functionality is provided separately by the [`mail-parser`](https://crates.io/crates/mail-parser) crate.
//!
//! ## Testing
//!
//! To run the testsuite:
//!
//! ```bash
//!  $ cargo test --all-features
//! ```
//!
//! or, to run the testsuite with MIRI:
//!
//! ```bash
//!  $ cargo +nightly miri test --all-features
//! ```
//!
//! ## License
//!
//! Licensed under either of
//!
//!  * Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
//!  * MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)
//!
//! at your option.
//!
//! ## Copyright
//!
//! Copyright (C) 2020-2022, Stalwart Labs Ltd.
//!
//! See [COPYING] for the license.
//!
//! [COPYING]: https://github.com/stalwartlabs/mail-send/blob/main/COPYING
//!

#[cfg(feature = "dkim")]
pub mod dkim;
pub mod smtp;
#[forbid(unsafe_code)]
pub mod transport;

use std::{borrow::Cow, fmt::Display, time::Duration};

pub use mail_builder;
use smtp::auth::Credentials;
use transport::stream::Stream;

#[derive(Debug)]
pub enum Error {
    /// I/O error
    Io(std::io::Error),

    /// Base64 decode error
    Base64(base64::DecodeError),

    // SMTP authentication error.
    Auth(smtp::auth::Error),

    /// DKIM signing error
    #[cfg(feature = "dkim")]
    DKIM(dkim::Error),

    /// Failure parsing SMTP reply
    UnparseableReply(smtp::reply::Error),

    /// Unexpected SMTP reply.
    UnexpectedReply(smtp::reply::Reply),

    /// SMTP authentication failure.
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
}

pub type Result<T> = std::result::Result<T, Error>;

/// SMTP client.
pub struct Transport<'x, State = Disconnected> {
    pub _state: std::marker::PhantomData<State>,
    pub stream: Stream,
    pub timeout: Duration,
    pub credentials: Option<Credentials<'x>>,
    #[cfg(feature = "dkim")]
    pub dkim: Option<dkim::DKIM<'x>>,
    pub allow_invalid_certs: bool,
    pub hostname: Cow<'x, str>,
    pub port: u16,
}

pub struct Connected;
pub struct Disconnected;

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Io(e) => write!(f, "I/O error: {}", e),
            Error::Base64(e) => write!(f, "Base64 decode error: {}", e),
            Error::Auth(e) => write!(f, "SMTP authentication error: {}", e),
            #[cfg(feature = "dkim")]
            Error::DKIM(e) => write!(f, "DKIM signing error: {}", e),
            Error::UnparseableReply(e) => write!(f, "Unparseable SMTP reply: {}", e),
            Error::UnexpectedReply(e) => e.fmt(f),
            Error::AuthenticationFailed(e) => e.fmt(f),
            Error::InvalidTLSName => write!(f, "Invalid TLS name provided"),
            Error::MissingCredentials => write!(f, "Missing authentication credentials"),
            Error::MissingMailFrom => write!(f, "Missing message sender"),
            Error::MissingRcptTo => write!(f, "Missing message recipients"),
            Error::UnsupportedAuthMechanism => write!(
                f,
                "The server does no support any of the available authentication methods"
            ),
            Error::Timeout => write!(f, "Connection timeout"),
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

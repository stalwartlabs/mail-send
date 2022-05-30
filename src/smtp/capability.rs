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

use super::reply::Severity;
use super::{auth::Mechanism, reply::Reply};
use std::convert::TryFrom;
use std::str::FromStr;

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub enum Capability {
    DSN,
    Atrn,
    Etrn,
    Help,
    StartTLS,
    SmtpUTF8,
    Chunking,
    Pipelining,
    EightBitMIME,
    EnhancedStatusCodes,
    Size(usize),
    Auth(Vec<Mechanism>),
    Unsupported(String),
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct Capabilties {
    hostname: String,
    capabilities: Vec<Capability>,
}

impl TryFrom<Reply> for Capabilties {
    type Error = crate::Error;

    fn try_from(value: Reply) -> Result<Self, Self::Error> {
        if value.severity() != Severity::PositiveCompletion {
            return Err(crate::Error::UnexpectedReply(value));
        }

        let message = value.message();
        let mut hostname = String::with_capacity(0);
        let mut capabilities = Vec::with_capacity(message.len());

        for (pos, line) in message.iter().enumerate() {
            let mut line = line.split(' ');
            if let Some(token) = line.next() {
                if pos > 0 {
                    capabilities.push(match token {
                        "STARTTLS" => Capability::StartTLS,
                        "AUTH" => Capability::Auth({
                            let mut mechanisms = line
                                .filter_map(|mechanism| Mechanism::try_from(mechanism).ok())
                                .collect::<Vec<Mechanism>>();
                            mechanisms.sort_unstable();
                            mechanisms
                        }),
                        "8BITMIME" => Capability::EightBitMIME,
                        "ENHANCEDSTATUSCODES" => Capability::EnhancedStatusCodes,
                        "SMTPUTF8" => Capability::SmtpUTF8,
                        "DSN" => Capability::DSN,
                        "CHUNKING" => Capability::Chunking,
                        "ATRN" => Capability::Atrn,
                        "ETRN" => Capability::Etrn,
                        "HELP" => Capability::Help,
                        "PIPELINING" => Capability::Pipelining,
                        "SIZE" => Capability::Size(
                            usize::from_str(line.next().unwrap_or("0")).unwrap_or(0),
                        ),
                        _ => Capability::Unsupported(token.to_string()),
                    });
                } else {
                    hostname = token.to_string();
                }
            }
        }

        if !hostname.is_empty() {
            Ok(Capabilties {
                hostname,
                capabilities,
            })
        } else {
            Err(crate::Error::UnexpectedReply(value))
        }
    }
}

impl Capabilties {
    #[cfg(test)]
    pub(crate) fn new(hostname: String, capabilities: Vec<Capability>) -> Self {
        Capabilties {
            hostname,
            capabilities,
        }
    }

    /// Returns the hostname of the SMTP server.
    pub fn hostname(&self) -> &str {
        &self.hostname
    }

    /// Returns the capabilities of the SMTP server.
    pub fn capabilities(&self) -> &[Capability] {
        &self.capabilities
    }

    /// Returns `true` if the SMTP server supports the STARTTLS extension.
    pub fn has_capability(&self, capability: &Capability) -> bool {
        self.capabilities.contains(capability)
    }

    /// Returns all supported authentication mechanisms.
    pub fn auth(&self) -> Option<&[Mechanism]> {
        self.capabilities()
            .iter()
            .find_map(|capability| match capability {
                Capability::Auth(mechanisms) if !mechanisms.is_empty() => {
                    Some(mechanisms.as_slice())
                }
                _ => None,
            })
    }
}

#[cfg(test)]
mod test {
    use std::convert::TryFrom;

    use crate::smtp::{auth::Mechanism, reply::ReplyParser};

    use super::{Capability, Capabilties};

    #[test]
    fn capabilities() {
        let mut parser = ReplyParser::new();

        for (reply, parsed_reply) in [
            (
                concat!(
                    "250-foo.com greets bar.com\r\n",
                    "250-8BITMIME\r\n",
                    "250-SIZE\r\n",
                    "250-DSN\r\n",
                    "250 HELP\r\n",
                ),
                Capabilties::new(
                    "foo.com".to_string(),
                    vec![
                        Capability::EightBitMIME,
                        Capability::Size(0),
                        Capability::DSN,
                        Capability::Help,
                    ],
                ),
            ),
            (
                concat!("250 xyz.com is on the air\r\n", ""),
                Capabilties::new("xyz.com".to_string(), vec![]),
            ),
            (
                concat!(
                    "250-smtp.example.com Hello client.example.com\r\n",
                    "250-AUTH GSSAPI DIGEST-MD5\r\n",
                    "250-ENHANCEDSTATUSCODES\r\n",
                    "250 STARTTLS\r\n",
                ),
                Capabilties::new(
                    "smtp.example.com".to_string(),
                    vec![
                        Capability::Auth(vec![Mechanism::DigestMD5]),
                        Capability::EnhancedStatusCodes,
                        Capability::StartTLS,
                    ],
                ),
            ),
            (
                concat!(
                    "250-smtp.example.com Hello client.example.com\r\n",
                    "250 AUTH GSSAPI DIGEST-MD5 PLAIN\r\n",
                ),
                Capabilties::new(
                    "smtp.example.com".to_string(),
                    vec![Capability::Auth(vec![
                        Mechanism::DigestMD5,
                        Mechanism::Plain,
                    ])],
                ),
            ),
            (
                concat!(
                    "250-smtp.example.com Hello client.example.com\r\n",
                    "250-AUTH DIGEST-MD5 CRAM-MD5\r\n",
                    "250-ENHANCEDSTATUSCODES\r\n",
                    "250 STARTTLS\r\n",
                ),
                Capabilties::new(
                    "smtp.example.com".to_string(),
                    vec![
                        Capability::Auth(vec![Mechanism::CramMD5, Mechanism::DigestMD5]),
                        Capability::EnhancedStatusCodes,
                        Capability::StartTLS,
                    ],
                ),
            ),
            (
                concat!(
                    "250-smtp.example.com Hello client.example.com\r\n",
                    "250-AUTH GSSAPI DIGEST-MD5\r\n",
                    "250-ENHANCEDSTATUSCODES\r\n",
                    "250 STARTTLS\r\n",
                ),
                Capabilties::new(
                    "smtp.example.com".to_string(),
                    vec![
                        Capability::Auth(vec![Mechanism::DigestMD5]),
                        Capability::EnhancedStatusCodes,
                        Capability::StartTLS,
                    ],
                ),
            ),
        ] {
            assert_eq!(
                Capabilties::try_from(parser.parse(reply.as_bytes()).unwrap()).unwrap(),
                parsed_reply
            );
        }
    }
}

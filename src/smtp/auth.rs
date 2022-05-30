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

use std::{borrow::Cow, convert::TryFrom, fmt::Display};

pub struct Credentials<'x> {
    username: Cow<'x, str>,
    secret: Cow<'x, str>,
}

impl<'x> From<(&'x str, &'x str)> for Credentials<'x> {
    fn from(credentials: (&'x str, &'x str)) -> Self {
        Credentials {
            username: credentials.0.into(),
            secret: credentials.1.into(),
        }
    }
}

impl<'x> From<(String, String)> for Credentials<'x> {
    fn from(credentials: (String, String)) -> Self {
        Credentials {
            username: credentials.0.into(),
            secret: credentials.1.into(),
        }
    }
}

#[derive(Debug, Clone)]
pub enum Error {
    InvalidChallenge,
}

/// Authentication mechanism
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Mechanism {
    /// Plain
    Plain = 5,

    /// Login
    Login = 4,

    /// Digest MD5
    #[cfg(feature = "digest-md5")]
    DigestMD5 = 3,

    /// Challenge-Response Authentication Mechanism (CRAM)
    #[cfg(feature = "cram-md5")]
    CramMD5 = 2,

    /// SASL XOAUTH2 (used by Google)
    XOauth2 = 1,
}

impl TryFrom<&str> for Mechanism {
    type Error = ();

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s {
            "PLAIN" => Ok(Mechanism::Plain),
            "LOGIN" => Ok(Mechanism::Login),
            #[cfg(feature = "digest-md5")]
            "DIGEST-MD5" => Ok(Mechanism::DigestMD5),
            #[cfg(feature = "cram-md5")]
            "CRAM-MD5" => Ok(Mechanism::CramMD5),
            "XOAUTH2" => Ok(Mechanism::XOauth2),
            _ => Err(()),
        }
    }
}

impl Display for Mechanism {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Mechanism::Plain => write!(f, "PLAIN"),
            Mechanism::Login => write!(f, "LOGIN"),
            #[cfg(feature = "digest-md5")]
            Mechanism::DigestMD5 => write!(f, "DIGEST-MD5"),
            #[cfg(feature = "cram-md5")]
            Mechanism::CramMD5 => write!(f, "CRAM-MD5"),
            Mechanism::XOauth2 => write!(f, "XOAUTH2"),
        }
    }
}

impl<'x> Credentials<'x> {
    /// Creates a new `Credentials` instance.
    pub fn new(
        username: impl Into<Cow<'x, str>>,
        secret: impl Into<Cow<'x, str>>,
    ) -> Credentials<'x> {
        Credentials {
            username: username.into(),
            secret: secret.into(),
        }
    }

    pub(crate) fn encode(&self, mechanism: Mechanism, challenge: &str) -> crate::Result<String> {
        Ok(base64::encode(
            match mechanism {
                Mechanism::Plain => {
                    format!("\u{0}{}\u{0}{}", self.username, self.secret)
                }

                Mechanism::Login => {
                    let challenge = base64::decode(challenge)?;

                    if b"user name"
                        .eq_ignore_ascii_case(challenge.get(0..9).ok_or(Error::InvalidChallenge)?)
                        || b"username".eq_ignore_ascii_case(
                            // Because Google makes its own standards
                            challenge.get(0..8).ok_or(Error::InvalidChallenge)?,
                        )
                    {
                        &self.username
                    } else if b"password"
                        .eq_ignore_ascii_case(challenge.get(0..8).ok_or(Error::InvalidChallenge)?)
                    {
                        &self.secret
                    } else {
                        return Err(Error::InvalidChallenge.into());
                    }
                    .to_string()
                }

                #[cfg(feature = "digest-md5")]
                Mechanism::DigestMD5 => {
                    let mut buf = Vec::with_capacity(10);
                    let mut key = None;
                    let mut in_quote = false;
                    let mut values = std::collections::HashMap::new();
                    let challenge = base64::decode(challenge)?;
                    let challenge_len = challenge.len();

                    for (pos, byte) in challenge.into_iter().enumerate() {
                        let add_key = match byte {
                            b'=' if !in_quote => {
                                if key.is_none() && !buf.is_empty() {
                                    key = String::from_utf8_lossy(&buf).into_owned().into();
                                    buf.clear();
                                } else {
                                    return Err(Error::InvalidChallenge.into());
                                }
                                false
                            }
                            b',' if !in_quote => true,
                            b'"' => {
                                in_quote = !in_quote;
                                false
                            }
                            _ => {
                                buf.push(byte);
                                false
                            }
                        };

                        if (add_key || pos == challenge_len - 1) && key.is_some() && !buf.is_empty()
                        {
                            values.insert(
                                key.take().unwrap(),
                                String::from_utf8_lossy(&buf).into_owned(),
                            );
                            buf.clear();
                        }
                    }

                    let (digest_uri, realm, realm_response) =
                        if let Some(realm) = values.get("realm") {
                            (
                                format!("smtp/{}", realm),
                                realm.as_str(),
                                format!(",realm=\"{}\"", realm),
                            )
                        } else {
                            ("smtp/localhost".to_string(), "", "".to_string())
                        };

                    let credentials = md5::compute(
                        format!("{}:{}:{}", self.username, realm, self.secret).as_bytes(),
                    );

                    let a2 = md5::compute(
                        if values.get("qpop").map_or(false, |v| v == "auth") {
                            format!("AUTHENTICATE:{}", digest_uri)
                        } else {
                            format!(
                                "AUTHENTICATE:{}:00000000000000000000000000000000",
                                digest_uri
                            )
                        }
                        .as_bytes(),
                    );

                    #[allow(unused_variables)]
                    let cnonce = {
                        use rand::RngCore;
                        let mut buf = [0u8; 16];
                        rand::thread_rng().fill_bytes(&mut buf);
                        base64::encode(&buf)
                    };

                    #[cfg(test)]
                    let cnonce = "OA6MHXh6VqTrRk".to_string();
                    let nonce = values.remove("nonce").unwrap_or_default();
                    let qop = values.remove("qop").unwrap_or_default();
                    let charset = values
                        .remove("charset")
                        .unwrap_or_else(|| "utf-8".to_string());

                    format!(
                        concat!(
                            "charset={},username=\"{}\",realm=\"{}\",nonce=\"{}\",nc=00000001,",
                            "cnonce=\"{}\",digest-uri=\"{}\",response={:x},qop={}"
                        ),
                        charset,
                        self.username,
                        realm_response,
                        nonce,
                        cnonce,
                        digest_uri,
                        md5::compute(
                            format!(
                                "{:x}:{}:00000001:{}:{}:{:x}",
                                credentials, nonce, cnonce, qop, a2
                            )
                            .as_bytes()
                        ),
                        qop
                    )
                }

                #[cfg(feature = "cram-md5")]
                Mechanism::CramMD5 => {
                    let mut secret_opad: Vec<u8> = vec![0x5c; 64];
                    let mut secret_ipad: Vec<u8> = vec![0x36; 64];

                    if self.secret.len() < 64 {
                        for (pos, byte) in self.secret.as_bytes().iter().enumerate() {
                            secret_opad[pos] = *byte ^ 0x5c;
                            secret_ipad[pos] = *byte ^ 0x36;
                        }
                    } else {
                        for (pos, byte) in md5::compute(self.secret.as_bytes()).iter().enumerate() {
                            secret_opad[pos] = *byte ^ 0x5c;
                            secret_ipad[pos] = *byte ^ 0x36;
                        }
                    }

                    secret_ipad.extend_from_slice(&base64::decode(challenge)?);
                    secret_opad.extend_from_slice(&md5::compute(&secret_ipad).0);

                    format!("{} {:x}", self.username, md5::compute(&secret_opad))
                }

                Mechanism::XOauth2 => format!(
                    "user={}\x01auth=Bearer {}\x01\x01",
                    self.username, self.secret
                ),
            }
            .as_bytes(),
        ))
    }
}

#[cfg(test)]
mod test {
    use std::convert::TryInto;

    use crate::smtp::auth::{Credentials, Mechanism};

    #[test]
    fn auth_encode() {
        // Digest-MD5
        #[cfg(feature = "digest-md5")]
        assert_eq!(
            Credentials::new("chris", "secret")
                .encode(
                    Mechanism::DigestMD5,
                    concat!(
                        "cmVhbG09ImVsd29vZC5pbm5vc29mdC5jb20iLG5vbmNlPSJPQTZNRzl0",
                        "RVFHbTJoaCIscW9wPSJhdXRoIixhbGdvcml0aG09bWQ1LXNlc3MsY2hh",
                        "cnNldD11dGYtOA=="
                    ),
                )
                .unwrap(),
            concat!(
                "Y2hhcnNldD11dGYtOCx1c2VybmFtZT0iY2hyaXMiLHJlYWxtPSIscmVhbG0",
                "9ImVsd29vZC5pbm5vc29mdC5jb20iIixub25jZT0iT0E2TUc5dEVRR20yaG",
                "giLG5jPTAwMDAwMDAxLGNub25jZT0iT0E2TUhYaDZWcVRyUmsiLGRpZ2Vzd",
                "C11cmk9InNtdHAvZWx3b29kLmlubm9zb2Z0LmNvbSIscmVzcG9uc2U9NDQ2",
                "NjIxODg3MzlmYzcxOGNlYmYyZjA4MTk4MWI4ZDIscW9wPWF1dGg=",
            )
        );

        // Challenge-Response Authentication Mechanism (CRAM)
        #[cfg(feature = "cram-md5")]
        assert_eq!(
            Credentials::new("tim", "tanstaaftanstaaf")
                .encode(
                    Mechanism::CramMD5,
                    "PDE4OTYuNjk3MTcwOTUyQHBvc3RvZmZpY2UucmVzdG9uLm1jaS5uZXQ+",
                )
                .unwrap(),
            "dGltIGI5MTNhNjAyYzdlZGE3YTQ5NWI0ZTZlNzMzNGQzODkw"
        );

        // SASL XOAUTH2
        assert_eq!(
            Credentials::new(
                "someuser@example.com",
                "ya29.vF9dft4qmTc2Nvb3RlckBhdHRhdmlzdGEuY29tCg"
            )
            .encode(Mechanism::XOauth2, "",)
            .unwrap(),
            concat!(
                "dXNlcj1zb21ldXNlckBleGFtcGxlLmNvbQFhdXRoPUJlYXJlciB5YTI5Ln",
                "ZGOWRmdDRxbVRjMk52YjNSbGNrQmhkSFJoZG1semRHRXVZMjl0Q2cBAQ=="
            )
        );

        // Login
        assert_eq!(
            Credentials::new("tim", "tanstaaftanstaaf")
                .encode(Mechanism::Login, "VXNlciBOYW1lAA==",)
                .unwrap(),
            "dGlt"
        );
        assert_eq!(
            Credentials::new("tim", "tanstaaftanstaaf")
                .encode(Mechanism::Login, "UGFzc3dvcmQA",)
                .unwrap(),
            "dGFuc3RhYWZ0YW5zdGFhZg=="
        );

        // Plain
        assert_eq!(
            Credentials::new("tim", "tanstaaftanstaaf")
                .encode(Mechanism::Plain, "",)
                .unwrap(),
            "AHRpbQB0YW5zdGFhZnRhbnN0YWFm"
        );
    }

    #[test]
    fn sort_mechanisms() {
        let mut mechs: Vec<Mechanism> = vec![
            "CRAM-MD5".try_into().unwrap(),
            "XOAUTH2".try_into().unwrap(),
            "PLAIN".try_into().unwrap(),
            "DIGEST-MD5".try_into().unwrap(),
            "LOGIN".try_into().unwrap(),
        ];
        mechs.sort_unstable();
        assert_eq!(
            mechs,
            vec![
                Mechanism::XOauth2,
                Mechanism::CramMD5,
                Mechanism::DigestMD5,
                Mechanism::Login,
                Mechanism::Plain,
            ]
        );
    }
}

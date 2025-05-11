/*
 * Copyright Stalwart Labs Ltd.
 *
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 */

use std::{fmt::Display, hash::Hash};

use base64::{engine, Engine};
use smtp_proto::{
    response::generate::BitToString, EhloResponse, AUTH_CRAM_MD5, AUTH_DIGEST_MD5, AUTH_LOGIN,
    AUTH_OAUTHBEARER, AUTH_PLAIN, AUTH_XOAUTH2,
};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{Credentials, SmtpClient};

impl<T: AsyncRead + AsyncWrite + Unpin> SmtpClient<T> {
    pub async fn authenticate<U>(
        &mut self,
        credentials: impl AsRef<Credentials<U>>,
        capabilities: impl AsRef<EhloResponse<String>>,
    ) -> crate::Result<&mut Self>
    where
        U: AsRef<str> + PartialEq + Eq + Hash,
    {
        let credentials = credentials.as_ref();
        let capabilities = capabilities.as_ref();
        let mut available_mechanisms = match &credentials {
            Credentials::Plain { .. } => AUTH_CRAM_MD5 | AUTH_DIGEST_MD5 | AUTH_LOGIN | AUTH_PLAIN,
            Credentials::OAuthBearer { .. } => AUTH_OAUTHBEARER,
            Credentials::XOauth2 { .. } => AUTH_XOAUTH2,
        } & capabilities.auth_mechanisms;

        // Try authenticating from most secure to least secure
        let mut has_err = None;
        let mut has_failed = false;

        while available_mechanisms != 0 && !has_failed {
            let mechanism = 1 << ((63 - available_mechanisms.leading_zeros()) as u64);
            available_mechanisms ^= mechanism;
            match self.auth(mechanism, credentials).await {
                Ok(_) => {
                    return Ok(self);
                }
                Err(err) => match err {
                    crate::Error::UnexpectedReply(reply) => {
                        has_failed = reply.code() == 535;
                        has_err = reply.into();
                    }
                    crate::Error::UnsupportedAuthMechanism => (),
                    _ => return Err(err),
                },
            }
        }

        if let Some(has_err) = has_err {
            Err(crate::Error::AuthenticationFailed(has_err))
        } else {
            Err(crate::Error::UnsupportedAuthMechanism)
        }
    }

    pub(crate) async fn auth<U>(
        &mut self,
        mechanism: u64,
        credentials: &Credentials<U>,
    ) -> crate::Result<()>
    where
        U: AsRef<str> + PartialEq + Eq + Hash,
    {
        let mut reply = if (mechanism & (AUTH_PLAIN | AUTH_XOAUTH2 | AUTH_OAUTHBEARER)) != 0 {
            self.cmd(
                format!(
                    "AUTH {} {}\r\n",
                    mechanism.to_mechanism(),
                    credentials.encode(mechanism, "")?,
                )
                .as_bytes(),
            )
            .await?
        } else {
            self.cmd(format!("AUTH {}\r\n", mechanism.to_mechanism()).as_bytes())
                .await?
        };

        for _ in 0..3 {
            match reply.code() {
                334 => {
                    reply = self
                        .cmd(
                            format!("{}\r\n", credentials.encode(mechanism, reply.message())?)
                                .as_bytes(),
                        )
                        .await?;
                }
                235 => {
                    return Ok(());
                }
                _ => {
                    return Err(crate::Error::UnexpectedReply(reply));
                }
            }
        }

        Err(crate::Error::UnexpectedReply(reply))
    }
}

#[derive(Debug, Clone)]
pub enum Error {
    InvalidChallenge,
}

impl<T: AsRef<str> + PartialEq + Eq + Hash> Credentials<T> {
    /// Creates a new `Credentials` instance.
    pub fn new(username: T, secret: T) -> Credentials<T> {
        Credentials::Plain { username, secret }
    }

    /// Creates a new XOAuth2 `Credentials` instance.
    pub fn new_xoauth2(username: T, secret: T) -> Credentials<T> {
        Credentials::XOauth2 { username, secret }
    }

    /// Creates a new OAuthBearer `Credentials` instance.
    pub fn new_oauth(payload: T) -> Credentials<T> {
        Credentials::OAuthBearer { token: payload }
    }

    /// Creates a new OAuthBearer `Credentials` instance from a Bearer token.
    pub fn new_oauth_from_token(token: T) -> Credentials<String> {
        Credentials::OAuthBearer {
            token: format!("auth=Bearer {}\x01\x01", token.as_ref()),
        }
    }

    pub fn encode(&self, mechanism: u64, challenge: &str) -> crate::Result<String> {
        Ok(engine::general_purpose::STANDARD.encode(
            match (mechanism, self) {
                (AUTH_PLAIN, Credentials::Plain { username, secret }) => {
                    format!("\u{0}{}\u{0}{}", username.as_ref(), secret.as_ref())
                }

                (AUTH_LOGIN, Credentials::Plain { username, secret }) => {
                    let challenge = engine::general_purpose::STANDARD.decode(challenge)?;
                    let username = username.as_ref();
                    let secret = secret.as_ref();

                    if b"user name"
                        .eq_ignore_ascii_case(challenge.get(0..9).ok_or(Error::InvalidChallenge)?)
                        || b"username".eq_ignore_ascii_case(
                            // Because Google makes its own standards
                            challenge.get(0..8).ok_or(Error::InvalidChallenge)?,
                        )
                    {
                        &username
                    } else if b"password"
                        .eq_ignore_ascii_case(challenge.get(0..8).ok_or(Error::InvalidChallenge)?)
                    {
                        &secret
                    } else {
                        return Err(Error::InvalidChallenge.into());
                    }
                    .to_string()
                }

                #[cfg(feature = "digest-md5")]
                (AUTH_DIGEST_MD5, Credentials::Plain { username, secret }) => {
                    let mut buf = Vec::with_capacity(10);
                    let mut key = None;
                    let mut in_quote = false;
                    let mut values = std::collections::HashMap::new();
                    let challenge = engine::general_purpose::STANDARD.decode(challenge)?;
                    let challenge_len = challenge.len();
                    let username = username.as_ref();
                    let secret = secret.as_ref();

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
                                format!("smtp/{realm}"),
                                realm.as_str(),
                                format!(",realm=\"{realm}\""),
                            )
                        } else {
                            ("smtp/localhost".to_string(), "", "".to_string())
                        };

                    let credentials =
                        md5::compute(format!("{username}:{realm}:{secret}").as_bytes());

                    let a2 = md5::compute(
                        if values.get("qpop").is_some_and(|v| v == "auth") {
                            format!("AUTHENTICATE:{digest_uri}")
                        } else {
                            format!("AUTHENTICATE:{digest_uri}:00000000000000000000000000000000")
                        }
                        .as_bytes(),
                    );

                    #[allow(unused_variables)]
                    let cnonce = {
                        use rand::RngCore;
                        let mut buf = [0u8; 16];
                        rand::rng().fill_bytes(&mut buf);
                        engine::general_purpose::STANDARD.encode(buf)
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
                        username,
                        realm_response,
                        nonce,
                        cnonce,
                        digest_uri,
                        md5::compute(
                            format!("{credentials:x}:{nonce}:00000001:{cnonce}:{qop}:{a2:x}")
                                .as_bytes()
                        ),
                        qop
                    )
                }

                #[cfg(feature = "cram-md5")]
                (AUTH_CRAM_MD5, Credentials::Plain { username, secret }) => {
                    let mut secret_opad: Vec<u8> = vec![0x5c; 64];
                    let mut secret_ipad: Vec<u8> = vec![0x36; 64];
                    let username = username.as_ref();
                    let secret = secret.as_ref();

                    if secret.len() < 64 {
                        for (pos, byte) in secret.as_bytes().iter().enumerate() {
                            secret_opad[pos] = *byte ^ 0x5c;
                            secret_ipad[pos] = *byte ^ 0x36;
                        }
                    } else {
                        for (pos, byte) in md5::compute(secret.as_bytes()).iter().enumerate() {
                            secret_opad[pos] = *byte ^ 0x5c;
                            secret_ipad[pos] = *byte ^ 0x36;
                        }
                    }

                    secret_ipad
                        .extend_from_slice(&engine::general_purpose::STANDARD.decode(challenge)?);
                    secret_opad.extend_from_slice(&md5::compute(&secret_ipad).0);

                    format!("{} {:x}", username, md5::compute(&secret_opad))
                }

                (AUTH_XOAUTH2, Credentials::XOauth2 { username, secret }) => format!(
                    "user={}\x01auth=Bearer {}\x01\x01",
                    username.as_ref(),
                    secret.as_ref()
                ),
                (AUTH_OAUTHBEARER, Credentials::OAuthBearer { token }) => {
                    token.as_ref().to_string()
                }
                _ => return Err(crate::Error::UnsupportedAuthMechanism),
            }
            .as_bytes(),
        ))
    }
}

impl<'x> From<(&'x str, &'x str)> for Credentials<&'x str> {
    fn from(credentials: (&'x str, &'x str)) -> Self {
        Credentials::Plain {
            username: credentials.0,
            secret: credentials.1,
        }
    }
}

impl From<(String, String)> for Credentials<String> {
    fn from(credentials: (String, String)) -> Self {
        Credentials::Plain {
            username: credentials.0,
            secret: credentials.1,
        }
    }
}

impl<U: AsRef<str> + PartialEq + Eq + Hash> AsRef<Credentials<U>> for Credentials<U> {
    fn as_ref(&self) -> &Credentials<U> {
        self
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::InvalidChallenge => write!(f, "Invalid challenge received."),
        }
    }
}

#[cfg(test)]
mod test {

    use smtp_proto::{AUTH_CRAM_MD5, AUTH_DIGEST_MD5, AUTH_LOGIN, AUTH_PLAIN, AUTH_XOAUTH2};

    use crate::smtp::auth::Credentials;

    #[test]
    fn auth_encode() {
        // Digest-MD5
        #[cfg(feature = "digest-md5")]
        assert_eq!(
            Credentials::new("chris", "secret")
                .encode(
                    AUTH_DIGEST_MD5,
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
                    AUTH_CRAM_MD5,
                    "PDE4OTYuNjk3MTcwOTUyQHBvc3RvZmZpY2UucmVzdG9uLm1jaS5uZXQ+",
                )
                .unwrap(),
            "dGltIGI5MTNhNjAyYzdlZGE3YTQ5NWI0ZTZlNzMzNGQzODkw"
        );

        // SASL XOAUTH2
        assert_eq!(
            Credentials::XOauth2 {
                username: "someuser@example.com",
                secret: "ya29.vF9dft4qmTc2Nvb3RlckBhdHRhdmlzdGEuY29tCg"
            }
            .encode(AUTH_XOAUTH2, "",)
            .unwrap(),
            concat!(
                "dXNlcj1zb21ldXNlckBleGFtcGxlLmNvbQFhdXRoPUJlYXJlciB5YTI5Ln",
                "ZGOWRmdDRxbVRjMk52YjNSbGNrQmhkSFJoZG1semRHRXVZMjl0Q2cBAQ=="
            )
        );

        // Login
        assert_eq!(
            Credentials::new("tim", "tanstaaftanstaaf")
                .encode(AUTH_LOGIN, "VXNlciBOYW1lAA==",)
                .unwrap(),
            "dGlt"
        );
        assert_eq!(
            Credentials::new("tim", "tanstaaftanstaaf")
                .encode(AUTH_LOGIN, "UGFzc3dvcmQA",)
                .unwrap(),
            "dGFuc3RhYWZ0YW5zdGFhZg=="
        );

        // Plain
        assert_eq!(
            Credentials::new("tim", "tanstaaftanstaaf")
                .encode(AUTH_PLAIN, "",)
                .unwrap(),
            "AHRpbQB0YW5zdGFhZnRhbnN0YWFm"
        );
    }
}

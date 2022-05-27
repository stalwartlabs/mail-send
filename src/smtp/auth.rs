use std::{borrow::Cow, collections::HashMap};

pub struct Credentials<'x> {
    username: Cow<'x, str>,
    secret: Cow<'x, str>,
}

#[derive(Debug, Clone)]
pub enum Error {
    InvalidChallenge,
}

pub enum Mechanism {
    /// Plain
    Plain,
    /// Login
    Login,
    /// Digest MD5
    DigestMD5,
    /// Challenge-Response Authentication Mechanism (CRAM)
    CramMD5,
    /// SASL XOAUTH2
    XOauth2,
}

impl<'x> Credentials<'x> {
    pub fn new(
        username: impl Into<Cow<'x, str>>,
        secret: impl Into<Cow<'x, str>>,
    ) -> Credentials<'x> {
        Credentials {
            username: username.into(),
            secret: secret.into(),
        }
    }

    pub fn encode(&self, mechanism: Mechanism, challenge: &str) -> super::Result<String> {
        Ok(match mechanism {
            Mechanism::Plain => {
                base64::encode(format!("\u{0}{}\u{0}{}", self.username, self.secret).as_bytes())
            }
            Mechanism::Login => {
                let challenge = base64::decode(challenge)?;
                base64::encode(
                    if b"user name"
                        .eq_ignore_ascii_case(challenge.get(0..9).ok_or(Error::InvalidChallenge)?)
                    {
                        &self.username
                    } else if b"password"
                        .eq_ignore_ascii_case(challenge.get(0..8).ok_or(Error::InvalidChallenge)?)
                    {
                        &self.secret
                    } else {
                        return Err(Error::InvalidChallenge.into());
                    }
                    .as_bytes(),
                )
            }
            Mechanism::DigestMD5 => {
                let mut buf = Vec::with_capacity(10);
                let mut key = None;
                let mut in_quote = false;
                let mut values = HashMap::new();
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

                    if (add_key || pos == challenge_len - 1) && key.is_some() && !buf.is_empty() {
                        values.insert(
                            key.take().unwrap(),
                            String::from_utf8_lossy(&buf).into_owned(),
                        );
                        buf.clear();
                    }
                }

                println!("{:?}", values);

                todo!()
            }
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

                base64::encode(
                    format!("{} {:x}", self.username, md5::compute(&secret_opad)).as_bytes(),
                )
            }
            Mechanism::XOauth2 => base64::encode(
                format!(
                    "user={}\x01auth=Bearer {}\x01\x01",
                    self.username, self.secret
                )
                .as_bytes(),
            ),
        })
    }
}

#[cfg(test)]
mod test {
    use crate::smtp::auth::{Credentials, Mechanism};

    #[test]
    fn auth_encode() {
        // Digest-MD5
        assert_eq!(
            Credentials::new("tim", "tanstaaftanstaaf")
                .encode(
                    Mechanism::DigestMD5,
                    concat!(
                        "cmVhbG09ImVsd29vZC5pbm5vc29mdC5jb20iLG5vbmNlPSJPQTZNRzl0",
                        "RVFHbTJoaCIscW9wPSJhdXRoIixhbGdvcml0aG09bWQ1LXNlc3MsY2hh",
                        "cnNldD11dGYtOA=="
                    ),
                )
                .unwrap(),
            "d"
        );

        // Challenge-Response Authentication Mechanism (CRAM)
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
            "dGVzdAB0ZXN0ADEyMzQ="
        );
    }
}

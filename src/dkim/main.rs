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

use std::{borrow::Cow, io::Write, path::Path, time::SystemTime};

use rsa::{pkcs1::DecodeRsaPrivateKey, PaddingScheme, RsaPrivateKey};
use sha2::{Digest, Sha256};

use super::{Error, Signature, DKIM};

impl<'x> DKIM<'x> {
    /// Creates a new DKIM signer from a PKCS1 PEM file.
    pub fn from_pkcs1_pem_file(path: &str) -> crate::Result<Self> {
        Ok(DKIM {
            private_key: RsaPrivateKey::read_pkcs1_pem_file(Path::new(path))
                .map_err(Error::PKCS)?,
            domain: "".into(),
            selector: "".into(),
            sign_headers: Vec::with_capacity(0),
            expiration: 0,
        })
    }

    /// Creates a new DKIM signer from a PKCS1 PEM string.
    pub fn from_pkcs1_pem(pem: &str) -> crate::Result<Self> {
        Ok(DKIM {
            private_key: RsaPrivateKey::from_pkcs1_pem(pem).map_err(Error::PKCS)?,
            domain: "".into(),
            selector: "".into(),
            sign_headers: Vec::with_capacity(0),
            expiration: 0,
        })
    }

    /// Creates a new DKIM signer from a PKCS1 binary file.
    pub fn from_pkcs1_der_file(path: &str) -> crate::Result<Self> {
        Ok(DKIM {
            private_key: RsaPrivateKey::read_pkcs1_der_file(Path::new(path))
                .map_err(Error::PKCS)?,
            domain: "".into(),
            selector: "".into(),
            sign_headers: Vec::with_capacity(0),
            expiration: 0,
        })
    }

    /// Creates a new DKIM signer from a PKCS1 binary slice.
    pub fn from_pkcs1_der(bytes: &[u8]) -> crate::Result<Self> {
        Ok(DKIM {
            private_key: RsaPrivateKey::from_pkcs1_der(bytes).map_err(Error::PKCS)?,
            domain: "".into(),
            selector: "".into(),
            sign_headers: Vec::with_capacity(0),
            expiration: 0,
        })
    }

    /// Sets the headers to sign.
    pub fn headers(mut self, headers: impl IntoIterator<Item = &'x str>) -> Self {
        self.sign_headers = headers
            .into_iter()
            .map(|h| Cow::Borrowed(h.as_bytes()))
            .collect();
        self
    }

    /// Sets the domain to use for signing.
    pub fn domain(mut self, domain: impl Into<Cow<'x, str>>) -> Self {
        self.domain = domain.into();
        self
    }

    /// Sets the selector to use for signing.
    pub fn selector(mut self, selector: impl Into<Cow<'x, str>>) -> Self {
        self.selector = selector.into();
        self
    }

    /// Sets the number of seconds from now to use for the signature expiration.
    pub fn expiration(mut self, expiration: u64) -> Self {
        self.expiration = expiration;
        self
    }

    /// Signs a message.
    pub fn sign(&self, message: &[u8]) -> crate::Result<Signature> {
        self.sign_with_time(
            message,
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        )
    }

    /// Signs a message using the provide current time.
    pub fn sign_with_time(&self, message: &[u8], now: u64) -> crate::Result<Signature> {
        let mut body_hasher = Sha256::new();
        let mut header_hasher = Sha256::new();

        // Canonicalize headers and body
        let signed_headers =
            self.canonicalize_relaxed(message, &mut header_hasher, &mut body_hasher)?;
        if signed_headers.is_empty() {
            return Err(Error::NoHeadersFound.into());
        } else if self.domain.is_empty() || self.selector.is_empty() {
            return Err(Error::MissingParameters.into());
        }

        let mut signature = Signature {
            d: self.domain.clone(),
            s: self.selector.clone(),
            b: String::new(),
            bh: base64::encode(body_hasher.finalize()),
            h: signed_headers,
            t: now,
            x: if self.expiration > 0 {
                now + self.expiration
            } else {
                0
            },
        };

        // Add signature to hash
        header_hasher.write_all(b"dkim-signature:")?;
        signature.write(&mut header_hasher, false)?;

        // RSA Sign
        signature.b = base64::encode(
            &self
                .private_key
                .sign(
                    PaddingScheme::new_pkcs1v15_sign::<Sha256>(),
                    &header_hasher.finalize(),
                )
                .map_err(Error::RSA)?,
        );

        Ok(signature)
    }
}

#[cfg(test)]
mod test {

    const TEST_KEY: &str = r#"-----BEGIN RSA PRIVATE KEY-----
MIICXwIBAAKBgQDwIRP/UC3SBsEmGqZ9ZJW3/DkMoGeLnQg1fWn7/zYtIxN2SnFC
jxOCKG9v3b4jYfcTNh5ijSsq631uBItLa7od+v/RtdC2UzJ1lWT947qR+Rcac2gb
to/NMqJ0fzfVjH4OuKhitdY9tf6mcwGjaNBcWToIMmPSPDdQPNUYckcQ2QIDAQAB
AoGBALmn+XwWk7akvkUlqb+dOxyLB9i5VBVfje89Teolwc9YJT36BGN/l4e0l6QX
/1//6DWUTB3KI6wFcm7TWJcxbS0tcKZX7FsJvUz1SbQnkS54DJck1EZO/BLa5ckJ
gAYIaqlA9C0ZwM6i58lLlPadX/rtHb7pWzeNcZHjKrjM461ZAkEA+itss2nRlmyO
n1/5yDyCluST4dQfO8kAB3toSEVc7DeFeDhnC1mZdjASZNvdHS4gbLIA1hUGEF9m
3hKsGUMMPwJBAPW5v/U+AWTADFCS22t72NUurgzeAbzb1HWMqO4y4+9Hpjk5wvL/
eVYizyuce3/fGke7aRYw/ADKygMJdW8H/OcCQQDz5OQb4j2QDpPZc0Nc4QlbvMsj
7p7otWRO5xRa6SzXqqV3+F0VpqvDmshEBkoCydaYwc2o6WQ5EBmExeV8124XAkEA
qZzGsIxVP+sEVRWZmW6KNFSdVUpk3qzK0Tz/WjQMe5z0UunY9Ax9/4PVhp/j61bf
eAYXunajbBSOLlx4D+TunwJBANkPI5S9iylsbLs6NkaMHV6k5ioHBBmgCak95JGX
GMot/L2x0IYyMLAz6oLWh2hm7zwtb0CgOrPo1ke44hFYnfc=
-----END RSA PRIVATE KEY-----"#;

    #[test]
    fn dkim_sign() {
        let dkim = super::DKIM::from_pkcs1_pem(TEST_KEY)
            .unwrap()
            .headers(["From", "To", "Subject"])
            .domain("stalw.art")
            .selector("default");
        let signature = dkim
            .sign_with_time(
                concat!(
                    "From: hello@stalw.art\r\n",
                    "To: dkim@stalw.art\r\n",
                    "Subject: Testing  DKIM!\r\n\r\n",
                    "Here goes the test\r\n\r\n"
                )
                .as_bytes(),
                311923920,
            )
            .unwrap();
        assert_eq!(
            concat!(
                "v=1; a=rsa-sha256; s=default; d=stalw.art; c=relaxed/relaxed; ",
                "h=subject:to:from; t=311923920; ",
                "bh=QoiUNYyUV+1tZ/xUPRcE+gST2zAStvJx1OK078Ylm5s=; ",
                "b=hkc6s33ZpxcHi5TQVPUTNQ+Qof/R5mJn+jP/kjKrCVuezU5kGUSO27Sln42B",
                "CRwLrG1g0fzLTTb6CjaW68JD4FoIjhe5u7kQuDnq5swmlRdLvqfc7Mg4VGhQJqm",
                "gOmvyiymsro9VCwBJCfZ5FHI49PN9YgmhLUB/YqLNlbNDVwo=;",
            ),
            signature.to_string()
        );
    }
}

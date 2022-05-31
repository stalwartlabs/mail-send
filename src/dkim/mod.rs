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

use std::borrow::Cow;

use rsa::RsaPrivateKey;

pub mod canonicalize;
pub mod main;
pub mod signature;

#[derive(Debug)]
pub enum Error {
    ParseError,
    MissingParameters,
    NoHeadersFound,
    RSA(rsa::errors::Error),
    PKCS(rsa::pkcs1::Error),
}

pub struct DKIM<'x> {
    private_key: RsaPrivateKey,
    domain: Cow<'x, str>,
    selector: Cow<'x, str>,
    sign_headers: Vec<Cow<'x, [u8]>>,
    expiration: u64,
}

pub struct Signature<'x> {
    d: Cow<'x, str>,
    s: Cow<'x, str>,
    b: String,
    bh: String,
    h: Vec<Vec<u8>>,
    x: u64,
    t: u64,
}

impl From<Error> for crate::Error {
    fn from(err: Error) -> Self {
        crate::Error::DKIM(err)
    }
}

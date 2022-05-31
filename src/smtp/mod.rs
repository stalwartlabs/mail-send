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

pub mod auth;
pub mod capability;
pub mod message;
pub mod reply;

impl From<auth::Error> for crate::Error {
    fn from(err: auth::Error) -> Self {
        crate::Error::Auth(err)
    }
}

impl From<reply::Error> for crate::Error {
    fn from(err: reply::Error) -> Self {
        crate::Error::UnparseableReply(err)
    }
}

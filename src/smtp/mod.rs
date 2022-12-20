/*
 * Copyright Stalwart Labs Ltd.
 *
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 */

use smtp_proto::{Response, Severity};

pub mod auth;
pub mod builder;
pub mod client;
pub mod ehlo;
pub mod envelope;
pub mod message;
pub mod tls;

impl From<auth::Error> for crate::Error {
    fn from(err: auth::Error) -> Self {
        crate::Error::Auth(err)
    }
}

trait AssertReply {
    fn is_positive_completion(&self) -> bool;
    fn assert_severity(self, severity: Severity) -> crate::Result<()>;
    fn assert_code(self, code: [u8; 3]) -> crate::Result<()>;
}

impl AssertReply for Response<String> {
    /// Returns `true` if the reply is a positive completion.
    fn is_positive_completion(&self) -> bool {
        self.severity() == Severity::PositiveCompletion
    }

    /// Returns Ok if the reply has the specified severity.
    fn assert_severity(self, severity: Severity) -> crate::Result<()> {
        if self.severity() != severity {
            Err(crate::Error::UnexpectedReply(self))
        } else {
            Ok(())
        }
    }

    /// Returns Ok if the reply has the specified status code.
    fn assert_code(self, code: [u8; 3]) -> crate::Result<()> {
        if self.code() != code {
            Err(crate::Error::UnexpectedReply(self))
        } else {
            Ok(())
        }
    }
}

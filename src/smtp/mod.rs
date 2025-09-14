/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
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

pub trait AssertReply: Sized {
    fn is_positive_completion(&self) -> bool;
    fn assert_positive_completion(self) -> crate::Result<()>;
    fn assert_severity(self, severity: Severity) -> crate::Result<()>;
    fn assert_code(self, code: u16) -> crate::Result<()>;
}

impl AssertReply for Response<String> {
    /// Returns `true` if the reply is a positive completion.
    #[inline(always)]
    fn is_positive_completion(&self) -> bool {
        (200..=299).contains(&self.code)
    }

    /// Returns Ok if the reply has the specified severity.
    #[inline(always)]
    fn assert_severity(self, severity: Severity) -> crate::Result<()> {
        if self.severity() == severity {
            Ok(())
        } else {
            Err(crate::Error::UnexpectedReply(self))
        }
    }

    /// Returns Ok if the reply returned a 2xx code.
    #[inline(always)]
    fn assert_positive_completion(self) -> crate::Result<()> {
        if (200..=299).contains(&self.code) {
            Ok(())
        } else {
            Err(crate::Error::UnexpectedReply(self))
        }
    }

    /// Returns Ok if the reply has the specified status code.
    #[inline(always)]
    fn assert_code(self, code: u16) -> crate::Result<()> {
        if self.code() == code {
            Ok(())
        } else {
            Err(crate::Error::UnexpectedReply(self))
        }
    }
}

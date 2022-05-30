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

use reqwest::header::CONTENT_TYPE;
use serde::Serialize;

use crate::message::IntoMessage;

#[derive(Debug, Default, Serialize)]
#[doc(hidden)]
struct Request<'x> {
    key: Cow<'x, str>,
    raw_message: Cow<'x, str>,
    from_email: Cow<'x, str>,
    to: Vec<Cow<'x, str>>,
}

/// Mailchimp client.
pub struct MailchimpClient<'x> {
    api_key: Cow<'x, str>,
}

impl<'x> From<&'x str> for MailchimpClient<'x> {
    fn from(api_key: &'x str) -> Self {
        Self::new(api_key)
    }
}

impl<'x> From<String> for MailchimpClient<'x> {
    fn from(api_key: String) -> Self {
        Self::new(api_key)
    }
}

impl<'x> MailchimpClient<'x> {
    /// Creates a new Mailchimp client with the specified API key.
    pub fn new(api_key: impl Into<Cow<'x, str>>) -> Self {
        Self {
            api_key: api_key.into(),
        }
    }

    /// Sends a message via Mailchimp.
    pub async fn send(&self, message: impl IntoMessage<'x>) -> crate::Result<()> {
        let message = message.into_message()?;
        let request = Request {
            key: self.api_key.clone(),
            raw_message: String::from_utf8_lossy(message.body.as_ref()),
            from_email: message.mail_from.email,
            to: message
                .rcpt_to
                .into_iter()
                .map(|address| address.email)
                .collect(),
        };

        let status = reqwest::Client::new()
            .post("https://mandrillapp.com/api/1.0/messages/send-raw")
            .header(CONTENT_TYPE, "application/json")
            .body(
                serde_json::to_string(&request)
                    .map_err(|err| crate::Error::Transport(err.to_string()))?,
            )
            .send()
            .await
            .map_err(|err| crate::Error::Transport(err.to_string()))?
            .status();
        if status.is_success() {
            Ok(())
        } else {
            Err(crate::Error::Transport(status.to_string()))
        }
    }
}

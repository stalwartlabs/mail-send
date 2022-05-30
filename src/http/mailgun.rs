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

use reqwest::{header::AUTHORIZATION, multipart};

use crate::message::IntoMessage;

/// Mailgun client.
pub struct MailgunClient {
    url: String,
    api_key: String,
}

impl MailgunClient {
    /// Create a new Mailgun client using the specified API key and domain name.
    pub fn new(api_key: &str, domain: &str) -> Self {
        Self {
            url: format!("https://api.mailgun.net/v3/{}/messages.mime", domain),
            api_key: format!("Basic {}", base64::encode(format!("api:{}", api_key))),
        }
    }

    /// Sends a message via Mailchimp.
    pub async fn send(&self, message: impl IntoMessage<'_>) -> crate::Result<()> {
        let message = message.into_message()?;
        let form = multipart::Form::new()
            .text(
                "to",
                message
                    .rcpt_to
                    .into_iter()
                    .map(|address| address.email)
                    .collect::<Vec<_>>()
                    .join(","),
            )
            .text(
                "message",
                String::from_utf8_lossy(message.body.as_ref()).to_string(),
            );
        let status = reqwest::Client::new()
            .post(&self.url)
            .header(AUTHORIZATION, &self.api_key)
            .multipart(form)
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

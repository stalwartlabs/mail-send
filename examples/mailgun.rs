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

use mail_builder::MessageBuilder;
use mail_send::http::mailgun::MailgunClient;

#[tokio::main]
async fn main() {
    // Build a simple multipart message
    // More examples of how to build messages available at
    // https://github.com/stalwartlabs/mail-builder/tree/main/examples
    let message = MessageBuilder::new()
        .from(("John Doe", "john@example.com"))
        .to(vec![
            ("Jane Doe", "jane@example.com"),
            ("James Smith", "james@test.com"),
        ])
        .subject("Hi!")
        .html_body("<h1>Hello, world!</h1>")
        .text_body("Hello world!");

    // Send the message via Mailchimp
    MailgunClient::new("YOUR_API_KEY", "yourdomain.com")
        .send(message)
        .await
        .unwrap();
}

/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use mail_builder::MessageBuilder;
use mail_send::SmtpClientBuilder;

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

    // Connect to the SMTP submissions port, upgrade to TLS and
    // authenticate using the provided credentials.
    SmtpClientBuilder::new("smtp.gmail.com", 587)
        .implicit_tls(false)
        .credentials(("john", "p4ssw0rd"))
        .connect()
        .await
        .unwrap()
        .send(message)
        .await
        .unwrap();
}

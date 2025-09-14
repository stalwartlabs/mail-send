/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use mail_builder::MessageBuilder;
use mail_send::SmtpClientBuilder;

#[tokio::main]
async fn main() {
    // Build a simple text message with a single attachment
    // More examples of how to build messages available at
    // https://github.com/stalwartlabs/mail-builder/tree/main/examples
    let message = MessageBuilder::new()
        .from(("John Doe", "john@example.com"))
        .to("jane@example.com")
        .subject("Hello, world!")
        .text_body("Hello, world!")
        .attachment("image/png", "kittens.png", [1, 2, 3, 4].as_ref());

    // Connect to an SMTP relay server.
    // The library will upgrade the connection to TLS if the server supports it.
    SmtpClientBuilder::new("mail.smtp2go.com", 2525)
        .implicit_tls(false)
        .connect()
        .await
        .unwrap()
        .send(message)
        .await
        .unwrap();
}

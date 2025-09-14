/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use mail_builder::MessageBuilder;
use mail_send::SmtpClientBuilder;

#[tokio::main]
async fn main() {
    // Build a simple html message with a single attachment
    // More examples of how to build messages available at
    // https://github.com/stalwartlabs/mail-builder/tree/main/examples
    let message = MessageBuilder::new()
        .from(("John Doe", "john@example.com"))
        .to("jane@example.com")
        .subject("Hello, world!")
        .html_body("<h1>Hello, world!</h1>")
        .attachment("image/png", "kittens.png", [1, 2, 3, 4].as_ref());

    // Connect to an SMTP relay server over TLS
    SmtpClientBuilder::new("smtp.gmail.com", 465)
        .connect()
        .await
        .unwrap()
        .send(message)
        .await
        .unwrap();
}

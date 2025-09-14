/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use mail_send::SmtpClientBuilder;
use mail_send::smtp::message::Message;

#[tokio::main]
async fn main() {
    // Build a raw message
    let message = Message::empty()
        .from("jdoe@example.com")
        .to("jane@example.com")
        .to("james@smith.com")
        .body(&b"From: jdoe@example.com\nTo: jane@example.com\nSubject: Hi!\n\nHello, world!"[..]);

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

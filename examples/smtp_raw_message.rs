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

use mail_send::smtp::message::Message;
use mail_send::SmtpClientBuilder;

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

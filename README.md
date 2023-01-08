# mail-send

[![crates.io](https://img.shields.io/crates/v/mail-send)](https://crates.io/crates/mail-send)
[![build](https://github.com/stalwartlabs/mail-send/actions/workflows/rust.yml/badge.svg)](https://github.com/stalwartlabs/mail-send/actions/workflows/rust.yml)
[![docs.rs](https://img.shields.io/docsrs/mail-send)](https://docs.rs/mail-send)
[![crates.io](https://img.shields.io/crates/l/mail-send)](http://www.apache.org/licenses/LICENSE-2.0)

_mail-send_ is a Rust library to build, sign and send e-mail messages via SMTP. It includes the following features:

- Generates **e-mail** messages conforming to the Internet Message Format standard (_RFC 5322_).
- Full **MIME** support (_RFC 2045 - 2049_) with automatic selection of the most optimal encoding for each message body part.
- DomainKeys Identified Mail (**DKIM**) Signatures (_RFC 6376_) with ED25519-SHA256, RSA-SHA256 and RSA-SHA1 support.
- Simple Mail Transfer Protocol (**SMTP**; _RFC 5321_) delivery.
- SMTP Service Extension for Secure SMTP over **TLS** (_RFC 3207_).
- SMTP Service Extension for Authentication (_RFC 4954_) with automatic mechanism negotiation (from most secure to least secure):
  - CRAM-MD5 (_RFC 2195_)
  - DIGEST-MD5 (_RFC 2831_; obsolete but still supported)
  - XOAUTH2 (Google proprietary)
  - LOGIN
  - PLAIN
- Full async (requires Tokio).

## Usage Example

Send a message via an SMTP server that requires authentication:

```rust
    // Build a simple multipart message
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
```

Sign a message with DKIM and send it via an SMTP relay server:

```rust
    // Build a simple text message with a single attachment
    let message = MessageBuilder::new()
        .from(("John Doe", "john@example.com"))
        .to("jane@example.com")
        .subject("Howdy!")
        .text_body("These pretzels are making me thirsty.")
        .binary_attachment("image/png", "pretzels.png", [1, 2, 3, 4].as_ref());

    // Sign an e-mail message using RSA-SHA256
    let pk_rsa = RsaKey::<Sha256>::from_pkcs1_pem(TEST_KEY).unwrap();
    let signer = DkimSigner::from_key(pk_rsa)
        .domain("example.com")
        .selector("default")
        .headers(["From", "To", "Subject"])
        .expiration(60 * 60 * 7); // Number of seconds before this signature expires (optional)

    // Connect to an SMTP relay server over TLS.
    // Signs each message with the configured DKIM signer.
    SmtpClientBuilder::new("smtp.gmail.com", 465)
        .connect()
        .await
        .unwrap()
        .send_signed(message, &signer)
        .await
        .unwrap();
```

More examples of how to build messages are available in the [`mail-builder`](https://crates.io/crates/mail-builder) crate.
Please note that this library does not support parsing e-mail messages as this functionality is provided separately by the [`mail-parser`](https://crates.io/crates/mail-parser) crate.

## Testing

To run the testsuite:

```bash
 $ cargo test --all-features
```

or, to run the testsuite with MIRI:

```bash
 $ cargo +nightly miri test --all-features
```

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Copyright

Copyright (C) 2020-2022, Stalwart Labs Ltd.

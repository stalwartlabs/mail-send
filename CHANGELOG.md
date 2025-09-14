mail-send 0.5.2
================================
- Add an option to choose the sending IP (#41)

mail-send 0.5.1
================================
- Bump `mail-parser` dependency to 0.11
- Bump `mail-auth` dependency to 0.7
- Bump `webpki-roots` dependency to 1.0

mail-send 0.5.0
================================
- Bump `mail-parser` dependency to 0.10
- Bump `mail-builder` dependency to 0.4
- Bump `mail-auth` dependency to 0.6

mail-send 0.4.9
================================
- Bump `rustls` dependency to 0.23
- Bump `tokio-rustls` dependency to 0.26

mail-send 0.4.8
================================
- Bump `mail-auth` dependency to 0.4
- Bump `base64` dependency to 0.22

mail-send 0.4.7
================================
- Added 'parser feature for `Message` conversion.

mail-send 0.4.6
================================
- Improved transparency procedure to also escape <CR>.
- Removed `skip-ehlo` feature.

mail-send 0.4.4
================================
- Updated transparency procedure to escape <LF>. as well as <CR><LF>. to prevent SMTP smuggling on vulnerable servers.

mail-send 0.4.3
================================
- Bump `rustls` dependency to 0.22

mail-send 0.4.2
================================
- Bump `webpki-roots` dependency to 0.26

mail-send 0.4.1
================================
- Bump `webpki-roots` dependency to 0.25

mail-send 0.4.0
================================
- Bump `mail-builder` dependency to 0.3

mail-send 0.3.3
================================
- Bump `rustls` dependency to 0.21

mail-send 0.3.2
================================
- Fix: Extend buffer from bytes read while reading EHLO (#12).
- Add an impl std::error::Error for mail_send::Error (#11)

mail-send 0.3.1
================================
- Fix: plain text connect issues (#10).

mail-send 0.3.0
================================
- Use of generics on TCP streams instead of static dispatch with enums.
- Switch to `mail-auth` for DKIM authentication.

mail-send 0.2.3
================================
- Fix: Send gets stuck when the message has a binary attachment (#7)

mail-send 0.2.2
================================
- Bump up to mail-builder v0.2.2
  
mail-send 0.2.1
================================
- Fixes to support mail-builder v0.2.1

mail-send 0.2.0
================================
- Removed HTTP support.
- API cleanup.

mail-send 0.1.0
================================
- Initial release.

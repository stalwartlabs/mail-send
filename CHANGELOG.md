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
- Switch to ``mail-auth`` for DKIM authentication.

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

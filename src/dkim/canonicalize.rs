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

use std::io::Write;

use super::DKIM;

#[derive(Debug, PartialEq, Eq)]
enum Header {
    Name,
    Value,
}

#[derive(Debug, PartialEq, Eq)]
enum Char {
    Other,
    Space,
    Cr,
    Lf,
}

impl<'x> DKIM<'x> {
    #[allow(clippy::while_let_on_iterator)]
    pub(crate) fn canonicalize_relaxed(
        &self,
        message: &[u8],
        mut header_hasher: impl Write,
        mut body_hasher: impl Write,
    ) -> std::io::Result<Vec<Vec<u8>>> {
        let mut headers: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(self.sign_headers.len());

        let mut buf = Vec::with_capacity(10);
        let mut iter = message.iter().peekable();
        let mut state = Header::Name;
        let mut last = Char::Other;

        // Collect headers
        while let Some(byte) = iter.next() {
            match state {
                Header::Name => match byte {
                    b' ' | b'\t' | b'\r' => (),
                    b'\n' => {
                        break;
                    }
                    b':' => {
                        if self
                            .sign_headers
                            .iter()
                            .any(|header| header.eq_ignore_ascii_case(&buf))
                        {
                            headers.push((buf.clone(), Vec::new()));
                            last = Char::Lf;
                            state = Header::Value;
                        } else {
                            while let Some(byte) = iter.next() {
                                if byte == &b'\n'
                                    && iter.peek().map_or(true, |next_byte| {
                                        ![b' ', b'\t'].contains(next_byte)
                                    })
                                {
                                    break;
                                }
                            }
                        }
                        buf.clear();
                    }
                    _ => buf.push(byte.to_ascii_lowercase()),
                },
                Header::Value => match byte {
                    b'\n' => {
                        if iter
                            .peek()
                            .map_or(true, |next_byte| ![b' ', b'\t'].contains(next_byte))
                        {
                            if last == Char::Cr {
                                buf.push(b'\r');
                            }
                            buf.push(b'\n');
                            headers.last_mut().unwrap().1.extend_from_slice(&buf);
                            buf.clear();
                            state = Header::Name;
                        }
                        last = Char::Lf;
                    }
                    b'\r' => {
                        if last == Char::Cr {
                            buf.push(b'\r');
                        }
                        last = Char::Cr;
                    }
                    b' ' | b'\t' => {
                        if last == Char::Cr {
                            buf.push(b'\r');
                        }
                        last = Char::Space;
                    }
                    _ => {
                        if last == Char::Space && !buf.is_empty() {
                            buf.push(b' ');
                        } else if last == Char::Cr {
                            buf.push(b'\r');
                        }
                        buf.push(*byte);
                        last = Char::Other;
                    }
                },
            }
        }

        // Write canonicalized headers
        let mut signed_headers = Vec::with_capacity(headers.len());
        while let Some((name, value)) = headers.pop() {
            header_hasher.write_all(&name)?;
            header_hasher.write_all(b":")?;
            header_hasher.write_all(&value)?;
            signed_headers.push(name);
        }

        // Write canonicalized body
        let mut body_bytes = 0;
        let mut crlf_seq = Vec::with_capacity(2);
        last = Char::Lf;
        while let Some(byte) = iter.next() {
            match byte {
                b'\n' => {
                    if last == Char::Cr {
                        crlf_seq.push(Char::Cr);
                    }
                    crlf_seq.push(Char::Lf);
                    last = Char::Lf;
                }
                b'\r' => {
                    if last == Char::Cr {
                        body_bytes += body_hasher.write(b"\r")?;
                    }
                    last = Char::Cr;
                }
                b' ' | b'\t' => {
                    if last == Char::Lf {
                        for char in crlf_seq.drain(..) {
                            body_bytes += match char {
                                Char::Cr => body_hasher.write(b"\r")?,
                                Char::Lf => body_hasher.write(b"\n")?,
                                _ => 0,
                            };
                        }
                    } else if last == Char::Cr {
                        body_bytes += body_hasher.write(b"\r")?;
                    }
                    last = Char::Space;
                }
                _ => {
                    if last == Char::Lf {
                        for char in crlf_seq.drain(..) {
                            body_bytes += match char {
                                Char::Cr => body_hasher.write(b"\r")?,
                                Char::Lf => body_hasher.write(b"\n")?,
                                _ => 0,
                            };
                        }
                    } else if last == Char::Space {
                        body_bytes += body_hasher.write(b" ")?;
                    } else if last == Char::Cr {
                        body_bytes += body_hasher.write(b"\r")?;
                    }
                    body_bytes += body_hasher.write(&[*byte])?;
                    last = Char::Other;
                }
            }
        }

        if body_bytes > 0 {
            let mut add_crlf = true;

            for char in crlf_seq.drain(..) {
                match char {
                    Char::Cr => {
                        body_hasher.write_all(b"\r")?;
                    }
                    Char::Lf => {
                        body_hasher.write_all(b"\n")?;
                        add_crlf = false;
                        break;
                    }
                    _ => (),
                }
            }

            if add_crlf {
                body_hasher.write_all(b"\r\n")?;
            }
            body_hasher.flush()?;
        } else {
            body_hasher.write_all(b"\r\n")?;
        }

        // Add any missing headers
        for header in &self.sign_headers {
            if !signed_headers
                .iter()
                .any(|sh| sh.eq_ignore_ascii_case(header.as_ref()))
            {
                signed_headers.push(header.clone().into_owned());
            }
        }

        Ok(signed_headers)
    }
}

#[cfg(test)]
mod test {
    const TEST_KEY: &str = r#"-----BEGIN RSA PRIVATE KEY-----
MIICXwIBAAKBgQDwIRP/UC3SBsEmGqZ9ZJW3/DkMoGeLnQg1fWn7/zYtIxN2SnFC
jxOCKG9v3b4jYfcTNh5ijSsq631uBItLa7od+v/RtdC2UzJ1lWT947qR+Rcac2gb
to/NMqJ0fzfVjH4OuKhitdY9tf6mcwGjaNBcWToIMmPSPDdQPNUYckcQ2QIDAQAB
AoGBALmn+XwWk7akvkUlqb+dOxyLB9i5VBVfje89Teolwc9YJT36BGN/l4e0l6QX
/1//6DWUTB3KI6wFcm7TWJcxbS0tcKZX7FsJvUz1SbQnkS54DJck1EZO/BLa5ckJ
gAYIaqlA9C0ZwM6i58lLlPadX/rtHb7pWzeNcZHjKrjM461ZAkEA+itss2nRlmyO
n1/5yDyCluST4dQfO8kAB3toSEVc7DeFeDhnC1mZdjASZNvdHS4gbLIA1hUGEF9m
3hKsGUMMPwJBAPW5v/U+AWTADFCS22t72NUurgzeAbzb1HWMqO4y4+9Hpjk5wvL/
eVYizyuce3/fGke7aRYw/ADKygMJdW8H/OcCQQDz5OQb4j2QDpPZc0Nc4QlbvMsj
7p7otWRO5xRa6SzXqqV3+F0VpqvDmshEBkoCydaYwc2o6WQ5EBmExeV8124XAkEA
qZzGsIxVP+sEVRWZmW6KNFSdVUpk3qzK0Tz/WjQMe5z0UunY9Ax9/4PVhp/j61bf
eAYXunajbBSOLlx4D+TunwJBANkPI5S9iylsbLs6NkaMHV6k5ioHBBmgCak95JGX
GMot/L2x0IYyMLAz6oLWh2hm7zwtb0CgOrPo1ke44hFYnfc=
-----END RSA PRIVATE KEY-----"#;

    #[test]
    fn dkim_canonicalize() {
        for (message, sign_headers, (expected_headers, expected_body)) in [
            (
                concat!(
                    "A: X\r\n",
                    "B : Y\t\r\n",
                    "\tZ  \r\n",
                    "\r\n",
                    " C \r\n",
                    "D \t E\r\n"
                )
                .to_string(),
                vec!["b", "a"],
                (
                    concat!("b:Y Z\r\n", "a:X\r\n").to_string(),
                    concat!(" C\r\n", "D E\r\n").to_string(),
                ),
            ),
            (
                concat!(
                    "A: X\r\n",
                    "B : Y\t\r\n",
                    "\tZ  \r\n",
                    "\r\n",
                    " C \r\n",
                    "D \t E\r\n"
                )
                .to_string(),
                vec!["a"],
                (
                    concat!("a:X\r\n").to_string(),
                    concat!(" C\r\n", "D E\r\n").to_string(),
                ),
            ),
            (
                concat!(
                    "  From : John\tdoe <jdoe@domain.com>\t\r\n",
                    "SUB JECT:\ttest  \t  \r\n\r\n",
                    " body \t   \r\n",
                    "\r\n",
                    "\r\n",
                )
                .to_string(),
                vec!["subject", "from"],
                (
                    concat!("subject:test\r\n", "from:John doe <jdoe@domain.com>\r\n").to_string(),
                    concat!(" body\r\n").to_string(),
                ),
            ),
            (
                concat!("H: value\t\r\n\r\n",).to_string(),
                vec!["h"],
                (
                    concat!("h:value\r\n").to_string(),
                    concat!("\r\n").to_string(),
                ),
            ),
            (
                concat!("\tx\t: \t\t\tz\r\n\r\nabc",).to_string(),
                vec!["x"],
                (
                    concat!("x:z\r\n").to_string(),
                    concat!("abc\r\n").to_string(),
                ),
            ),
        ] {
            let mut headers = Vec::new();
            let mut body = Vec::new();
            let dkim = super::DKIM::from_pkcs1_pem(TEST_KEY)
                .unwrap()
                .headers(sign_headers.clone().into_iter());

            let signed_headers = dkim
                .canonicalize_relaxed(message.as_bytes(), &mut headers, &mut body)
                .unwrap();
            assert_eq!(expected_headers, String::from_utf8(headers).unwrap());
            assert_eq!(expected_body, String::from_utf8(body).unwrap());
            assert_eq!(
                signed_headers,
                sign_headers
                    .iter()
                    .map(|s| s.as_bytes().to_vec())
                    .collect::<Vec<_>>()
            );
        }
    }
}

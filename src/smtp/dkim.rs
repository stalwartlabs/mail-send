use std::borrow::Cow;

use rsa::RsaPrivateKey;
use sha2::{Digest, Sha256};

pub enum Error {
    ParseError,
}

pub struct DKIM<'x> {
    private_key: RsaPrivateKey,
    domain: Cow<'x, str>,
}

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

#[allow(clippy::while_let_on_iterator)]
pub fn canonicalize_relaxed(
    message: &[u8],
    sign_headers: &[&[u8]],
) -> (Vec<u8>, Vec<u8>, Vec<Vec<u8>>, usize) {
    let mut header = Vec::with_capacity(10);
    let mut headers = Vec::with_capacity(128);
    let mut found_headers = Vec::with_capacity(sign_headers.len());
    let mut body = Vec::with_capacity(message.len());

    let mut iter = message.iter().enumerate().peekable();
    let mut state = Header::Name;
    let mut last = Char::Other;
    let mut sign_pos = 0;

    while let Some((pos, byte)) = iter.next() {
        match state {
            Header::Name => match byte {
                b' ' | b'\t' | b'\r' => (),
                b'\n' => {
                    break;
                }
                b':' => {
                    if sign_headers.is_empty() || sign_headers.contains(&header.as_slice()) {
                        headers.extend_from_slice(&header);
                        headers.push(b':');
                        if !found_headers.contains(&header) {
                            found_headers.push(header);
                            header = Vec::with_capacity(10);
                        } else {
                            header.clear();
                        }
                        while iter
                            .peek()
                            .map_or(false, |(_, next_byte)| [b' ', b'\t'].contains(next_byte))
                        {
                            iter.next();
                        }
                        last = Char::Lf;
                        state = Header::Value;
                    } else {
                        while let Some((pos, byte)) = iter.next() {
                            if byte == &b'\n'
                                && iter.peek().map_or(true, |(_, next_byte)| {
                                    ![b' ', b'\t'].contains(next_byte)
                                })
                            {
                                sign_pos = pos + 1;
                                break;
                            }
                        }
                        header.clear();
                    }
                }
                _ => header.push(byte.to_ascii_lowercase()),
            },
            Header::Value => match byte {
                b'\n' => {
                    if iter
                        .peek()
                        .map_or(true, |(_, next_byte)| ![b' ', b'\t'].contains(next_byte))
                    {
                        if last == Char::Cr {
                            headers.push(b'\r');
                        }
                        headers.push(b'\n');
                        sign_pos = pos + 1;
                        state = Header::Name;
                    }
                    last = Char::Lf;
                }
                b'\r' => {
                    if last == Char::Cr {
                        headers.push(b'\r');
                    }
                    last = Char::Cr;
                }
                b' ' | b'\t' => {
                    if last == Char::Cr {
                        headers.push(b'\r');
                    }
                    last = Char::Space;
                }
                _ => {
                    if last == Char::Space {
                        headers.push(b' ');
                    } else if last == Char::Cr {
                        headers.push(b'\r');
                    }
                    headers.push(*byte);
                    last = Char::Other;
                }
            },
        }
    }

    let mut crlf_seq = Vec::with_capacity(2);
    last = Char::Lf;
    while let Some((_, byte)) = iter.next() {
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
                    body.push(b'\r');
                }
                last = Char::Cr;
            }
            b' ' | b'\t' => {
                if last == Char::Lf {
                    for char in crlf_seq.drain(..) {
                        match char {
                            Char::Cr => body.push(b'\r'),
                            Char::Lf => body.push(b'\n'),
                            _ => (),
                        }
                    }
                } else if last == Char::Cr {
                    body.push(b'\r');
                }
                last = Char::Space;
            }
            _ => {
                if last == Char::Lf {
                    for char in crlf_seq.drain(..) {
                        match char {
                            Char::Cr => body.push(b'\r'),
                            Char::Lf => body.push(b'\n'),
                            _ => (),
                        }
                    }
                } else if last == Char::Space {
                    body.push(b' ');
                } else if last == Char::Cr {
                    body.push(b'\r');
                }
                body.push(*byte);
                last = Char::Other;
            }
        }
    }

    if !body.is_empty() {
        for char in crlf_seq.drain(..) {
            match char {
                Char::Cr => body.push(b'\r'),
                Char::Lf => {
                    body.push(b'\n');
                    break;
                }
                _ => (),
            }
        }
    } else {
        body.extend_from_slice(b"\r\n");
    }

    (headers, body, found_headers, sign_pos)
}

impl<'x> DKIM<'x> {
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        /*let mut hasher = Sha256::new();
        hasher.update(&message);
        let hash = hasher.finalize().to_vec();

        let signature = self.private_key.sign(&hash, &rsa::Padding::PKCS1);*/

        vec![]
    }
}

#[cfg(test)]
mod test {

    #[test]
    fn canonicalize_relaxed() {
        for (message, sign_headers, (expected_header, expected_body, expected_sign_pos)) in [
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
                vec!["a", "b"],
                (
                    concat!("a:X\r\n", "b:Y Z\r\n").to_string(),
                    concat!(" C\r\n", "D E\r\n").to_string(),
                    20,
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
                    20,
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
                vec!["from", "subject"],
                (
                    concat!("from:John doe <jdoe@domain.com>\r\n", "subject:test\r\n").to_string(),
                    concat!(" body\r\n").to_string(),
                    59,
                ),
            ),
            (
                concat!("H: value\t\r\n\r\n",).to_string(),
                vec!["h"],
                (
                    concat!("h:value\r\n").to_string(),
                    concat!("\r\n").to_string(),
                    11,
                ),
            ),
            (
                concat!("\tx\t: \t\t\tz\r\n\r\nabc",).to_string(),
                vec!["x"],
                (
                    concat!("x:z\r\n").to_string(),
                    concat!("abc").to_string(),
                    11,
                ),
            ),
        ] {
            let (header, body, found_headers, sign_pos) = super::canonicalize_relaxed(
                message.as_bytes(),
                &sign_headers
                    .iter()
                    .map(|s| s.as_bytes())
                    .collect::<Vec<_>>(),
            );
            assert_eq!(expected_header, String::from_utf8(header).unwrap());
            assert_eq!(expected_body, String::from_utf8(body).unwrap());
            assert_eq!(expected_sign_pos, sign_pos);
            assert_eq!(
                found_headers,
                sign_headers
                    .iter()
                    .map(|s| s.as_bytes().to_vec())
                    .collect::<Vec<_>>(),
            );
        }
    }
}

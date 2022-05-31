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

use std::{
    fmt::{Display, Formatter},
    io::Write,
};

use super::Signature;

impl<'x> Signature<'x> {
    pub(crate) fn write(&self, mut writer: impl Write, as_header: bool) -> std::io::Result<()> {
        if as_header {
            writer.write_all(b"DKIM-Signature: ")?;
        };
        writer.write_all(b"v=1; a=rsa-sha256; s=")?;
        writer.write_all(self.s.as_bytes())?;
        writer.write_all(b"; d=")?;
        writer.write_all(self.d.as_bytes())?;
        writer.write_all(b"; c=relaxed/relaxed; h=")?;
        for (num, h) in self.h.iter().enumerate() {
            if num > 0 {
                writer.write_all(b":")?;
            }
            writer.write_all(h)?;
        }
        writer.write_all(b"; t=")?;
        writer.write_all(self.t.to_string().as_bytes())?;
        if self.x > 0 {
            writer.write_all(b"; x=")?;
            writer.write_all(self.x.to_string().as_bytes())?;
        }
        writer.write_all(b"; bh=")?;
        writer.write_all(self.bh.as_bytes())?;
        writer.write_all(b"; b=")?;
        writer.write_all(self.b.as_bytes())?;
        writer.write_all(b";")?;
        if as_header {
            writer.write_all(b"\r\n")?;
        }
        Ok(())
    }

    pub fn write_header(&self, writer: impl Write) -> std::io::Result<()> {
        self.write(writer, true)
    }

    pub fn to_header(&self) -> String {
        let mut buf = Vec::new();
        self.write(&mut buf, true).unwrap();
        String::from_utf8(buf).unwrap()
    }
}

impl<'x> Display for Signature<'x> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut buf = Vec::new();
        self.write(&mut buf, false).map_err(|_| std::fmt::Error)?;
        f.write_str(&String::from_utf8(buf).map_err(|_| std::fmt::Error)?)
    }
}

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
    borrow::Cow,
    collections::{HashMap, HashSet},
    fmt::Display,
};

use mail_builder::{
    headers::{address, HeaderType},
    MessageBuilder,
};

#[derive(Debug, Default)]
pub struct Message<'x> {
    pub mail_from: Address<'x>,
    pub rcpt_to: Vec<Address<'x>>,
    pub body: Cow<'x, [u8]>,
}

#[derive(Debug, Default)]
pub struct Address<'x> {
    pub email: Cow<'x, str>,
    pub parameters: Parameters<'x>,
}

#[derive(Debug, Default)]
pub struct Parameters<'x> {
    pub params: HashMap<Cow<'x, str>, Option<Cow<'x, str>>>,
}

impl<'x> Message<'x> {
    /// Create a new message
    pub fn new<T, U, V>(from: T, to: U, body: V) -> Self
    where
        T: Into<Address<'x>>,
        U: IntoIterator<Item = T>,
        V: Into<Cow<'x, [u8]>>,
    {
        Message {
            mail_from: from.into(),
            rcpt_to: to.into_iter().map(Into::into).collect(),
            body: body.into(),
        }
    }

    /// Create a new empty message.
    pub fn empty() -> Self {
        Message {
            mail_from: Address::default(),
            rcpt_to: Vec::new(),
            body: Default::default(),
        }
    }

    /// Set the sender of the message.
    pub fn from(mut self, address: impl Into<Address<'x>>) -> Self {
        self.mail_from = address.into();
        self
    }

    /// Add a message recipient.
    pub fn to(mut self, address: impl Into<Address<'x>>) -> Self {
        self.rcpt_to.push(address.into());
        self
    }

    /// Set the message body.
    pub fn body(mut self, body: impl Into<Cow<'x, [u8]>>) -> Self {
        self.body = body.into();
        self
    }
}

impl<'x> From<&'x str> for Address<'x> {
    fn from(email: &'x str) -> Self {
        Address {
            email: email.into(),
            parameters: Parameters::default(),
        }
    }
}

impl<'x> From<String> for Address<'x> {
    fn from(email: String) -> Self {
        Address {
            email: email.into(),
            parameters: Parameters::default(),
        }
    }
}

impl<'x> Address<'x> {
    pub fn new(email: impl Into<Cow<'x, str>>, parameters: Parameters<'x>) -> Self {
        Address {
            email: email.into(),
            parameters,
        }
    }
}

impl<'x> Parameters<'x> {
    pub fn new() -> Self {
        Self {
            params: HashMap::new(),
        }
    }

    pub fn param(&mut self, key: impl Into<Cow<'x, str>>, value: impl Into<Cow<'x, str>>) {
        self.params.insert(key.into(), Some(value.into()));
    }

    pub fn keyword(&mut self, key: impl Into<Cow<'x, str>>) {
        self.params.insert(key.into(), None);
    }
}

impl<'x> Display for Parameters<'x> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if !self.params.is_empty() {
            for (key, value) in &self.params {
                f.write_str(" ")?;
                f.write_str(key)?;
                if let Some(value) = value {
                    f.write_str("=")?;
                    f.write_str(value)?;
                }
            }
        }
        Ok(())
    }
}

pub trait IntoMessage<'x> {
    fn into_message(self) -> crate::Result<Message<'x>>;
}

impl<'x> IntoMessage<'x> for Message<'x> {
    fn into_message(self) -> crate::Result<Message<'x>> {
        Ok(self)
    }
}

impl<'x, 'y> IntoMessage<'x> for MessageBuilder<'y> {
    fn into_message(self) -> crate::Result<Message<'x>> {
        let mut mail_from = None;
        let mut rcpt_to = HashSet::new();

        for (key, value) in self.headers.iter() {
            if key.eq_ignore_ascii_case("from") {
                if let Some(HeaderType::Address(address::Address::Address(addr))) = value.last() {
                    let email = addr.email.trim();
                    if !email.is_empty() {
                        mail_from = email.to_string().into();
                    }
                }
            } else if key.eq_ignore_ascii_case("to")
                || key.eq_ignore_ascii_case("cc")
                || key.eq_ignore_ascii_case("bcc")
            {
                for addr in value {
                    if let HeaderType::Address(addr) = addr {
                        match addr {
                            address::Address::Address(addr) => {
                                let email = addr.email.trim();
                                if !email.is_empty() {
                                    rcpt_to.insert(email.to_string());
                                }
                            }
                            address::Address::Group(group) => {
                                for addr in &group.addresses {
                                    if let address::Address::Address(addr) = addr {
                                        let email = addr.email.trim();
                                        if !email.is_empty() {
                                            rcpt_to.insert(email.to_string());
                                        }
                                    }
                                }
                            }
                            address::Address::List(list) => {
                                for addr in list {
                                    if let address::Address::Address(addr) = addr {
                                        let email = addr.email.trim();
                                        if !email.is_empty() {
                                            rcpt_to.insert(email.to_string());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        if rcpt_to.is_empty() {
            return Err(crate::Error::MissingRcptTo);
        }

        Ok(Message {
            mail_from: mail_from.ok_or(crate::Error::MissingMailFrom)?.into(),
            rcpt_to: rcpt_to
                .into_iter()
                .map(|email| Address {
                    email: email.into(),
                    parameters: Parameters::default(),
                })
                .collect(),
            body: self.write_to_vec()?.into(),
        })
    }
}

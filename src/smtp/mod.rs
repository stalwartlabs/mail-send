use std::{borrow::Cow, collections::HashMap, fmt::Display};

pub mod auth;
pub mod capability;
pub mod client;
pub mod dkim;
pub mod reply;
pub mod stream;
pub mod tls;

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Auth(auth::Error),
    Base64(base64::DecodeError),
    DKIM(dkim::Error),
    Reply(reply::Error),
    UnexpectedReply(reply::Reply),
    InvalidTLSName,
    MissingCredentials,
    Timeout,
}

pub type Result<T> = std::result::Result<T, Error>;

impl From<auth::Error> for Error {
    fn from(err: auth::Error) -> Self {
        Error::Auth(err)
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::Io(err)
    }
}

impl From<base64::DecodeError> for Error {
    fn from(err: base64::DecodeError) -> Self {
        Error::Base64(err)
    }
}

impl From<dkim::Error> for Error {
    fn from(err: dkim::Error) -> Self {
        Error::DKIM(err)
    }
}

impl From<reply::Error> for Error {
    fn from(err: reply::Error) -> Self {
        Error::Reply(err)
    }
}

#[derive(Debug, Default)]
pub struct Params<'x> {
    params: HashMap<Cow<'x, str>, Option<Cow<'x, str>>>,
}

impl<'x> Params<'x> {
    pub fn new() -> Self {
        Self {
            params: HashMap::new(),
        }
    }

    pub fn add_param(&mut self, key: impl Into<Cow<'x, str>>, value: impl Into<Cow<'x, str>>) {
        self.params.insert(key.into(), Some(value.into()));
    }

    pub fn add_simple_param(&mut self, key: impl Into<Cow<'x, str>>) {
        self.params.insert(key.into(), None);
    }
}

impl<'x> Display for Params<'x> {
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

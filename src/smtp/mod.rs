pub mod auth;
pub mod capability;
pub mod client;
pub mod dkim;
pub mod reply;

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Auth(auth::Error),
    Base64(base64::DecodeError),
}

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

pub type Result<T> = std::result::Result<T, Error>;

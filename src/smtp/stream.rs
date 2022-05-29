use tokio::{io::AsyncWriteExt, net::TcpStream};

#[allow(clippy::large_enum_variant)]
pub enum SmtpStream {
    Basic(TcpStream),
    Tls(tokio_rustls::client::TlsStream<TcpStream>),
    #[cfg(test)]
    Debug(Vec<u8>),
    None,
}

impl SmtpStream {
    pub async fn write_all(&mut self, bytes: &[u8]) -> tokio::io::Result<()> {
        match self {
            SmtpStream::Basic(stream) => stream.write_all(bytes).await,
            SmtpStream::Tls(stream) => stream.write_all(bytes).await,
            #[cfg(test)]
            SmtpStream::Debug(stream) => {
                stream.extend_from_slice(bytes);
                Ok(())
            }
            _ => unreachable!(),
        }
    }

    pub async fn write(&mut self, bytes: &[u8]) -> tokio::io::Result<usize> {
        match self {
            SmtpStream::Basic(stream) => stream.write(bytes).await,
            SmtpStream::Tls(stream) => stream.write(bytes).await,
            #[cfg(test)]
            SmtpStream::Debug(stream) => {
                stream.extend_from_slice(bytes);
                Ok(bytes.len())
            }
            _ => unreachable!(),
        }
    }

    pub async fn flush(&mut self) -> tokio::io::Result<()> {
        match self {
            SmtpStream::Basic(stream) => stream.flush().await,
            SmtpStream::Tls(stream) => stream.flush().await,
            _ => Ok(()),
        }
    }

    pub async fn write_message(&mut self, message: &[u8]) -> tokio::io::Result<()> {
        // Transparency procedure
        #[derive(Debug)]
        enum State {
            Cr,
            CrLf,
            Init,
        }

        let mut state = State::Init;
        let mut last_pos = 0;
        for (pos, byte) in message.iter().enumerate() {
            if *byte == b'.' && matches!(state, State::CrLf) {
                if let Some(bytes) = message.get(last_pos..pos) {
                    self.write(bytes).await?;
                    self.write(b".").await?;
                    last_pos = pos;
                }
                state = State::Init;
            } else if *byte == b'\r' {
                state = State::Cr;
            } else if *byte == b'\n' && matches!(state, State::Cr) {
                state = State::CrLf;
            } else {
                state = State::Init;
            }
        }
        if let Some(bytes) = message.get(last_pos..) {
            self.write(bytes).await?;
        }
        self.write_all("\r\n.\r\n".as_bytes()).await
    }
}

impl Default for SmtpStream {
    fn default() -> Self {
        SmtpStream::None
    }
}

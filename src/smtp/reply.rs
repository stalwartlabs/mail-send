const MAX_MESSAGE_LENGTH: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Severity {
    PositiveCompletion = 2,
    PositiveIntermediate = 3,
    TransientNegativeCompletion = 4,
    PermanentNegativeCompletion = 5,
    Invalid = 0,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Category {
    Syntax = 0,
    Information = 1,
    Connections = 2,
    Unspecified3 = 3,
    Unspecified4 = 4,
    MailSystem = 5,
    Invalid = 6,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    code: u16,
    message: Vec<String>,
}

impl Reply {
    pub fn code(&self) -> u16 {
        self.code
    }

    pub fn message(&self) -> &[String] {
        &self.message
    }

    pub fn severity(&self) -> Severity {
        match self.code / 100 {
            2 => Severity::PositiveCompletion,
            3 => Severity::PositiveIntermediate,
            4 => Severity::TransientNegativeCompletion,
            5 => Severity::PermanentNegativeCompletion,
            _ => Severity::Invalid,
        }
    }

    pub fn category(&self) -> Category {
        match self.code / 10 % 10 {
            0 => Category::Syntax,
            1 => Category::Information,
            2 => Category::Connections,
            3 => Category::Unspecified3,
            4 => Category::Unspecified4,
            5 => Category::MailSystem,
            _ => Category::Invalid,
        }
    }

    pub fn details(&self) -> u16 {
        self.code % 10
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplyParseError {
    InvalidReplyCode,
    InvalidSeparator,
    IncompleteReply,
    CodeMismatch,
    MessageTooLong,
    NeedsMoreData,
}

enum ReplyParserState {
    FirstDigit,
    SecondDigit,
    ThirdDigit,
    Separator,
    Description,
}

pub struct ReplyParser {
    code: u16,
    current_code: u16,
    state: ReplyParserState,
    is_last: bool,
    buf: Vec<u8>,
    message: Vec<String>,
    message_len: usize,
}

impl Default for ReplyParser {
    fn default() -> Self {
        Self {
            code: u16::MAX,
            current_code: 0,
            state: ReplyParserState::FirstDigit,
            buf: Vec::with_capacity(128),
            is_last: false,
            message: Vec::with_capacity(4),
            message_len: 0,
        }
    }
}

impl ReplyParser {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn reset(&mut self) {
        self.state = ReplyParserState::FirstDigit;
        self.code = u16::MAX;
        self.current_code = 0;
        self.message_len = 0;
        self.is_last = false;
    }

    pub fn parse(&mut self, bytes: &[u8]) -> Result<Reply, ReplyParseError> {
        for byte in bytes {
            match self.state {
                ReplyParserState::FirstDigit => {
                    if (b'0'..=b'9').contains(byte) {
                        self.current_code = ((byte - b'0') as u16) * 100;
                        self.state = ReplyParserState::SecondDigit;
                    } else {
                        self.reset();
                        return Err(ReplyParseError::InvalidReplyCode);
                    }
                }
                ReplyParserState::SecondDigit => {
                    if (b'0'..=b'9').contains(byte) {
                        self.current_code += ((byte - b'0') as u16) * 10;
                        self.state = ReplyParserState::ThirdDigit;
                    } else {
                        self.reset();
                        return Err(ReplyParseError::InvalidReplyCode);
                    }
                }
                ReplyParserState::ThirdDigit => {
                    if (b'0'..=b'9').contains(byte) {
                        self.current_code += (byte - b'0') as u16;
                        self.state = ReplyParserState::Separator;
                    } else {
                        self.reset();
                        return Err(ReplyParseError::InvalidReplyCode);
                    }
                }
                ReplyParserState::Separator => {
                    match byte {
                        b' ' => {
                            self.is_last = true;
                        }
                        b'-' => (),
                        _ => {
                            self.reset();
                            return Err(ReplyParseError::InvalidSeparator);
                        }
                    }

                    if self.code == u16::MAX {
                        self.code = self.current_code;
                    } else if self.code != self.current_code {
                        self.reset();
                        return Err(ReplyParseError::CodeMismatch);
                    }
                    self.current_code = 0;
                    self.state = ReplyParserState::Description;
                }
                ReplyParserState::Description => match byte {
                    b'\n' => {
                        if !self.buf.is_empty() {
                            self.message
                                .push(String::from_utf8_lossy(&self.buf).into_owned());
                            self.buf.clear();
                        }

                        self.state = ReplyParserState::FirstDigit;
                        self.current_code = 0;

                        if self.is_last {
                            let code = self.code;

                            self.code = u16::MAX;
                            self.is_last = false;
                            self.message_len = 0;

                            return Ok(Reply {
                                code,
                                message: std::mem::take(&mut self.message),
                            });
                        }
                    }
                    b'\r' => (),
                    _ => {
                        if self.message_len < MAX_MESSAGE_LENGTH {
                            self.buf.push(*byte);
                            self.message_len += 1;
                        } else {
                            self.reset();
                            return Err(ReplyParseError::MessageTooLong);
                        }
                    }
                },
            }
        }

        Err(ReplyParseError::NeedsMoreData)
    }
}

#[cfg(test)]
mod test {
    use crate::smtp::reply::{Category, ReplyParseError, Severity, MAX_MESSAGE_LENGTH};

    use super::ReplyParser;

    #[test]
    fn reply_parser() {
        // Create parser
        let mut parser = ReplyParser::new();

        // Parse valid multi-line response
        let result = parser.parse(b"250-First line\r\n250-Second line\r\n250-234 Text beginning with numbers\r\n250 The last line\r\n").unwrap();
        assert_eq!(result.code(), 250);
        assert_eq!(result.severity(), Severity::PositiveCompletion);
        assert_eq!(result.category(), Category::MailSystem);
        assert_eq!(result.details(), 0);
        assert_eq!(
            result.message(),
            &[
                "First line",
                "Second line",
                "234 Text beginning with numbers",
                "The last line"
            ]
        );

        // Parse valid single-line response
        let result = parser
            .parse(b"421 These pretzels are making me thirsty\r\n")
            .unwrap();
        assert_eq!(result.code(), 421);
        assert_eq!(result.severity(), Severity::TransientNegativeCompletion);
        assert_eq!(result.category(), Category::Connections);
        assert_eq!(result.details(), 1);
        assert_eq!(result.message(), &["These pretzels are making me thirsty",]);

        // Parse chunked response
        assert_eq!(
            parser.parse(b"555-These pretzels\r\n"),
            Err(ReplyParseError::NeedsMoreData)
        );
        let result = parser.parse(b"555 are making me thirsty\r\n").unwrap();
        assert_eq!(result.code(), 555);
        assert_eq!(result.severity(), Severity::PermanentNegativeCompletion);
        assert_eq!(result.category(), Category::MailSystem);
        assert_eq!(result.details(), 5);
        assert_eq!(
            result.message(),
            &["These pretzels", "are making me thirsty"]
        );

        // Parse invalid response (code mismatch)
        assert_eq!(
            parser.parse(b"421-These pretzels\r\n250 are making me thirsty\r\n"),
            Err(ReplyParseError::CodeMismatch)
        );

        // Parse invalid response (alphabetical characters in code)
        assert_eq!(
            parser.parse(b"1zz-These pretzels are making me thirsty\r\n"),
            Err(ReplyParseError::InvalidReplyCode)
        );

        // Parse invalid response (alphabetical characters in separator)
        assert_eq!(
            parser.parse(b"123These pretzels are making me thirsty\r\n"),
            Err(ReplyParseError::InvalidSeparator)
        );

        // Parse invalid response (message too long)
        let mut long_response = Vec::new();
        (0..MAX_MESSAGE_LENGTH + 1).for_each(|_| long_response.extend_from_slice(b"123-a\r\n"));
        long_response.extend_from_slice(b"123 a\r\n");
        assert_eq!(
            parser.parse(&long_response),
            Err(ReplyParseError::MessageTooLong)
        );
    }
}

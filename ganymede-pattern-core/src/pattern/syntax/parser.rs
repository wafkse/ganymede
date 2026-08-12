//! Streaming tokenizer for the public fixed-width pattern grammar.
//!
//! The parser advances through an enumerated byte iterator and never indexes its source. Truncated
//! tokens therefore become ordinary iterator exhaustion cases. Once the parser reports a syntax
//! error it transitions to a terminal state and yields no later token.

extern crate alloc;

use alloc::vec::Vec;
use core::{iter::Peekable, num::NonZeroUsize};

use super::{MaskedByte, ParseError, ParseErrorKind, Source, Token};

/// One decoded nibble before its position inside a byte is known.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Nibble {
    /// A concrete hexadecimal value from zero through fifteen.
    Exact(u8),

    /// An unconstrained nibble written with `?`.
    Wildcard,
}

impl Nibble {
    /// Decode one ASCII hexadecimal digit or wildcard marker.
    #[inline]
    const fn decode(target_byte: u8) -> Option<Self> {
        match target_byte {
            b'?' => Some(Self::Wildcard),
            b'0'..=b'9' => Some(Self::Exact(target_byte - b'0')),
            b'a'..=b'f' => Some(Self::Exact(target_byte - b'a' + 10)),
            b'A'..=b'F' => Some(Self::Exact(target_byte - b'A' + 10)),
            _ => None,
        }
    }

    /// Place this nibble into its byte position and produce matching value and mask bits.
    #[inline]
    const fn shifted(self, target_shift: u32) -> (u8, u8) {
        match self {
            Self::Exact(target_value) => (target_value << target_shift, 0x0f << target_shift),
            Self::Wildcard => (0, 0),
        }
    }
}

/// Progress state needed to distinguish an empty source from ordinary end of input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// No semantic token has been emitted yet.
    Fresh,

    /// At least one semantic token has been emitted.
    Active,

    /// End of input or a syntax failure has made the iterator terminal.
    Finished,
}

/// Streaming tokenizer for the textual fixed-width pattern language.
///
/// Tokens are separated by ASCII whitespace. Hexadecimal pairs such as `48` represent exact bytes.
/// `?` and `??` represent whole-byte wildcards. Forms such as `4?` and `?f` constrain one nibble.
/// `[N]` represents a nonzero decimal run of wildcard bytes. Quoted literals represent exact bytes
/// and support `\\`, `\"`, `\n`, `\r`, `\t`, and `\xNN` escapes.
///
/// The parser borrows the source and allocates only when decoding a quoted literal. Source offsets in
/// [`ParseError`] are byte offsets. After the first error the iterator is terminal, which lets callers
/// stop on failure without needing a separate recovery protocol.
#[derive(Debug)]
// NOTE(invariant): `source` advances monotonically and `state` becomes `Finished` after EOF or any syntax error, so no source byte is revisited and no token is emitted after termination.
pub struct Parser<'source> {
    /// Enumerated source bytes retained at the current lexical position.
    source: Peekable<Source<'source>>,

    /// Progress and terminal state for the token stream.
    state: State,
}

impl<'source> Parser<'source> {
    /// Start tokenization at the first byte of a borrowed source string.
    ///
    /// Construction performs no validation and no allocation. Syntax is checked lazily as the
    /// iterator advances. Call [`super::parse`] when complete validation and canonical materialization
    /// are required before any token is observed.
    #[inline]
    #[must_use]
    pub fn new(target_source: &'source str) -> Self {
        let source = target_source.as_bytes().iter().enumerate().peekable();
        let state = State::Fresh;

        Self { source, state }
    }

    /// Produce one token or terminal condition while preserving parser state invariants.
    fn token(&mut self) -> Result<Option<Token>, ParseError> {
        let Self { source, state } = self;

        if *state == State::Finished {
            return Ok(None);
        }

        Self::space(source);

        let Some((offset, leading)) = source.next().map(|(offset, byte)| (offset, *byte)) else {
            let is_empty = *state == State::Fresh;

            *state = State::Finished;

            return if is_empty {
                Err(ParseError::new(0, ParseErrorKind::Empty))
            } else {
                Ok(None)
            };
        };

        let token = match leading {
            b'"' => Self::quoted(source, offset),
            b'[' => Self::skip(source, offset),
            b'?' => Self::masked(source, offset, leading),
            _ if Nibble::decode(leading).is_some() => Self::masked(source, offset, leading),
            _ => Err(ParseError::new(offset, ParseErrorKind::Unexpected(leading))),
        }
        .and_then(|target_token| {
            Self::boundary(source)?;

            Ok(target_token)
        });

        match token {
            Ok(target_token) => {
                *state = State::Active;

                Ok(Some(target_token))
            }
            Err(target_error) => {
                *state = State::Finished;

                Err(target_error)
            }
        }
    }

    /// Consume inter-token ASCII whitespace without consuming the first byte of the next token.
    #[inline]
    fn space(target_source: &mut Peekable<Source<'_>>) {
        while target_source
            .next_if(|(_, target_byte)| target_byte.is_ascii_whitespace())
            .is_some()
        {}
    }

    /// Decode one exact byte, whole-byte wildcard, or nibble wildcard.
    fn masked(
        target_source: &mut Peekable<Source<'_>>,
        target_offset: usize,
        target_first: u8,
    ) -> Result<Token, ParseError> {
        let is_lone_wildcard = target_first == b'?'
            && target_source
                .peek()
                .is_none_or(|(_, target_byte)| target_byte.is_ascii_whitespace());

        if is_lone_wildcard {
            return Ok(Token::Byte(MaskedByte::new(0, 0)));
        }

        let Some((_, target_second)) = target_source.next().map(|(offset, byte)| (offset, *byte))
        else {
            return Err(ParseError::new(
                target_offset,
                ParseErrorKind::IncompleteByte,
            ));
        };
        let Some(target_high) = Nibble::decode(target_first) else {
            return Err(ParseError::new(target_offset, ParseErrorKind::InvalidHex));
        };
        let Some(target_low) = Nibble::decode(target_second) else {
            return Err(ParseError::new(target_offset, ParseErrorKind::InvalidHex));
        };
        let (high_value, high_mask) = target_high.shifted(4);
        let (low_value, low_mask) = target_low.shifted(0);
        let value = high_value | low_value;
        let mask = high_mask | low_mask;

        Ok(Token::Byte(MaskedByte::new(value, mask)))
    }

    /// Decode one quoted literal and apply byte-oriented escapes while the source is consumed.
    fn quoted(
        target_source: &mut Peekable<Source<'_>>,
        target_start: usize,
    ) -> Result<Token, ParseError> {
        let mut bytes = Vec::new();

        loop {
            let Some((offset, target_byte)) =
                target_source.next().map(|(offset, byte)| (offset, *byte))
            else {
                return Err(ParseError::new(
                    target_start,
                    ParseErrorKind::UnterminatedString,
                ));
            };

            match target_byte {
                b'"' => return Ok(Token::Bytes(bytes)),
                b'\\' => bytes.push(Self::escape(target_source, offset)?),
                _ => bytes.push(target_byte),
            }
        }
    }

    /// Decode one supported quoted-literal escape after its leading backslash.
    fn escape(
        target_source: &mut Peekable<Source<'_>>,
        target_offset: usize,
    ) -> Result<u8, ParseError> {
        let Some((_, target_escape)) = target_source.next().map(|(offset, byte)| (offset, *byte))
        else {
            return Err(ParseError::new(
                target_offset,
                ParseErrorKind::InvalidEscape,
            ));
        };

        match target_escape {
            b'\\' | b'"' => Ok(target_escape),
            b'n' => Ok(b'\n'),
            b'r' => Ok(b'\r'),
            b't' => Ok(b'\t'),
            b'x' => Self::hex(target_source, target_offset),
            _ => Err(ParseError::new(
                target_offset,
                ParseErrorKind::InvalidEscape,
            )),
        }
    }

    /// Decode the two hexadecimal digits following a quoted `\x` escape.
    fn hex(
        target_source: &mut Peekable<Source<'_>>,
        target_offset: usize,
    ) -> Result<u8, ParseError> {
        let target_high = target_source
            .next()
            .and_then(|(_, target_byte)| Nibble::decode(*target_byte));
        let target_low = target_source
            .next()
            .and_then(|(_, target_byte)| Nibble::decode(*target_byte));

        match (target_high, target_low) {
            (Some(Nibble::Exact(high)), Some(Nibble::Exact(low))) => Ok((high << 4) | low),
            _ => Err(ParseError::new(
                target_offset,
                ParseErrorKind::InvalidEscape,
            )),
        }
    }

    /// Decode a bracketed decimal wildcard width and prove it is nonzero.
    fn skip(
        target_source: &mut Peekable<Source<'_>>,
        target_start: usize,
    ) -> Result<Token, ParseError> {
        let mut count = 0usize;
        let mut has_digit = false;

        loop {
            let Some((_, target_byte)) =
                target_source.peek().map(|(offset, byte)| (*offset, **byte))
            else {
                return Err(ParseError::new(target_start, ParseErrorKind::InvalidSkip));
            };

            if target_byte == b']' {
                target_source.next();
                break;
            }

            if !target_byte.is_ascii_digit() {
                return Err(ParseError::new(target_start, ParseErrorKind::InvalidSkip));
            }

            has_digit = true;
            target_source.next();
            let digit = usize::from(target_byte - b'0');
            count = count
                .checked_mul(10)
                .and_then(|target_count| target_count.checked_add(digit))
                .ok_or_else(|| ParseError::new(target_start, ParseErrorKind::InvalidSkip))?;
        }

        if !has_digit {
            return Err(ParseError::new(target_start, ParseErrorKind::InvalidSkip));
        }

        let count = NonZeroUsize::new(count)
            .ok_or_else(|| ParseError::new(target_start, ParseErrorKind::InvalidSkip))?;

        Ok(Token::Skip(count))
    }

    /// Prove that a completed token is followed by whitespace or end of input.
    #[inline]
    fn boundary(target_source: &mut Peekable<Source<'_>>) -> Result<(), ParseError> {
        let Some((offset, target_byte)) =
            target_source.peek().map(|(offset, byte)| (*offset, **byte))
        else {
            return Ok(());
        };

        if target_byte.is_ascii_whitespace() {
            Ok(())
        } else {
            Err(ParseError::new(offset, ParseErrorKind::Boundary))
        }
    }
}

impl Iterator for Parser<'_> {
    type Item = Result<Token, ParseError>;

    /// Advance by one semantic token.
    ///
    /// A syntax error is yielded once as `Some(Err(..))`. Every later call returns `None` because
    /// parser recovery is intentionally outside this fixed-width grammar.
    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        match self.token() {
            Ok(Some(target_token)) => Some(Ok(target_token)),
            Ok(None) => None,
            Err(target_error) => Some(Err(target_error)),
        }
    }
}

impl core::iter::FusedIterator for Parser<'_> {}

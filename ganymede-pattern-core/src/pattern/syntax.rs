//! Semantic representation of the textual pattern grammar.
//!
//! This module separates syntax from search planning. Parsing produces owned byte values and masks
//! that contain no references to the source string. Scanner planning can therefore treat parsed
//! input exactly like programmatically constructed patterns.
//!
//! [`Parser`] is the streaming interface. [`parse`] is the complete validation and materialization
//! operation for callers that need canonical byte and mask arrays.

extern crate alloc;

use alloc::vec::Vec;
use core::{iter::Enumerate, num::NonZeroUsize, slice::Iter};

mod parser;

pub use parser::Parser;

/// One byte position with an explicit constrained-bit mask.
///
/// Matching uses `((candidate ^ value) & mask) == 0`. A mask of `0xff` therefore represents an exact
/// byte while a zero mask represents a whole-byte wildcard. Partial masks preserve nibble wildcard
/// syntax without introducing a separate runtime representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// NOTE(invariant): Bits outside `mask` are always cleared in `value`, so equivalent masked bytes have one canonical representation.
pub struct MaskedByte {
    /// Canonical byte value with unconstrained bits cleared.
    value: u8,

    /// Bits that must equal the corresponding value bits during matching.
    mask: u8,
}

impl MaskedByte {
    /// Canonicalize one value and mask pair.
    ///
    /// Unconstrained bits in `target_value` are discarded. This makes equality useful for comparing
    /// semantic byte constraints rather than the incidental spelling used to construct them.
    #[inline]
    #[must_use]
    pub const fn new(target_value: u8, target_mask: u8) -> Self {
        let value = target_value & target_mask;
        let mask = target_mask;

        Self { value, mask }
    }

    /// Return the canonical constrained value bits.
    #[inline]
    #[must_use]
    pub const fn value(&self) -> u8 {
        let Self { value, .. } = self;

        *value
    }

    /// Return the mask selecting bits that participate in matching.
    #[inline]
    #[must_use]
    pub const fn mask(&self) -> u8 {
        let Self { mask, .. } = self;

        *mask
    }

    /// Report whether this position requires one exact byte value.
    #[inline]
    #[must_use]
    pub const fn is_exact(&self) -> bool {
        let Self { mask, .. } = self;

        *mask == u8::MAX
    }

    /// Report whether this position accepts every byte value.
    #[inline]
    #[must_use]
    pub const fn is_wildcard(&self) -> bool {
        let Self { mask, .. } = self;

        *mask == 0
    }
}

/// One token after lexical decoding but before expansion into parallel byte and mask arrays.
///
/// Tokens retain the useful semantic distinctions of the source grammar. [`Token::Byte`] covers
/// exact bytes and nibble masks. [`Token::Skip`] preserves a nonzero wildcard run as one value.
/// [`Token::Bytes`] owns the decoded payload of a quoted literal so escape processing occurs once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Token {
    /// One constrained or wildcard byte position.
    Byte(MaskedByte),

    /// A nonzero run of unconstrained byte positions.
    Skip(NonZeroUsize),

    /// Exact bytes decoded from one quoted literal.
    Bytes(Vec<u8>),
}

impl Token {
    /// Return the number of fixed-width pattern positions represented by this token.
    ///
    /// A quoted literal may have zero width. The complete materialized pattern still requires at
    /// least one byte position, so zero-width tokens are harmless when combined with other tokens.
    #[inline]
    #[must_use]
    pub const fn width(&self) -> usize {
        match self {
            Self::Byte(..) => 1,
            Self::Skip(target_count) => target_count.get(),
            Self::Bytes(target_bytes) => target_bytes.len(),
        }
    }

    /// Expand this token into the canonical parallel representation.
    fn append(self, target_bytes: &mut Vec<u8>, target_masks: &mut Vec<u8>) {
        match self {
            Self::Byte(target_byte) => {
                target_bytes.push(target_byte.value());
                target_masks.push(target_byte.mask());
            }
            Self::Skip(target_count) => {
                let next_length = target_bytes.len() + target_count.get();

                target_bytes.resize(next_length, 0);
                target_masks.resize(next_length, 0);
            }
            Self::Bytes(target_literal) => {
                let next_length = target_masks.len() + target_literal.len();

                target_bytes.extend_from_slice(&target_literal);
                target_masks.resize(next_length, u8::MAX);
            }
        }
    }
}

/// Parse an entire source string into canonical byte and mask arrays.
///
/// This consumes the same public [`Parser`] stream available to callers. No separate grammar is used
/// by the materializing path, so procedural macro expansion and runtime pattern construction accept
/// and reject the same source language. The returned arrays are nonempty and have equal length.
///
/// # Errors
///
/// Returns the first [`ParseError`] emitted by [`Parser`]. A source that contains only ASCII
/// whitespace is rejected because a zero-width pattern cannot produce a progressing scanner.
#[inline]
pub fn parse(target_pattern: &str) -> Result<(Vec<u8>, Vec<u8>), ParseError> {
    let mut bytes = Vec::new();
    let mut masks = Vec::new();

    Parser::new(target_pattern).try_for_each(|target_token| {
        target_token?.append(&mut bytes, &mut masks);

        Ok::<(), ParseError>(())
    })?;

    NonZeroUsize::new(bytes.len()).ok_or(ParseError::new(0, ParseErrorKind::Empty))?;

    Ok((bytes, masks))
}

/// Syntax failure classification independent of its source location.
///
/// The enum is suitable for callers that want structured diagnostics or recovery policy while
/// [`ParseError`] adds the byte offset needed to identify the rejected source position.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseErrorKind {
    /// No pattern position was present after whitespace was consumed.
    Empty,

    /// A token began with a byte that is not part of the grammar.
    Unexpected(u8),

    /// A two-position hexadecimal or nibble token ended after its first position.
    IncompleteByte,

    /// A required hexadecimal nibble contained a non-hexadecimal byte.
    InvalidHex,

    /// A fixed wildcard span was empty, zero, malformed, or too large for `usize`.
    InvalidSkip,

    /// A quoted literal reached end of input before its closing quote.
    UnterminatedString,

    /// A quoted literal contained an unsupported or incomplete escape sequence.
    InvalidEscape,

    /// A complete token was followed by another byte without separating whitespace.
    Boundary,
}

impl core::fmt::Display for ParseErrorKind {
    #[inline]
    fn fmt(&self, target_formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Empty => target_formatter.write_str("pattern is empty"),
            Self::Unexpected(target_byte) => write!(
                target_formatter,
                "unexpected token byte 0x{target_byte:02x}"
            ),
            Self::IncompleteByte => target_formatter.write_str("incomplete byte token"),
            Self::InvalidHex => target_formatter.write_str("invalid hexadecimal nibble"),
            Self::InvalidSkip => target_formatter.write_str("invalid fixed skip"),
            Self::UnterminatedString => {
                target_formatter.write_str("unterminated quoted byte string")
            }
            Self::InvalidEscape => target_formatter.write_str("invalid quoted byte escape"),
            Self::Boundary => {
                target_formatter.write_str("pattern tokens must be separated by whitespace")
            }
        }
    }
}

impl core::error::Error for ParseErrorKind {}

/// Located syntax failure from one parser source.
///
/// Offsets count source bytes rather than Unicode scalar values. The grammar itself is byte oriented
/// and accepts only ASCII syntax, so this remains stable even when unsupported UTF-8 appears in the
/// input before the rejected token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseError {
    /// Byte offset into the original UTF-8 source string.
    offset: usize,

    /// Semantic reason that parsing could not continue.
    kind: ParseErrorKind,
}

impl core::fmt::Display for ParseError {
    #[inline]
    fn fmt(&self, target_formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let Self { offset, kind } = self;

        write!(target_formatter, "{kind} at byte {offset}")
    }
}

impl core::error::Error for ParseError {}

impl ParseError {
    /// Construct a located error for parser internals and compatible external parsers.
    #[inline]
    #[must_use]
    pub const fn new(target_offset: usize, target_kind: ParseErrorKind) -> Self {
        Self {
            offset: target_offset,
            kind: target_kind,
        }
    }

    /// Return the byte offset of the rejected token or escape.
    #[inline]
    #[must_use]
    pub const fn offset(&self) -> usize {
        let Self { offset, .. } = self;

        *offset
    }

    /// Return the structured failure reason without its source position.
    #[inline]
    #[must_use]
    pub const fn kind(&self) -> ParseErrorKind {
        let Self { kind, .. } = self;

        *kind
    }
}

/// Enumerated source iterator retained by [`Parser`].
type Source<'source> = Enumerate<Iter<'source, u8>>;

pub mod prelude {
    //! Imports for callers that consume or materialize pattern syntax.
    //!
    //! The prelude includes both the streaming token interface and the complete parsed form. Search
    //! planning and scanning remain outside this module so syntax consumers do not inherit those
    //! policies accidentally.

    pub use super::{MaskedByte, ParseError, ParseErrorKind, Parser, Token, parse};
}

#[cfg(test)]
mod tests {
    //! Syntax tests cover token identity, representation expansion, escapes, and failure classes.

    use super::*;

    #[test]
    fn parser_exposes_semantic_tokens() {
        let tokens = Parser::new(r#"4? [2] "ELF""#)
            .collect::<Result<Vec<_>, _>>()
            .expect("test token stream should parse");
        let mut tokens = tokens.into_iter();

        assert_eq!(
            tokens.next(),
            Some(Token::Byte(MaskedByte::new(0x40, 0xf0)))
        );
        assert!(matches!(
            tokens.next(),
            Some(Token::Skip(target_count)) if target_count.get() == 2
        ));
        assert_eq!(tokens.next(), Some(Token::Bytes(Vec::from(*b"ELF"))));
        assert_eq!(tokens.next(), None);
    }

    #[test]
    fn parser_combines_exact_masked_string_and_skip_tokens() {
        let (bytes, masks) =
            parse(r#"48 8B ?? 4? ?F [2] "ELF""#).expect("test pattern should parse");

        assert_eq!(
            bytes,
            &[0x48, 0x8b, 0x00, 0x40, 0x0f, 0, 0, b'E', b'L', b'F']
        );
        assert_eq!(
            masks,
            &[0xff, 0xff, 0x00, 0xf0, 0x0f, 0, 0, 0xff, 0xff, 0xff]
        );
    }

    #[test]
    fn parser_preserves_quoted_escape_bytes() {
        let (bytes, masks) = parse(r#""A\x00\\\"\n""#).expect("quoted escapes should parse");

        assert_eq!(bytes, b"A\0\\\"\n");
        assert!(masks.iter().all(|target_mask| *target_mask == u8::MAX));
    }

    #[test]
    fn parser_rejects_empty_and_malformed_tokens() {
        assert_eq!(
            parse(" ").expect_err("empty pattern must fail").kind(),
            ParseErrorKind::Empty
        );
        assert_eq!(
            parse("4Z").expect_err("bad hex must fail").kind(),
            ParseErrorKind::InvalidHex
        );
        assert_eq!(
            parse("[0]").expect_err("zero skip must fail").kind(),
            ParseErrorKind::InvalidSkip
        );
        assert_eq!(
            parse("\"\"")
                .expect_err("zero-width quoted pattern must fail")
                .kind(),
            ParseErrorKind::Empty
        );
    }
}

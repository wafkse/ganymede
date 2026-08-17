//! Parser for Pelite-style executable binary-pattern syntax.
//!
//! Parsing emits the same flat [`super::Atom`] stream interpreted by the scanner. Whitespace is
//! optional. Save slot zero records each match start and later captures are assigned in source
//! order. Alternative branches reuse capture slots from the same branch entry and retain the
//! maximum extent required by any branch.

extern crate alloc;

use alloc::vec::Vec;

use super::Atom;

/// Parse an entire executable pattern into its flat atom representation.
///
/// Ganymede accepts Pelite's exact-byte, whole-wildcard, fixed and variable skip, capture, follow,
/// followed-subpattern, alignment, integer-read, zero, quoted-byte, and alternative syntax. It also
/// accepts nibble wildcards and lowers them to `Fuzzy` plus `Byte` atoms.
///
/// # Errors
///
/// This returns the first located syntax failure. A pattern whose effective atom stream contains
/// only the implicit match-start capture is rejected.
#[inline]
pub fn parse(target_source: &str) -> Result<Vec<Atom>, ParseError> {
    Parser::new(target_source).finish()
}

/// Executable-pattern syntax failure classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseErrorKind {
    /// No effective pattern operation remained.
    Empty,

    /// A token began with an unsupported source byte.
    Unexpected(u8),

    /// A byte token ended before both nibble positions were present.
    IncompleteByte,

    /// A required hexadecimal or wildcard nibble was malformed.
    InvalidHex,

    /// A fixed or ranged decimal skip was malformed or exceeded host indexing.
    InvalidSkip,

    /// A quoted byte string reached source end before its closing quote.
    UnterminatedString,

    /// Sequential capture-slot assignment exceeded the atom representation.
    SaveOverflow,

    /// An alignment marker had no valid exponent operand.
    AlignedOperand,

    /// An integer read marker had no supported width operand.
    ReadOperand,

    /// A followed subpattern reached source end before its closing brace.
    SubPattern,

    /// A parenthesized alternative group was malformed or unclosed.
    Alternative,
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
            Self::InvalidSkip => target_formatter.write_str("invalid skip range"),
            Self::UnterminatedString => {
                target_formatter.write_str("unterminated quoted byte string")
            }
            Self::SaveOverflow => target_formatter.write_str("too many pattern capture slots"),
            Self::AlignedOperand => target_formatter.write_str("invalid alignment operand"),
            Self::ReadOperand => target_formatter.write_str("invalid integer read operand"),
            Self::SubPattern => target_formatter.write_str("invalid followed subpattern"),
            Self::Alternative => target_formatter.write_str("invalid alternative group"),
        }
    }
}

impl core::error::Error for ParseErrorKind {}

/// Located executable-pattern syntax failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseError {
    /// Byte offset into the original UTF-8 source.
    offset: usize,

    /// Semantic syntax failure.
    kind: ParseErrorKind,
}

impl ParseError {
    /// Construct one located parser failure.
    #[inline]
    #[must_use]
    pub const fn new(target_offset: usize, target_kind: ParseErrorKind) -> Self {
        Self {
            offset: target_offset,
            kind: target_kind,
        }
    }

    /// Return the rejected source byte offset.
    #[inline]
    #[must_use]
    pub const fn offset(&self) -> usize {
        let Self { offset, .. } = self;

        *offset
    }

    /// Return the structured syntax failure.
    #[inline]
    #[must_use]
    pub const fn kind(&self) -> ParseErrorKind {
        let Self { kind, .. } = self;

        *kind
    }
}

impl core::fmt::Display for ParseError {
    #[inline]
    fn fmt(&self, target_formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let Self { offset, kind } = self;

        write!(target_formatter, "{kind} at byte {offset}")
    }
}

impl core::error::Error for ParseError {}

/// Recursive parser state for one borrowed source string.
#[derive(Debug)]
// NOTE(invariant): `offset` never exceeds `source.len()` and `next_slot` is the first unassigned capture slot for the active sequence.
struct Parser<'source> {
    /// Source bytes interpreted by the grammar.
    source: &'source [u8],

    /// Current source byte offset.
    offset: usize,

    /// Next capture slot after the reserved match-start slot.
    next_slot: u16,
}

impl<'source> Parser<'source> {
    /// Bind parser state to one source string.
    #[inline]
    const fn new(target_source: &'source str) -> Self {
        Self {
            source: target_source.as_bytes(),
            offset: 0,
            next_slot: 1,
        }
    }

    /// Compile the complete source into one flat executable atom stream.
    fn finish(mut self) -> Result<Vec<Atom>, ParseError> {
        let mut atoms = vec![Atom::Save(0)];
        atoms.extend(self.sequence(None)?);
        self.space();

        let Self { source, offset, .. } = &self;

        if *offset != source.len() {
            return Err(self.error(ParseErrorKind::Unexpected(source[*offset])));
        }

        Self::trim(&mut atoms);

        if atoms.len() == 1 {
            return Err(ParseError::new(0, ParseErrorKind::Empty));
        }

        Ok(atoms)
    }

    /// Parse one sequence until the requested closing delimiter or source end.
    fn sequence(&mut self, target_end: Option<u8>) -> Result<Vec<Atom>, ParseError> {
        let mut atoms = Vec::new();

        loop {
            self.space();
            let Some(target_byte) = self.peek() else {
                return if target_end.is_some() {
                    Err(self.error(ParseErrorKind::SubPattern))
                } else {
                    Ok(atoms)
                };
            };

            if target_end == Some(target_byte) {
                self.advance();

                return Ok(atoms);
            }

            if matches!(target_byte, b'|' | b')') {
                return Ok(atoms);
            }

            self.operation(&mut atoms)?;
        }
    }

    /// Parse and append one source operation.
    fn operation(&mut self, target_atoms: &mut Vec<Atom>) -> Result<(), ParseError> {
        let target_start = self.position();
        let target_leading = self
            .take()
            .ok_or_else(|| ParseError::new(target_start, ParseErrorKind::Empty))?;

        match target_leading {
            b'\'' => target_atoms.push(Atom::Save(self.slot()?)),
            b'[' => self.skip(target_atoms, target_start)?,
            b'"' => self.quoted(target_atoms, target_start)?,
            b'%' => self.follow(target_atoms, Atom::Jump1, 1)?,
            b'$' => self.follow(target_atoms, Atom::Jump4, 4)?,
            b'*' => self.follow(target_atoms, Atom::Pointer, 0)?,
            b'@' => target_atoms.push(self.aligned(target_start)?),
            b'i' => target_atoms.push(self.read(target_start, true)?),
            b'u' => target_atoms.push(self.read(target_start, false)?),
            b'z' => target_atoms.push(Atom::Zero(self.slot()?)),
            b'(' => self.choice(target_atoms, target_start)?,
            b'?' => self.byte(target_atoms, target_start, target_leading)?,
            _ if Self::hex(target_leading).is_some() => {
                self.byte(target_atoms, target_start, target_leading)?;
            }
            _ => {
                return Err(ParseError::new(
                    target_start,
                    ParseErrorKind::Unexpected(target_leading),
                ));
            }
        }

        Ok(())
    }

    /// Parse one exact byte, whole wildcard, or nibble wildcard.
    fn byte(
        &mut self,
        target_atoms: &mut Vec<Atom>,
        target_start: usize,
        target_first: u8,
    ) -> Result<(), ParseError> {
        let second_is_nibble = match target_first {
            b'?' => self.peek().and_then(Self::hex).is_some(),
            _ => self.peek().is_some_and(Self::is_nibble),
        };

        if target_first == b'?' && !second_is_nibble {
            Self::skip_push(target_atoms, 1);

            return Ok(());
        }

        let target_second = self
            .take()
            .ok_or_else(|| ParseError::new(target_start, ParseErrorKind::IncompleteByte))?;
        let (high_value, high_mask) = Self::nibble(target_first)
            .ok_or_else(|| ParseError::new(target_start, ParseErrorKind::InvalidHex))?;
        let (low_value, low_mask) = Self::nibble(target_second)
            .ok_or_else(|| ParseError::new(target_start, ParseErrorKind::InvalidHex))?;
        let value = (high_value << 4) | low_value;
        let mask = (high_mask << 4) | low_mask;

        match mask {
            0 => Self::skip_push(target_atoms, 1),
            u8::MAX => target_atoms.push(Atom::Byte(value)),
            _ => {
                target_atoms.push(Atom::Fuzzy(mask));
                target_atoms.push(Atom::Byte(value));
            }
        }

        Ok(())
    }

    /// Parse and append one fixed or ranged decimal skip.
    fn skip(
        &mut self,
        target_atoms: &mut Vec<Atom>,
        target_start: usize,
    ) -> Result<(), ParseError> {
        let minimum = self.decimal(target_start)?;

        match self.peek() {
            Some(b']') => {
                self.advance();
                Self::skip_push(target_atoms, minimum);
            }
            Some(b'-') => {
                self.advance();
                let maximum = self.decimal(target_start)?;

                if self.take() != Some(b']') || minimum >= maximum {
                    return Err(ParseError::new(target_start, ParseErrorKind::InvalidSkip));
                }

                Self::skip_push(target_atoms, minimum);
                let extent = maximum - minimum;
                target_atoms.push(Atom::Many(extent));
            }
            _ => return Err(ParseError::new(target_start, ParseErrorKind::InvalidSkip)),
        }

        Ok(())
    }

    /// Parse one unsigned decimal host-size value.
    fn decimal(&mut self, target_start: usize) -> Result<usize, ParseError> {
        let mut value = 0usize;
        let mut seen = false;

        while let Some(target_byte @ b'0'..=b'9') = self.peek() {
            seen = true;
            self.advance();
            value = value
                .checked_mul(10)
                .and_then(|target_value| target_value.checked_add(usize::from(target_byte - b'0')))
                .ok_or_else(|| ParseError::new(target_start, ParseErrorKind::InvalidSkip))?;
        }

        if seen {
            Ok(value)
        } else {
            Err(ParseError::new(target_start, ParseErrorKind::InvalidSkip))
        }
    }

    /// Parse and append one raw quoted byte string.
    fn quoted(
        &mut self,
        target_atoms: &mut Vec<Atom>,
        target_start: usize,
    ) -> Result<(), ParseError> {
        loop {
            let Some(target_byte) = self.take() else {
                return Err(ParseError::new(
                    target_start,
                    ParseErrorKind::UnterminatedString,
                ));
            };

            if target_byte == b'"' {
                return Ok(());
            }

            target_atoms.push(Atom::Byte(target_byte));
        }
    }

    /// Parse one follow operation and optional restoring subpattern.
    fn follow(
        &mut self,
        target_atoms: &mut Vec<Atom>,
        target_follow: Atom,
        target_resume: usize,
    ) -> Result<(), ParseError> {
        self.space();

        if self.peek() != Some(b'{') {
            target_atoms.push(target_follow);

            return Ok(());
        }

        self.advance();
        let target_nested = self.sequence(Some(b'}'))?;
        target_atoms.push(Atom::Push(target_resume));
        target_atoms.push(target_follow);
        target_atoms.extend(target_nested);
        target_atoms.push(Atom::Pop);

        Ok(())
    }

    /// Parse one alignment exponent.
    fn aligned(&mut self, target_start: usize) -> Result<Atom, ParseError> {
        let target_byte = self
            .take()
            .ok_or_else(|| ParseError::new(target_start, ParseErrorKind::AlignedOperand))?;
        let exponent = match target_byte {
            b'0'..=b'9' => target_byte - b'0',
            b'a'..=b'z' => target_byte - b'a' + 10,
            b'A'..=b'Z' => target_byte - b'A' + 10,
            _ => {
                return Err(ParseError::new(
                    target_start,
                    ParseErrorKind::AlignedOperand,
                ));
            }
        };

        Ok(Atom::Aligned(exponent))
    }

    /// Parse one signed or unsigned integer read and assign its capture slot.
    fn read(&mut self, target_start: usize, target_signed: bool) -> Result<Atom, ParseError> {
        let target_width = self
            .take()
            .ok_or_else(|| ParseError::new(target_start, ParseErrorKind::ReadOperand))?;
        let slot = self.slot()?;
        let atom = match (target_signed, target_width) {
            (true, b'1') => Atom::ReadI8(slot),
            (false, b'1') => Atom::ReadU8(slot),
            (true, b'2') => Atom::ReadI16(slot),
            (false, b'2') => Atom::ReadU16(slot),
            (true, b'4') => Atom::ReadI32(slot),
            (false, b'4') => Atom::ReadU32(slot),
            _ => return Err(ParseError::new(target_start, ParseErrorKind::ReadOperand)),
        };

        Ok(atom)
    }

    /// Parse one parenthesized alternative group and lower it to case and break atoms.
    fn choice(
        &mut self,
        target_atoms: &mut Vec<Atom>,
        target_start: usize,
    ) -> Result<(), ParseError> {
        let entry_slot = self.next_slot();
        let mut alternatives = Vec::new();
        let mut maximum_slot = entry_slot;

        loop {
            self.set_next_slot(entry_slot);
            let target_alternative = self.sequence(None)?;
            maximum_slot = maximum_slot.max(self.next_slot());

            if target_alternative.is_empty() {
                return Err(ParseError::new(target_start, ParseErrorKind::Alternative));
            }

            alternatives.push(target_alternative);
            self.space();

            match self.take() {
                Some(b'|') => {}
                Some(b')') if alternatives.len() >= 2 => break,
                _ => return Err(ParseError::new(target_start, ParseErrorKind::Alternative)),
            }
        }

        self.set_next_slot(maximum_slot);
        Self::encode_choice(target_atoms, alternatives);

        Ok(())
    }

    /// Encode parsed alternatives as Pelite-style relative case and break control flow.
    fn encode_choice(target_atoms: &mut Vec<Atom>, target_alternatives: Vec<Vec<Atom>>) {
        let mut cases = Vec::new();
        let mut breaks = Vec::new();

        for target_alternative in target_alternatives {
            cases.push(target_atoms.len());
            target_atoms.push(Atom::Case(0));
            target_atoms.extend(target_alternative);
            breaks.push(target_atoms.len());
            target_atoms.push(Atom::Break(0));
        }

        let end = target_atoms.len();
        let Some(last_case) = cases.pop() else {
            return;
        };
        target_atoms[last_case] = Atom::Nop;
        let Some(last_break) = breaks.pop() else {
            return;
        };
        target_atoms[last_break] = Atom::Nop;

        let mut next_case = last_case;

        while let Some(target_case) = cases.pop() {
            target_atoms[target_case] = Atom::Case(next_case - target_case - 1);
            next_case = target_case;
        }

        for target_break in breaks {
            target_atoms[target_break] = Atom::Break(end - target_break - 1);
        }
    }

    /// Allocate one sequential capture slot.
    fn slot(&mut self) -> Result<u8, ParseError> {
        let Self {
            offset, next_slot, ..
        } = self;
        let target_slot = u8::try_from(*next_slot)
            .map_err(|_| ParseError::new(*offset, ParseErrorKind::SaveOverflow))?;
        *next_slot += 1;

        Ok(target_slot)
    }

    /// Append one fixed skip while coalescing adjacent skip atoms without overflow.
    fn skip_push(target_atoms: &mut Vec<Atom>, target_count: usize) {
        if target_count == 0 {
            return;
        }

        if let Some(Atom::Skip(target_existing)) = target_atoms.last_mut()
            && let Some(combined) = target_existing.checked_add(target_count)
        {
            *target_existing = combined;

            return;
        }

        target_atoms.push(Atom::Skip(target_count));
    }

    /// Remove terminal unconstrained movement that cannot affect acceptance.
    fn trim(target_atoms: &mut Vec<Atom>) {
        while matches!(
            target_atoms.last(),
            Some(Atom::Skip(..) | Atom::Pop | Atom::Many(..))
        ) {
            target_atoms.pop();
        }
    }

    /// Consume ASCII whitespace.
    fn space(&mut self) {
        while self
            .peek()
            .is_some_and(|target_byte| target_byte.is_ascii_whitespace())
        {
            self.advance();
        }
    }

    /// Return the current source byte offset.
    #[inline]
    const fn position(&self) -> usize {
        let Self { offset, .. } = self;

        *offset
    }

    /// Return the current sequential capture counter.
    #[inline]
    const fn next_slot(&self) -> u16 {
        let Self { next_slot, .. } = self;

        *next_slot
    }

    /// Replace the sequential capture counter while entering or leaving an alternative branch.
    #[inline]
    const fn set_next_slot(&mut self, target_next_slot: u16) {
        let Self { next_slot, .. } = self;

        *next_slot = target_next_slot;
    }

    /// Advance by one source byte.
    #[inline]
    const fn advance(&mut self) {
        let Self { offset, .. } = self;

        *offset += 1;
    }

    /// Peek the current source byte.
    #[inline]
    fn peek(&self) -> Option<u8> {
        let Self { source, offset, .. } = self;

        source.get(*offset).copied()
    }

    /// Consume the current source byte.
    #[inline]
    fn take(&mut self) -> Option<u8> {
        let target_byte = self.peek()?;
        self.advance();

        Some(target_byte)
    }

    /// Construct one failure at the current source byte offset.
    #[inline]
    const fn error(&self, target_kind: ParseErrorKind) -> ParseError {
        ParseError::new(self.position(), target_kind)
    }

    /// Determine whether one byte can occupy a hexadecimal or wildcard nibble position.
    #[inline]
    const fn is_nibble(target_byte: u8) -> bool {
        target_byte == b'?' || Self::hex(target_byte).is_some()
    }

    /// Decode one hexadecimal or wildcard nibble into value and mask bits.
    #[inline]
    const fn nibble(target_byte: u8) -> Option<(u8, u8)> {
        if target_byte == b'?' {
            return Some((0, 0));
        }

        match Self::hex(target_byte) {
            Some(target_value) => Some((target_value, 0x0f)),
            None => None,
        }
    }

    /// Decode one ASCII hexadecimal nibble.
    #[inline]
    const fn hex(target_byte: u8) -> Option<u8> {
        match target_byte {
            b'0'..=b'9' => Some(target_byte - b'0'),
            b'a'..=b'f' => Some(target_byte - b'a' + 10),
            b'A'..=b'F' => Some(target_byte - b'A' + 10),
            _ => None,
        }
    }
}

pub mod prelude {
    //! Convenience imports for executable pattern parsing.

    pub use super::{ParseError, ParseErrorKind, parse};
}

#[cfg(test)]
mod tests {
    //! Regression coverage for Pelite lowering, captures, ranges, and malformed control flow.

    use super::*;

    #[test]
    fn parser_lowers_followed_subpatterns_to_push_and_pop_atoms() {
        let atoms = parse("E8 $ { ' 31 C0 } 83 F0").expect("followed pattern should parse");

        assert!(
            atoms
                .windows(2)
                .any(|target_pair| { matches!(target_pair, [Atom::Push(4), Atom::Jump4]) })
        );
        assert!(atoms.contains(&Atom::Pop));
    }

    #[test]
    fn ranged_skip_lowers_to_fixed_skip_then_non_greedy_many() {
        let atoms = parse("B8 [16] 50 [13-42] FF").expect("ranged pattern should parse");

        assert!(atoms.contains(&Atom::Skip(16)));
        assert!(atoms.contains(&Atom::Skip(13)));
        assert!(atoms.contains(&Atom::Many(29)));
    }

    #[test]
    fn alternatives_lower_to_relative_case_and_break_atoms() {
        let atoms = parse("83 C0 ( 6A ? | 68 ???? ) E8").expect("alternative should parse");

        assert!(
            atoms
                .iter()
                .any(|target_atom| matches!(target_atom, Atom::Case(..)))
        );
        assert!(
            atoms
                .iter()
                .any(|target_atom| matches!(target_atom, Atom::Break(..)))
        );
        assert!(atoms.contains(&Atom::Nop));
    }

    #[test]
    fn alternative_capture_slots_are_reused_by_branch_position() {
        let atoms = parse("( ' 41 | ' 42 ) ' 43").expect("capture alternatives should parse");
        let captures = atoms
            .iter()
            .filter_map(|target_atom| match target_atom {
                Atom::Save(target_slot) => Some(*target_slot),
                _ => None,
            })
            .collect::<Vec<_>>();

        assert_eq!(captures, vec![0, 1, 1, 2]);
    }

    #[test]
    fn consecutive_question_marks_remain_independent_pelite_wildcards() {
        let atoms = parse("41 ???? 42").expect("whole wildcard pattern should parse");

        assert!(atoms.contains(&Atom::Skip(4)));
    }

    #[test]
    fn nibble_wildcards_lower_to_fuzzy_byte_pairs() {
        let atoms = parse("4? ?F ?? 42").expect("nibble pattern should parse");

        assert!(
            atoms.windows(2).any(|target_pair| {
                matches!(target_pair, [Atom::Fuzzy(0xf0), Atom::Byte(0x40)])
            })
        );
        assert!(
            atoms.windows(2).any(|target_pair| {
                matches!(target_pair, [Atom::Fuzzy(0x0f), Atom::Byte(0x0f)])
            })
        );
        assert!(atoms.contains(&Atom::Skip(2)));
    }

    #[test]
    fn malformed_control_syntax_reports_stable_failure_classes() {
        let cases = [
            ("", ParseErrorKind::Empty),
            ("[4-4]", ParseErrorKind::InvalidSkip),
            ("[4-]", ParseErrorKind::InvalidSkip),
            ("(41)", ParseErrorKind::Alternative),
            ("(41|)", ParseErrorKind::Alternative),
            ("${41", ParseErrorKind::SubPattern),
            ("u8", ParseErrorKind::ReadOperand),
            ("@!", ParseErrorKind::AlignedOperand),
        ];

        for (target_source, target_kind) in cases {
            assert_eq!(
                parse(target_source)
                    .expect_err("malformed executable pattern must fail")
                    .kind(),
                target_kind,
                "unexpected failure class for {target_source:?}"
            );
        }
    }

    #[test]
    fn quoted_runtime_bytes_remain_raw() {
        let atoms = parse(r#""A\n""#).expect("quoted bytes should parse");
        let bytes = atoms
            .iter()
            .filter_map(|target_atom| match target_atom {
                Atom::Byte(target_byte) => Some(*target_byte),
                _ => None,
            })
            .collect::<Vec<_>>();

        assert_eq!(bytes, br"A\n");
    }
}

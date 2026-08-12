//! Validated fixed-width patterns and their compiled search representation.
//!
//! A pattern is represented by parallel byte and mask slices. Construction proves that the slices
//! have equal nonzero width, then derives a search plan from those exact values. Callers can borrow
//! the representation through [`Pattern`] or retain owned storage through [`PatternBuf`].
//!
//! Syntax parsing and scanning are separate public capabilities. They consume the same validated
//! representation, which keeps textual syntax policy out of the hot matching path.

extern crate alloc;

use alloc::vec::Vec;
use core::str::FromStr;

mod plan;

pub mod scan;

pub mod syntax;

use plan::SearchPlan;

/// One masked byte selected to reject unlikely candidate positions quickly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// NOTE(invariant): `mask` is nonzero and `offset` lies within the pattern that produced this probe.
struct Probe {
    /// Byte offset from a candidate pattern start.
    offset: usize,

    /// Pattern byte with unconstrained bits cleared.
    value: u8,

    /// Bits that participate in candidate comparison.
    mask: u8,
}

/// Failure while constructing a fixed-width pattern from byte and mask arrays.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatternError {
    /// A zero-width pattern would match without consuming any byte.
    Empty,

    /// Pattern bytes and masks must describe the same number of positions.
    Length {
        /// Number of supplied pattern bytes.
        bytes: usize,

        /// Number of supplied pattern masks.
        masks: usize,
    },
}

impl core::fmt::Display for PatternError {
    #[inline]
    fn fmt(&self, target_formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Empty => target_formatter.write_str("pattern is empty"),
            Self::Length { bytes, masks } => write!(
                target_formatter,
                "pattern byte count {bytes} does not match mask count {masks}"
            ),
        }
    }
}

impl core::error::Error for PatternError {}

/// Borrowed fixed-width pattern whose search plan is already compiled.
///
/// The value is cheap to copy because it borrows both representation slices. The stored plan is
/// derived once during construction and remains coherent with those slices for the complete borrow.
/// Matching never reparses syntax or reallocates pattern storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// NOTE(invariant): `bytes` and `masks` are nonempty and equal in length, and `plan` was derived from those exact slices.
pub struct Pattern<'pattern> {
    /// Pattern byte values.
    bytes: &'pattern [u8],

    /// Bit masks selecting constrained bits in each pattern byte.
    masks: &'pattern [u8],

    /// Candidate-discovery strategy derived once during construction.
    plan: SearchPlan,
}

impl<'pattern> Pattern<'pattern> {
    /// Validate borrowed representation slices and compile their search plan.
    ///
    /// `target_masks` selects which bits of each corresponding byte are significant. Successful
    /// construction therefore proves that every pattern position has one value and one mask.
    ///
    /// # Errors
    ///
    /// Returns [`PatternError::Empty`] when no progressing match can be formed. Returns
    /// [`PatternError::Length`] when positional byte and mask data cannot be paired exactly.
    #[inline]
    pub const fn from_parts(
        target_bytes: &'pattern [u8],
        target_masks: &'pattern [u8],
    ) -> Result<Self, PatternError> {
        let nonempty = !target_bytes.is_empty();
        let same_length = target_bytes.len() == target_masks.len();

        match (nonempty, same_length) {
            (false, _) => Err(PatternError::Empty),
            (true, false) => Err(PatternError::Length {
                bytes: target_bytes.len(),
                masks: target_masks.len(),
            }),
            (true, true) => {
                let plan = SearchPlan::compile(target_bytes, target_masks);

                Ok(Self {
                    bytes: target_bytes,
                    masks: target_masks,
                    plan,
                })
            }
        }
    }

    /// Construct a statically emitted pattern after asserting representation invariants.
    ///
    /// This entry point exists for the companion procedural macro so const pattern expressions do
    /// not depend on const support for `Result::expect`.
    #[doc(hidden)]
    #[inline]
    #[must_use]
    pub const fn from_static_parts(
        target_bytes: &'pattern [u8],
        target_masks: &'pattern [u8],
    ) -> Self {
        assert!(!target_bytes.is_empty(), "static pattern must be nonempty");
        assert!(
            target_bytes.len() == target_masks.len(),
            "static pattern byte and mask lengths must match"
        );

        let plan = SearchPlan::compile(target_bytes, target_masks);

        Self {
            bytes: target_bytes,
            masks: target_masks,
            plan,
        }
    }

    /// Return the fixed byte width consumed by one match.
    #[inline]
    #[must_use]
    pub const fn len(&self) -> usize {
        let Self { bytes, .. } = self;

        bytes.len()
    }

    /// Report whether this pattern consumes no bytes.
    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        false
    }

    /// Borrow the pattern byte values.
    #[inline]
    #[must_use]
    pub const fn bytes(&self) -> &'pattern [u8] {
        let Self { bytes, .. } = self;

        bytes
    }

    /// Borrow the per-byte bit masks.
    #[inline]
    #[must_use]
    pub const fn masks(&self) -> &'pattern [u8] {
        let Self { masks, .. } = self;

        masks
    }

    /// Determine whether one same-width byte slice satisfies every constrained bit.
    #[inline]
    #[must_use]
    pub fn matches(&self, target_bytes: &[u8]) -> bool {
        let Self { bytes, masks, .. } = self;
        let is_same_length = target_bytes.len() == bytes.len();

        is_same_length
            && bytes.iter().zip(masks.iter()).zip(target_bytes.iter()).all(
                |((&pattern_byte, &mask), &target_byte)| ((target_byte ^ pattern_byte) & mask) == 0,
            )
    }

    /// Borrow the exact-byte region selected for substring candidate discovery.
    ///
    /// Literal plans return the complete pattern. Anchored plans return the exact run proven during
    /// planning. Masked-probe and wildcard plans have no substring anchor.
    #[inline]
    fn anchor(&self) -> Option<&'pattern [u8]> {
        let Self { bytes, plan, .. } = self;

        match *plan {
            SearchPlan::Literal => Some(bytes),
            SearchPlan::Anchor { offset, length } => Some(
                bytes
                    .get(offset..offset + length)
                    .expect("compiled anchor must remain within the pattern representation"),
            ),
            SearchPlan::Probes { .. } | SearchPlan::Wildcard => None,
        }
    }

    /// Return the compiled search strategy tied to this exact representation.
    #[inline]
    const fn plan(&self) -> SearchPlan {
        let Self { plan, .. } = self;

        *plan
    }
}

/// Owned fixed-width pattern for runtime construction and long-lived scanner reuse.
///
/// Ownership lets callers discard source syntax or temporary construction buffers while retaining
/// the compiled plan. Borrowing through [`Self::as_pattern`] does not rebuild that plan.
#[derive(Debug, Clone, PartialEq, Eq)]
// NOTE(invariant): Owned byte and mask arrays are nonempty and equal in length, and `plan` was derived after those arrays reached their final contents.
pub struct PatternBuf {
    /// Owned pattern byte values.
    bytes: Vec<u8>,

    /// Owned bit masks.
    masks: Vec<u8>,

    /// Candidate-discovery strategy derived from the owned arrays.
    plan: SearchPlan,
}

impl PatternBuf {
    /// Take ownership of canonical representation arrays and compile one search plan.
    ///
    /// Inputs become owned vectors before validation. Their buffers are retained by the pattern, so
    /// transferring existing vectors does not require a shrink-to-fit allocation before scanning.
    ///
    /// # Errors
    ///
    /// Returns [`PatternError::Empty`] when the owned representation has no byte position. Returns
    /// [`PatternError::Length`] when byte and mask positions cannot be paired exactly.
    #[inline]
    pub fn from_parts(
        target_bytes: impl Into<Vec<u8>>,
        target_masks: impl Into<Vec<u8>>,
    ) -> Result<Self, PatternError> {
        let bytes = target_bytes.into();
        let masks = target_masks.into();
        let pattern = Pattern::from_parts(&bytes, &masks)?;
        let plan = pattern.plan();

        Ok(Self { bytes, masks, plan })
    }

    /// Parse syntax once and retain an owned compiled pattern.
    ///
    /// Parsing materializes canonical byte and mask arrays directly. Search planning then runs over
    /// those arrays, so runtime parsing and direct construction converge on the same scanner
    /// representation without retaining an intermediate syntax object.
    ///
    /// # Errors
    ///
    /// Returns the first [`syntax::ParseError`] produced while tokenizing or materializing the
    /// source. No partially compiled pattern is returned on failure.
    #[inline]
    pub fn parse(target_pattern: &str) -> Result<Self, syntax::ParseError> {
        let (bytes, masks) = syntax::parse(target_pattern)?;

        let plan = SearchPlan::compile(&bytes, &masks);

        Ok(Self { bytes, masks, plan })
    }

    /// Borrow this owned pattern without rebuilding its search strategy.
    #[inline]
    #[must_use]
    pub const fn as_pattern(&self) -> Pattern<'_> {
        let Self { bytes, masks, plan } = self;

        Pattern {
            bytes: bytes.as_slice(),
            masks: masks.as_slice(),
            plan: *plan,
        }
    }
}

impl FromStr for PatternBuf {
    type Err = syntax::ParseError;

    #[inline]
    fn from_str(target_pattern: &str) -> Result<Self, Self::Err> {
        Self::parse(target_pattern)
    }
}

pub mod prelude {
    //! Convenience imports for validated pattern construction and scanning.
    //!
    //! This prelude composes the pattern representation with its scanner and syntax surfaces.

    pub use super::scan::{Matches, Scanner};
    pub use super::syntax::{MaskedByte, ParseError, ParseErrorKind, Parser, Token, parse};
    pub use super::{Pattern, PatternBuf, PatternError};
}

#[cfg(test)]
mod tests {
    //! Regression coverage for fixed-width representation and plan-independent matching.

    use super::*;

    #[test]
    fn masked_matching_accepts_nibble_wildcards() {
        let bytes = [0x40, 0x0f, 0x00];
        let masks = [0xf0, 0x0f, 0x00];
        let pattern = Pattern::from_parts(&bytes, &masks).expect("test pattern should be valid");

        assert!(pattern.matches(&[0x4a, 0xbf, 0xff]));
        assert!(!pattern.matches(&[0x5a, 0xbf, 0xff]));
    }

    #[test]
    fn pattern_rejects_empty_or_mismatched_arrays() {
        assert_eq!(Pattern::from_parts(&[], &[]), Err(PatternError::Empty));
        assert!(matches!(
            Pattern::from_parts(&[1], &[]),
            Err(PatternError::Length { .. })
        ));
    }
}

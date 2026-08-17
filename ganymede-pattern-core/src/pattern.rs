//! Unified compiled binary patterns with Pelite-style semantics and fixed-width optimization.
//!
//! Every pattern owns one flat atom stream. Patterns with linear fixed-width semantics also carry a
//! derived private byte and mask projection used by the optimized search engine. Dynamic control
//! flow remains interpreted directly from the same atom stream.

extern crate alloc;

use alloc::{boxed::Box, vec::Vec};
use core::str::FromStr;

mod fixed;

pub mod scan;
pub mod syntax;

use fixed::{Fixed, FixedBuf};

/// Pointer width used when an executable pattern follows an absolute pointer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PointerWidth {
    /// Four-byte little-endian pointer used by 32-bit targets.
    U32,

    /// Eight-byte little-endian pointer used by 64-bit targets.
    U64,
}

impl PointerWidth {
    /// Return the encoded pointer width in bytes.
    #[inline]
    #[must_use]
    pub const fn bytes(self) -> usize {
        match self {
            Self::U32 => 4,
            Self::U64 => 8,
        }
    }
}

/// One instruction in a flat executable binary pattern.
///
/// The control model follows Pelite. `Push` and `Pop` execute a followed subpattern and restore its
/// caller cursor. `Many` retries the remaining pattern at increasing byte offsets. `Case` and
/// `Break` encode alternatives with relative atom offsets. Ganymede omits Pelite's PE and MSVC
/// specific type-name operation because this crate owns format-neutral byte-image scanning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Atom {
    /// Match one exact byte using the active fuzzy mask.
    Byte(u8),

    /// Save the current virtual cursor in one capture slot when present.
    Save(u8),

    /// Execute the following atoms recursively, then restore the caller cursor after advancing it.
    ///
    /// A zero argument advances by the selected target pointer width.
    Push(usize),

    /// Return successfully from one pushed subpattern.
    Pop,

    /// Apply one bit mask to the next byte comparison.
    Fuzzy(u8),

    /// Advance the cursor by the supplied byte count.
    ///
    /// A zero argument advances by the selected target pointer width.
    Skip(usize),

    /// Rewind the cursor by the supplied byte count.
    ///
    /// A zero argument rewinds by the selected target pointer width.
    Back(usize),

    /// Retry the remaining pattern non-greedily within the supplied forward byte extent.
    ///
    /// A zero argument searches through the remaining byte image.
    Many(usize),

    /// Follow one signed eight-bit displacement relative to the next byte.
    Jump1,

    /// Follow one signed little-endian 32-bit displacement relative to the next dword.
    Jump4,

    /// Follow one target-width little-endian absolute pointer.
    Pointer,

    /// Add one signed 32-bit displacement to a saved virtual cursor and follow the result.
    Pir(u8),

    /// Require the current virtual cursor to equal one available saved value.
    Check(u8),

    /// Require the current virtual cursor to be aligned to `1 << exponent`.
    Aligned(u8),

    /// Read and sign-extend one byte into a capture slot.
    ReadI8(u8),

    /// Read and zero-extend one byte into a capture slot.
    ReadU8(u8),

    /// Read and sign-extend one little-endian word into a capture slot.
    ReadI16(u8),

    /// Read and zero-extend one little-endian word into a capture slot.
    ReadU16(u8),

    /// Read and sign-extend one little-endian dword into a capture slot.
    ReadI32(u8),

    /// Read one little-endian unsigned dword into a capture slot.
    ReadU32(u8),

    /// Store zero in one capture slot when present.
    Zero(u8),

    /// Retry an alternative after skipping the supplied number of atoms when the current branch fails.
    Case(usize),

    /// Finish the current alternative successfully and skip the supplied number of atoms.
    Break(usize),

    /// Perform no cursor or capture operation.
    Nop,
}

impl Atom {
    /// Return the capture slot referenced by this atom when one exists.
    #[inline]
    #[must_use]
    pub const fn slot(self) -> Option<u8> {
        match self {
            Self::Save(slot)
            | Self::Pir(slot)
            | Self::Check(slot)
            | Self::ReadI8(slot)
            | Self::ReadU8(slot)
            | Self::ReadI16(slot)
            | Self::ReadU16(slot)
            | Self::ReadI32(slot)
            | Self::ReadU32(slot)
            | Self::Zero(slot) => Some(slot),
            _ => None,
        }
    }
}

/// Failure while constructing a compiled binary pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatternError {
    /// A pattern must contain at least one atom.
    Empty,
}

impl core::fmt::Display for PatternError {
    #[inline]
    fn fmt(&self, target_formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Empty => target_formatter.write_str("pattern is empty"),
        }
    }
}

impl core::error::Error for PatternError {}

/// Borrowed compiled binary pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// NOTE(invariant): `atoms` is nonempty, `save_len` exactly covers every referenced capture slot, and `fixed` when present is derived from those same atoms.
pub struct Pattern<'pattern> {
    /// Flat executable atom stream.
    atoms: &'pattern [Atom],

    /// Capture extent derived from the complete atom stream.
    save_len: usize,

    /// Optional fixed-width projection derived from the same atoms.
    fixed: Option<Fixed<'pattern>>,
}

impl<'pattern> Pattern<'pattern> {
    /// Validate one borrowed atom stream and derive its capture extent.
    ///
    /// Control-flow offsets are checked during execution. Invalid offsets reject that execution
    /// branch rather than making the borrowed representation unsafe.
    ///
    /// # Errors
    ///
    /// This rejects an empty atom stream.
    #[inline]
    pub const fn from_atoms(target_atoms: &'pattern [Atom]) -> Result<Self, PatternError> {
        if target_atoms.is_empty() {
            return Err(PatternError::Empty);
        }

        let save_len = Self::capture_len(target_atoms);

        Ok(Self {
            atoms: target_atoms,
            save_len,
            fixed: None,
        })
    }

    /// Construct a statically emitted pattern and optional fixed projection.
    ///
    /// This entry point exists for the companion procedural macro. Empty fixed slices select the
    /// interpreter path. Nonempty fixed slices must have equal lengths.
    #[doc(hidden)]
    #[inline]
    #[must_use]
    pub const fn from_static_parts(
        target_atoms: &'pattern [Atom],
        target_fixed_bytes: &'pattern [u8],
        target_fixed_masks: &'pattern [u8],
    ) -> Self {
        assert!(!target_atoms.is_empty(), "static pattern must be nonempty");
        assert!(
            target_fixed_bytes.len() == target_fixed_masks.len(),
            "static fixed pattern byte and mask lengths must match"
        );
        assert!(
            target_fixed_bytes.is_empty()
                || Fixed::valid_for(target_atoms, target_fixed_bytes, target_fixed_masks),
            "static fixed pattern projection must match its atoms"
        );

        let save_len = Self::capture_len(target_atoms);
        let fixed = if target_fixed_bytes.is_empty() {
            None
        } else {
            Some(Fixed::new(target_fixed_bytes, target_fixed_masks))
        };

        Self {
            atoms: target_atoms,
            save_len,
            fixed,
        }
    }

    /// Borrow the flat executable atom stream.
    #[inline]
    #[must_use]
    pub const fn atoms(&self) -> &'pattern [Atom] {
        let Self { atoms, .. } = self;

        atoms
    }

    /// Return the complete capture-array width required by this pattern.
    #[inline]
    #[must_use]
    pub const fn save_len(&self) -> usize {
        let Self { save_len, .. } = self;

        *save_len
    }

    /// Borrow the private fixed projection when this pattern can use the optimized engine.
    #[inline]
    const fn fixed(&self) -> Option<Fixed<'pattern>> {
        let Self { fixed, .. } = self;

        *fixed
    }

    /// Derive the capture extent from one atom stream.
    const fn capture_len(target_atoms: &[Atom]) -> usize {
        let mut index = 0usize;
        let mut save_len = 0usize;

        while index < target_atoms.len() {
            if let Some(slot) = target_atoms[index].slot() {
                let required = slot as usize + 1;

                if required > save_len {
                    save_len = required;
                }
            }

            index += 1;
        }

        save_len
    }
}

/// Owned executable pattern compiled from runtime syntax or atom construction.
#[derive(Debug, Clone, PartialEq, Eq)]
// NOTE(invariant): `atoms` is nonempty, `save_len` is derived from those exact final atoms, and `fixed` when present is derived from the same final stream.
pub struct PatternBuf {
    /// Owned flat executable atom stream.
    atoms: Box<[Atom]>,

    /// Capture extent derived from `atoms`.
    save_len: usize,

    /// Owned fixed-width projection when the atoms are statically linear.
    fixed: Option<FixedBuf>,
}

impl PatternBuf {
    /// Take ownership of an atom sequence and derive its capture extent.
    ///
    /// # Errors
    ///
    /// This rejects an empty atom sequence.
    #[inline]
    pub fn from_atoms(target_atoms: impl Into<Vec<Atom>>) -> Result<Self, PatternError> {
        let atoms = target_atoms.into();
        let pattern = Pattern::from_atoms(&atoms)?;
        let save_len = pattern.save_len();
        let fixed = FixedBuf::compile(&atoms);
        let atoms = atoms.into_boxed_slice();

        Ok(Self {
            atoms,
            save_len,
            fixed,
        })
    }

    /// Parse Pelite-style executable syntax into one owned flat pattern.
    ///
    /// # Errors
    ///
    /// This returns the first located syntax failure without retaining partial parser state.
    #[inline]
    pub fn parse(target_pattern: &str) -> Result<Self, syntax::ParseError> {
        let atoms = syntax::parse(target_pattern)?;
        let save_len = Pattern::capture_len(&atoms);
        let fixed = FixedBuf::compile(&atoms);
        let atoms = atoms.into_boxed_slice();

        Ok(Self {
            atoms,
            save_len,
            fixed,
        })
    }

    /// Borrow this owned pattern without reparsing or copying its atom stream.
    #[inline]
    #[must_use]
    pub const fn as_pattern(&self) -> Pattern<'_> {
        let Self {
            atoms,
            save_len,
            fixed,
        } = self;
        let fixed = match fixed {
            Some(target_fixed) => Some(target_fixed.as_fixed()),
            None => None,
        };

        Pattern {
            atoms,
            save_len: *save_len,
            fixed,
        }
    }

    /// Borrow the owned flat atom stream.
    #[inline]
    #[must_use]
    pub fn atoms(&self) -> &[Atom] {
        let Self { atoms, .. } = self;

        atoms
    }

    /// Borrow derived fixed parts for companion procedural macro expansion.
    #[doc(hidden)]
    #[inline]
    #[must_use]
    pub fn fixed_parts(&self) -> Option<(&[u8], &[u8])> {
        let Self { fixed, .. } = self;
        let target_fixed = fixed.as_ref()?;

        Some((target_fixed.bytes(), target_fixed.masks()))
    }

    /// Return the complete capture-array width required by this pattern.
    #[inline]
    #[must_use]
    pub const fn save_len(&self) -> usize {
        let Self { save_len, .. } = self;

        *save_len
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
    //! Convenience imports for executable pattern construction and scanning.

    pub use super::scan::{Matches, Scanner};
    pub use super::syntax::{ParseError, ParseErrorKind, parse};
    pub use super::{Atom, Pattern, PatternBuf, PatternError, PointerWidth};
}

#[cfg(test)]
mod tests {
    //! Representation tests cover empty rejection and capture-width derivation.

    use super::*;

    #[test]
    fn pattern_derives_capture_extent_from_flat_atoms() {
        assert_eq!(Pattern::from_atoms(&[]), Err(PatternError::Empty));

        let atoms = [Atom::Save(0), Atom::ReadU32(7), Atom::Byte(0x90)];
        let pattern = Pattern::from_atoms(&atoms).expect("nonempty atom stream should be valid");

        assert_eq!(pattern.save_len(), 8);
        assert_eq!(pattern.atoms(), &atoms);
    }

    #[test]
    fn fixed_projection_is_derived_only_for_linear_patterns() {
        let fixed = PatternBuf::parse("41 ? 4? [2] 42").expect("fixed pattern should parse");
        let dynamic = PatternBuf::parse("41 [1-4] 42").expect("dynamic pattern should parse");

        assert!(fixed.fixed_parts().is_some());
        assert!(dynamic.fixed_parts().is_none());
    }
}

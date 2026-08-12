//! Representation-preserving text views for foreign byte data.
//!
//! This crate keeps original bytes authoritative while allowing optional textual interpretation.
//! It exists so process, image-format, and runtime-linker layers can share path-like data without
//! forcing UTF-8, ASCII, normalization, or lossy conversion.
#![deny(clippy::all, clippy::perf, clippy::nursery, clippy::pedantic)]
#![forbid(clippy::unwrap_used, clippy::panic, rustdoc::all)]
#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]

extern crate alloc;

use alloc::boxed::Box;
use core::{ops::Deref, str};

/// Owned path bytes with no required text encoding.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
// NOTE(invariant): The exact input bytes are retained without normalization or encoding conversion.
pub struct BytePath(Box<[u8]>);

impl BytePath {
    /// Copy path bytes into owned storage.
    #[inline]
    #[must_use]
    pub fn new(target_bytes: &[u8]) -> Self {
        Self(target_bytes.into())
    }

    /// Borrow the final slash-delimited path component.
    #[inline]
    #[must_use]
    pub fn basename(&self) -> &[u8] {
        let Self(bytes) = self;

        match bytes.rsplit(|target_byte| *target_byte == b'/').next() {
            Some(target_basename) => target_basename,
            None => bytes,
        }
    }

    /// Consume the path and return its exact bytes.
    #[inline]
    #[must_use]
    pub fn into_boxed_bytes(self) -> Box<[u8]> {
        let Self(bytes) = self;

        bytes
    }

    /// Inspect the path as UTF-8 without discarding its byte representation.
    #[inline]
    #[must_use]
    pub fn utf8(&self) -> MaybeUtf8<'_> {
        let Self(bytes) = self;

        MaybeUtf8::new(bytes)
    }

    /// Inspect the path as ASCII without discarding its byte representation.
    #[inline]
    #[must_use]
    pub fn ascii(&self) -> MaybeAscii<'_> {
        let Self(bytes) = self;

        MaybeAscii::new(bytes)
    }
}

impl Deref for BytePath {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &Self::Target {
        let Self(bytes) = self;

        bytes
    }
}

/// A borrowed byte sequence with an optional UTF-8 interpretation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// NOTE(invariant): The byte slice is always retained and the text view exists only when the complete slice is valid UTF-8.
pub struct MaybeUtf8<'text> {
    /// Original bytes retained regardless of UTF-8 validity.
    bytes: &'text [u8],

    /// Borrowed UTF-8 view when the complete byte sequence validates.
    text: Option<&'text str>,
}

impl<'text> MaybeUtf8<'text> {
    /// Classify a byte slice by UTF-8 validity.
    #[inline]
    #[must_use]
    pub fn new(target_bytes: &'text [u8]) -> Self {
        let text = str::from_utf8(target_bytes).ok();
        let original_bytes = target_bytes;

        Self {
            bytes: original_bytes,
            text,
        }
    }

    /// Borrow the original bytes.
    #[inline]
    #[must_use]
    pub const fn bytes(&self) -> &'text [u8] {
        let Self { bytes, .. } = self;

        bytes
    }

    /// Borrow the UTF-8 view when validation succeeded.
    #[inline]
    #[must_use]
    pub const fn text(&self) -> Option<&'text str> {
        let Self { text, .. } = self;

        *text
    }
}

/// A borrowed byte sequence with an optional ASCII interpretation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// NOTE(invariant): The byte slice is always retained and `ascii` is present exactly when every byte is in the ASCII range.
pub struct MaybeAscii<'text> {
    /// Original bytes retained regardless of ASCII validity.
    bytes: &'text [u8],

    /// Borrowed byte view when every byte belongs to the ASCII range.
    ascii: Option<&'text [u8]>,
}

impl<'text> MaybeAscii<'text> {
    /// Classify a byte slice by ASCII validity.
    #[inline]
    #[must_use]
    pub const fn new(bytes: &'text [u8]) -> Self {
        let is_ascii = bytes.is_ascii();

        let ascii = if is_ascii { Some(bytes) } else { None };

        Self { bytes, ascii }
    }

    /// Borrow the original bytes.
    #[inline]
    #[must_use]
    pub const fn bytes(&self) -> &'text [u8] {
        let Self { bytes, .. } = self;

        bytes
    }

    /// Borrow the bytes when the complete slice is ASCII.
    #[inline]
    #[must_use]
    pub const fn ascii(&self) -> Option<&'text [u8]> {
        let Self { ascii, .. } = self;

        *ascii
    }
}

pub mod prelude {
    //! Convenience imports for representation-preserving byte text.
    //!
    //! This module groups the crate's commonly used text-view boundary behind one import path. It
    //! introduces no encoding policy and leaves the original byte representation authoritative.

    pub use crate::{BytePath, MaybeAscii, MaybeUtf8};
}

#[cfg(test)]
mod tests {
    //! Regression coverage for byte preservation and optional text classification.

    use super::*;

    #[test]
    fn byte_path_preserves_non_utf8_bytes() {
        let path = BytePath::new(b"/tmp/lib\xff.so");
        let utf8 = path.utf8();

        assert_eq!(utf8.bytes(), b"/tmp/lib\xff.so");
        assert_eq!(utf8.text(), None);
        assert_eq!(path.basename(), b"lib\xff.so");
    }

    #[test]
    fn ascii_classification_retains_original_bytes() {
        let path = BytePath::new(b"kernel32.dll");
        let ascii = path.ascii();

        assert_eq!(ascii.bytes(), b"kernel32.dll");
        assert_eq!(ascii.ascii(), Some(b"kernel32.dll".as_slice()));
    }
}

//! Bounded byte scanning over explicit foreign process ranges.
//!
//! Callers choose target ranges while [`Scanner`] owns the reusable copy policy and scratch
//! storage. Process attachment and typed foreign access remain in `ganymede-process`.
#![deny(clippy::all, clippy::perf, clippy::nursery, clippy::pedantic)]
#![forbid(clippy::unwrap_used, clippy::panic, rustdoc::all)]
#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]

use core::{borrow::Borrow, num::NonZeroUsize};
use std::ffi::{CStr, CString};

use catalejo::{
    address::{ViAddr, ViRange},
    ffi::binding::virtual_offset_t,
    manage::Manage,
    offset::{Offset, Sparse},
    prelude::{Assemble, ByteCopyStatus, Foreign, Unassociated},
};
use ganymede_process::process::{AccessError, Process};
use memchr::memmem;

/// An exact runtime byte extent required from one foreign byte handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BytesLimit(usize);

impl BytesLimit {
    /// Construct an exact byte extent.
    #[inline]
    #[must_use]
    pub const fn new(limit: usize) -> Self {
        Self(limit)
    }

    /// Return the exact required byte extent.
    #[inline]
    #[must_use]
    pub const fn get(self) -> usize {
        let Self(limit) = self;

        limit
    }
}

/// Owned bytes assembled from one exact readable foreign byte span.
#[derive(Debug, Clone, PartialEq, Eq)]
// NOTE(invariant): The vector length equals the requested `BytesLimit` and contains bytes copied in order from the supplied foreign access.
pub struct Bytes(Vec<u8>);

impl Bytes {
    /// Borrow the assembled bytes.
    #[inline]
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        let Self(bytes) = self;

        bytes
    }

    /// Consume this assembled value into its owned bytes.
    #[inline]
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        let Self(bytes) = self;

        bytes
    }
}

/// Sparse byte displacement used to retain the starting foreign access as assembly provenance.
#[derive(Clone, Copy, Debug)]
#[repr(transparent)]
// NOTE(invariant): Every represented offset is a valid byte displacement and carries no local association.
struct ByteOffset(Offset);

// SAFETY Every Offset representation is a valid byte displacement and this marker has no local association.
unsafe impl Unassociated for ByteOffset {}

impl ByteOffset {
    /// Convert one host byte count into a target-width byte displacement.
    #[inline]
    fn new(target_offset: usize) -> Option<Self> {
        virtual_offset_t::try_from(target_offset)
            .ok()
            .map(Offset::byte)
            .map(Self)
    }
}

impl Sparse for ByteOffset {
    type Structure = u8;
    type Value = u8;

    #[inline]
    fn offset(target_value: impl Borrow<Self>) -> Offset {
        let &Self(target_offset) = target_value.borrow();

        target_offset
    }
}

impl Assemble for Bytes {
    type Value = u8;
    type Context = BytesLimit;
    type Error = ByteLiftError;

    #[inline]
    fn assemble_with<M>(
        target_manager: &M,
        target_handle: Foreign<Self::Value>,
        target_context: &Self::Context,
    ) -> Result<Self, Self::Error>
    where
        M: Manage,
    {
        let count = target_context.get();
        let mut bytes = Vec::with_capacity(count);
        let mut offset = 0_usize;

        loop {
            if offset >= count {
                break Ok(Self(bytes));
            }

            let target_offset = ByteOffset::new(offset).ok_or(ByteLiftError::Unavailable)?;
            let target_access = target_handle
                .sparse(target_offset)
                .ok_or(ByteLiftError::Unavailable)?;
            let target_foreign = target_manager
                .refresh(target_access)
                .ok_or(ByteLiftError::Unavailable)?;
            let requested = (count - offset).min(target_foreign.leftover().get());
            let copy = target_foreign
                .append(&mut bytes, requested)
                .ok_or(ByteLiftError::Unavailable)?;
            let copied = copy.copied();

            match copy.status() {
                ByteCopyStatus::Complete => {
                    offset = offset
                        .checked_add(copied)
                        .ok_or(ByteLiftError::Unavailable)?;
                }
                ByteCopyStatus::Faulted => break Err(ByteLiftError::Fault),
            }
        }
    }
}

/// A nonzero upper bound for one NUL-delimited foreign byte string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CBytesLimit(NonZeroUsize);

impl CBytesLimit {
    /// Construct a C-string bound that includes its required NUL terminator.
    #[inline]
    #[must_use]
    pub const fn new(bound: NonZeroUsize) -> Self {
        Self(bound)
    }

    /// Return the inclusive byte bound.
    #[inline]
    #[must_use]
    pub const fn get(self) -> NonZeroUsize {
        let Self(bound) = self;

        bound
    }
}

/// Owned NUL-delimited bytes acquired from a bounded foreign byte span.
#[derive(Debug, Clone, PartialEq, Eq)]
// NOTE(invariant): The contained CString ends at the first NUL observed within the requested foreign byte bound.
pub struct CBytes(CString);

impl CBytes {
    /// Borrow the assembled C string including its NUL terminator.
    #[inline]
    #[must_use]
    pub fn as_c_str(&self) -> &CStr {
        let Self(bytes) = self;

        bytes.as_c_str()
    }

    /// Borrow the assembled bytes without the NUL terminator.
    #[inline]
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        Self::as_c_str(self).to_bytes()
    }

    /// Consume this assembled value into its owned C string.
    #[inline]
    #[must_use]
    pub fn into_c_string(self) -> CString {
        let Self(bytes) = self;

        bytes
    }
}

impl Assemble for CBytes {
    type Value = u8;
    type Context = CBytesLimit;
    type Error = ByteLiftError;

    #[inline]
    fn assemble_with<M>(
        target_manager: &M,
        target_handle: Foreign<Self::Value>,
        target_context: &Self::Context,
    ) -> Result<Self, Self::Error>
    where
        M: Manage,
    {
        let limit = target_context.get().get();
        let mut bytes = Vec::with_capacity(limit);
        let mut offset = 0_usize;

        loop {
            if offset >= limit {
                break Err(ByteLiftError::MissingTerminator);
            }

            let target_offset = ByteOffset::new(offset).ok_or(ByteLiftError::Unavailable)?;
            let target_access = target_handle
                .sparse(target_offset)
                .ok_or(ByteLiftError::Unavailable)?;
            let target_foreign = target_manager
                .refresh(target_access)
                .ok_or(ByteLiftError::Unavailable)?;
            let requested = (limit - offset).min(target_foreign.leftover().get());
            let original_length = bytes.len();
            let copy = target_foreign
                .append(&mut bytes, requested)
                .ok_or(ByteLiftError::Unavailable)?;
            let copied = copy.copied();
            let terminator = copy.bytes().iter().position(|byte| *byte == 0);
            let status = copy.status();

            match (terminator, status) {
                (Some(terminator), _) => {
                    bytes.truncate(original_length + terminator + 1);

                    // SAFETY: `terminator` is the first NUL in the retained byte prefix and
                    // truncation retains it as the final byte.
                    break Ok(Self(unsafe { CString::from_vec_with_nul_unchecked(bytes) }));
                }
                (None, ByteCopyStatus::Complete) => {
                    offset = offset
                        .checked_add(copied)
                        .ok_or(ByteLiftError::Unavailable)?;
                }
                (None, ByteCopyStatus::Faulted) => break Err(ByteLiftError::Fault),
            }
        }
    }
}

/// Failure while acquiring one foreign byte representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, fack::prelude::Error)]
pub enum ByteLiftError {
    /// Managed foreign access cannot represent the requested byte span.
    #[error("foreign byte span is unavailable")]
    Unavailable,

    /// Catalejo's protected byte copy faulted.
    #[error("foreign byte copy faulted")]
    Fault,

    /// No NUL byte occurred in the available C-string extent.
    #[error("foreign C string has no terminator in its available extent")]
    MissingTerminator,
}

/// Reusable scanner over explicit foreign process ranges.
///
/// One scanner retains the caller-selected copy bound and one scratch allocation across scans.
/// Every scan still receives its exact process, ranges, and needle so the scanner owns no process
/// lifetime or address-space policy.
#[derive(Debug)]
pub struct Scanner {
    /// Maximum bytes copied into local storage for one scan step.
    copy_size: NonZeroUsize,

    /// Reusable local storage filled from foreign memory before local matching.
    buffer: Vec<u8>,
}

impl Scanner {
    /// Construct a scanner with one nonzero foreign copy bound.
    #[inline]
    #[must_use]
    pub fn new(copy_size: NonZeroUsize) -> Self {
        let buffer = Vec::with_capacity(copy_size.get());

        Self { copy_size, buffer }
    }

    /// Return the maximum bytes copied for one scan step.
    #[inline]
    #[must_use]
    pub const fn copy_size(&self) -> NonZeroUsize {
        let Self { copy_size, .. } = self;

        *copy_size
    }

    /// Scan explicit process ranges for one nonempty byte sequence.
    ///
    /// The retained copy size must be at least the needle length so every candidate start can be
    /// decided from one copied window. Empty needles produce no matches.
    ///
    /// # Errors
    ///
    /// This returns [`ScanError::CopyTooSmall`] when the retained copy size cannot contain the
    /// needle. Foreign access, protected copy faults, and checked address overflow are preserved.
    #[inline]
    pub fn bytes(
        &mut self,
        process: &Process,
        ranges: &[ViRange],
        needle: &[u8],
    ) -> Result<Vec<ViAddr>, ScanError> {
        let Self { copy_size, buffer } = self;
        let copy_size = copy_size.get();
        let empty = needle.is_empty();
        let fits = needle.len() <= copy_size;

        match (empty, fits) {
            (true, _) => Ok(Vec::new()),
            (false, false) => Err(ScanError::CopyTooSmall {
                copy_size,
                needle_size: needle.len(),
            }),
            (false, true) => {
                let overlap = needle.len().saturating_sub(1);
                let step = copy_size.saturating_sub(overlap);
                let mut matches = Vec::new();

                for range in ranges {
                    Self::scan_range(
                        process,
                        *range,
                        needle,
                        copy_size,
                        step,
                        buffer,
                        &mut matches,
                    )?;
                }

                matches.sort_unstable();
                matches.dedup();

                Ok(matches)
            }
        }
    }

    /// Scan one range while reusing the scanner scratch storage.
    fn scan_range(
        process: &Process,
        range: ViRange,
        needle: &[u8],
        copy_size: usize,
        step: usize,
        buffer: &mut Vec<u8>,
        matches: &mut Vec<ViAddr>,
    ) -> Result<(), ScanError> {
        let size = range.size().map_or(0, NonZeroUsize::get);
        let mut offset = 0_usize;

        while offset < size {
            let remaining = size.saturating_sub(offset);
            let count = remaining.min(copy_size);
            let address = Self::address_at(range.start_address, offset)?;

            Self::copy_bytes(process, address, count, buffer)?;

            let candidate_end = if remaining > copy_size { step } else { count };

            Self::push_matches(
                range.start_address,
                offset,
                buffer,
                needle,
                candidate_end,
                matches,
            )?;

            offset = offset
                .checked_add(step)
                .ok_or(ScanError::AddressOverflow(range.start_address))?;
        }

        Ok(())
    }

    /// Translate local matches whose starts belong to the current candidate span.
    fn push_matches(
        range_start: ViAddr,
        chunk_offset: usize,
        buffer: &[u8],
        needle: &[u8],
        candidate_end: usize,
        matches: &mut Vec<ViAddr>,
    ) -> Result<(), ScanError> {
        for match_offset in memmem::find_iter(buffer, needle) {
            if match_offset >= candidate_end {
                break;
            }

            let absolute_offset = chunk_offset
                .checked_add(match_offset)
                .ok_or(ScanError::AddressOverflow(range_start))?;
            let address = Self::address_at(range_start, absolute_offset)?;

            matches.push(address);
        }

        Ok(())
    }

    /// Refill scanner scratch storage from one exact foreign byte span.
    fn copy_bytes(
        process: &Process,
        address: ViAddr,
        count: usize,
        buffer: &mut Vec<u8>,
    ) -> Result<(), ScanError> {
        let foreign = Process::open::<u8>(process, address)?;
        let bytes = foreign
            .assemble_with::<Bytes, _>(process, &BytesLimit::new(count))
            .map_err(ScanError::Bytes)?;

        buffer.clear();
        buffer.extend_from_slice(bytes.as_bytes());
        Ok(())
    }

    /// Add one host byte offset to a process virtual address.
    fn address_at(address: ViAddr, offset: usize) -> Result<ViAddr, ScanError> {
        let ViAddr(base_address) = address;
        let offset = u64::try_from(offset).map_err(|_| ScanError::AddressOverflow(address))?;

        base_address
            .checked_add(offset)
            .map(ViAddr::new)
            .ok_or(ScanError::AddressOverflow(address))
    }
}

/// Failure while scanning explicit foreign process ranges.
#[derive(Debug, fack::prelude::Error)]
pub enum ScanError {
    /// The retained copy size cannot contain one complete needle.
    #[error("scan copy size {copy_size} is smaller than needle size {needle_size}")]
    CopyTooSmall {
        /// Scanner copy size.
        copy_size: usize,

        /// Required needle byte length.
        needle_size: usize,
    },

    /// Typed foreign access could not be opened.
    #[error(transparent(0))]
    Access(AccessError),

    /// Managed foreign byte assembly failed.
    #[error(transparent(0))]
    Bytes(ByteLiftError),

    /// Checked process virtual address progression overflowed.
    #[error("scan address overflow from {0:?}")]
    AddressOverflow(ViAddr),
}

impl From<AccessError> for ScanError {
    #[inline]
    fn from(source: AccessError) -> Self {
        Self::Access(source)
    }
}

pub mod prelude {
    //! This is the `ganymede-scan` prelude.
    //!
    //! It re-exports the scanner and its structural failure type.

    pub use crate::{ByteLiftError, Bytes, BytesLimit, CBytes, CBytesLimit, ScanError, Scanner};
}

#[cfg(test)]
mod tests {
    use super::*;
    use ganymede_process::process::{Process, ProcessId};

    #[test]
    fn match_crossing_copy_boundary_is_emitted_by_next_window() {
        let range_start = ViAddr::new(0x1000);
        let needle = b"abcd";
        let copy_size = 8_usize;
        let overlap = needle.len() - 1;
        let step = copy_size - overlap;
        let source = b"xxxxxxabcdyy";
        let mut matches = Vec::new();

        Scanner::push_matches(
            range_start,
            0,
            &source[..copy_size],
            needle,
            step,
            &mut matches,
        )
        .expect("first local match translation should succeed");
        Scanner::push_matches(
            range_start,
            step,
            &source[step..],
            needle,
            source.len() - step,
            &mut matches,
        )
        .expect("second local match translation should succeed");

        assert_eq!(matches, [ViAddr::new(0x1006)]);
    }

    #[test]
    fn overlap_candidate_is_emitted_exactly_once_across_adjacent_windows() {
        let range_start = ViAddr::new(0x2000);
        let needle = b"abc";
        let copy_size = 8_usize;
        let overlap = needle.len() - 1;
        let step = copy_size - overlap;
        let source = b"xxabcxabczz";
        let mut matches = Vec::new();

        Scanner::push_matches(
            range_start,
            0,
            &source[..copy_size],
            needle,
            step,
            &mut matches,
        )
        .expect("first local match translation should succeed");
        Scanner::push_matches(
            range_start,
            step,
            &source[step..],
            needle,
            source.len() - step,
            &mut matches,
        )
        .expect("second local match translation should succeed");

        assert_eq!(matches, [ViAddr::new(0x2002), ViAddr::new(0x2006)]);
    }

    #[test]
    fn final_partial_window_emits_tail_match() {
        let range_start = ViAddr::new(0x3000);
        let needle = b"abcd";
        let source = b"xxabcd";
        let mut matches = Vec::new();

        Scanner::push_matches(range_start, 0, source, needle, source.len(), &mut matches)
            .expect("final local match translation should succeed");

        assert_eq!(matches, [ViAddr::new(0x3002)]);
    }

    #[test]
    #[ignore = "requires the mirilla device"]
    fn assembles_bytes_across_a_managed_window_boundary() {
        let process =
            Process::new(ProcessId(std::process::id())).expect("the current process should engage");
        let granule = usize::try_from(process.granule().size())
            .expect("the manager granule should fit host address width");
        let source = vec![0x5a_u8; granule * 2 + 64];
        let base = virtual_offset_t::try_from(source.as_ptr().expose_provenance())
            .expect("the source pointer should fit target address width");
        let granule = virtual_offset_t::try_from(granule)
            .expect("the manager granule should fit target address width");
        let boundary = base
            .checked_add(granule)
            .expect("the next granule should be representable")
            & !(granule - 1);
        let start = boundary - 8;
        let start_index = usize::try_from(start - base)
            .expect("the cross-window source offset should fit host width");
        let expected = &source[start_index..start_index + 32];
        let foreign = process
            .open::<u8>(ViAddr::new(start))
            .expect("the cross-window origin should open");
        let observed = foreign
            .assemble_with::<Bytes, _>(&process, &BytesLimit::new(expected.len()))
            .expect("assembly should refresh access across the window boundary");

        assert_eq!(observed.as_bytes(), expected);
    }

    #[test]
    #[ignore = "requires the mirilla device"]
    fn assembles_c_bytes_across_a_managed_window_boundary() {
        let process =
            Process::new(ProcessId(std::process::id())).expect("the current process should engage");
        let granule = usize::try_from(process.granule().size())
            .expect("the manager granule should fit host address width");
        let mut source = vec![b'x'; granule * 2 + 64];
        let base = virtual_offset_t::try_from(source.as_ptr().expose_provenance())
            .expect("the source pointer should fit target address width");
        let granule = virtual_offset_t::try_from(granule)
            .expect("the manager granule should fit target address width");
        let boundary = base
            .checked_add(granule)
            .expect("the next granule should be representable")
            & !(granule - 1);
        let start = boundary - 3;
        let start_index = usize::try_from(start - base)
            .expect("the cross-window source offset should fit host width");
        let source_text = b"abcdef\0";

        source[start_index..start_index + source_text.len()].copy_from_slice(source_text);

        let foreign = process
            .open::<u8>(ViAddr::new(start))
            .expect("the cross-window origin should open");
        let limit = NonZeroUsize::new(source_text.len()).expect("the test bound should be nonzero");
        let observed = foreign
            .assemble_with::<CBytes, _>(&process, &CBytesLimit::new(limit))
            .expect("C-string assembly should refresh access across the window boundary");

        assert_eq!(observed.as_bytes(), b"abcdef");
    }
}

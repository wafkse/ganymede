//! Private fixed-width projection and search planning.
//!
//! A unified pattern may carry this derived representation when every atom has fixed linear byte
//! semantics. The projection exists only to accelerate candidate discovery and verification.

extern crate alloc;

use alloc::{boxed::Box, vec::Vec};

use super::Atom;

mod plan;
pub(super) mod scan;

use plan::SearchPlan;

/// One masked byte selected for candidate filtering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// NOTE(invariant): `mask` is nonzero and `offset` lies within the fixed projection that produced this probe.
pub(super) struct Probe {
    /// Byte offset from a candidate start.
    pub(super) offset: usize,

    /// Canonical constrained byte value.
    pub(super) value: u8,

    /// Bits participating in comparison.
    pub(super) mask: u8,
}

/// Borrowed fixed projection of one executable pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// NOTE(invariant): `bytes` and `masks` are nonempty and equal in length, and `plan` was derived from those exact slices.
pub struct Fixed<'pattern> {
    /// Canonical byte values.
    bytes: &'pattern [u8],

    /// Canonical per-byte masks.
    masks: &'pattern [u8],

    /// Candidate-discovery strategy.
    plan: SearchPlan,
}
impl<'pattern> Fixed<'pattern> {
    /// Construct a fixed projection from validated static parts.
    #[inline]
    pub(super) const fn new(target_bytes: &'pattern [u8], target_masks: &'pattern [u8]) -> Self {
        let plan = SearchPlan::compile(target_bytes, target_masks);

        Self {
            bytes: target_bytes,
            masks: target_masks,
            plan,
        }
    }

    /// Validate that static fixed parts are exactly derived from one atom stream.
    pub(super) const fn valid_for(
        target_atoms: &[Atom],
        target_bytes: &[u8],
        target_masks: &[u8],
    ) -> bool {
        if target_atoms.is_empty()
            || target_bytes.is_empty()
            || target_bytes.len() != target_masks.len()
            || !matches!(target_atoms[0], Atom::Save(0))
        {
            return false;
        }

        let mut atom_index = 0usize;
        let mut byte_index = 0usize;
        let mut mask = u8::MAX;

        while atom_index < target_atoms.len() {
            match target_atoms[atom_index] {
                Atom::Save(0) if atom_index == 0 => {}
                Atom::Nop => {}
                Atom::Fuzzy(target_mask) if mask == u8::MAX => mask = target_mask,
                Atom::Byte(target_byte) => {
                    if byte_index >= target_bytes.len()
                        || target_bytes[byte_index] != target_byte & mask
                        || target_masks[byte_index] != mask
                    {
                        return false;
                    }

                    byte_index += 1;
                    mask = u8::MAX;
                }
                Atom::Skip(target_skip) if target_skip != 0 && mask == u8::MAX => {
                    let Some(target_end) = byte_index.checked_add(target_skip) else {
                        return false;
                    };

                    if target_end > target_bytes.len() {
                        return false;
                    }

                    while byte_index < target_end {
                        if target_bytes[byte_index] != 0 || target_masks[byte_index] != 0 {
                            return false;
                        }

                        byte_index += 1;
                    }
                }
                _ => return false,
            }

            atom_index += 1;
        }

        byte_index == target_bytes.len() && mask == u8::MAX
    }

    /// Return the projection width.
    #[inline]
    pub(super) const fn len(&self) -> usize {
        let Self { bytes, .. } = self;

        bytes.len()
    }

    /// Borrow canonical byte values.
    #[inline]
    pub(super) const fn bytes(&self) -> &'pattern [u8] {
        let Self { bytes, .. } = self;

        bytes
    }

    /// Borrow canonical masks.
    #[inline]
    pub(super) const fn masks(&self) -> &'pattern [u8] {
        let Self { masks, .. } = self;

        masks
    }

    /// Return the derived search plan.
    #[inline]
    pub(super) const fn plan(&self) -> SearchPlan {
        let Self { plan, .. } = self;

        *plan
    }
    /// Borrow the exact anchor selected by the search plan.
    #[inline]
    pub(super) fn anchor(&self) -> Option<&'pattern [u8]> {
        let Self { bytes, plan, .. } = self;

        match *plan {
            SearchPlan::Literal => Some(bytes),
            SearchPlan::Anchor { offset, length } => bytes.get(offset..offset + length),
            SearchPlan::Probes { .. } | SearchPlan::Wildcard => None,
        }
    }

    /// Verify one same-width candidate against every constrained bit.
    #[inline]
    pub(super) fn matches(&self, target_bytes: &[u8]) -> bool {
        let Self { bytes, masks, .. } = self;

        target_bytes.len() == bytes.len()
            && bytes.iter().zip(masks.iter()).zip(target_bytes.iter()).all(
                |((&target_pattern, &target_mask), &target_byte)| {
                    ((target_byte ^ target_pattern) & target_mask) == 0
                },
            )
    }
}

/// Owned fixed projection retained by a runtime-compiled pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
// NOTE(invariant): `bytes` and `masks` are nonempty and equal in length, and `plan` was derived after those arrays reached their final contents.
pub(super) struct FixedBuf {
    /// Canonical byte values.
    bytes: Box<[u8]>,

    /// Canonical per-byte masks.
    masks: Box<[u8]>,

    /// Candidate-discovery strategy.
    plan: SearchPlan,
}

impl FixedBuf {
    /// Derive a fixed projection when the atom stream has linear fixed-width semantics.
    pub(super) fn compile(target_atoms: &[Atom]) -> Option<Self> {
        if !matches!(target_atoms.first(), Some(Atom::Save(0))) {
            return None;
        }

        let width = Self::width(target_atoms)?;
        let mut bytes = Vec::with_capacity(width);
        let mut masks = Vec::with_capacity(width);
        let mut mask = u8::MAX;

        for (target_index, target_atom) in target_atoms.iter().enumerate() {
            match *target_atom {
                Atom::Save(0) if target_index == 0 => {}
                Atom::Nop => {}
                Atom::Fuzzy(target_mask) => mask = target_mask,
                Atom::Byte(target_byte) => {
                    bytes.push(target_byte & mask);
                    masks.push(mask);
                    mask = u8::MAX;
                }
                Atom::Skip(target_skip) if target_skip != 0 => {
                    let next = bytes.len().checked_add(target_skip)?;
                    bytes.resize(next, 0);
                    masks.resize(next, 0);
                    mask = u8::MAX;
                }
                _ => return None,
            }
        }

        if bytes.is_empty() || mask != u8::MAX {
            return None;
        }

        let plan = SearchPlan::compile(&bytes, &masks);
        let bytes = bytes.into_boxed_slice();
        let masks = masks.into_boxed_slice();

        Some(Self { bytes, masks, plan })
    }

    /// Borrow the fixed projection without rebuilding its search plan.
    #[inline]
    pub(super) const fn as_fixed(&self) -> Fixed<'_> {
        let Self { bytes, masks, plan } = self;

        Fixed {
            bytes,
            masks,
            plan: *plan,
        }
    }

    /// Return the fixed width when every atom is eligible for optimized projection.
    fn width(target_atoms: &[Atom]) -> Option<usize> {
        let mut width = 0usize;
        let mut fuzzy = false;

        for (target_index, target_atom) in target_atoms.iter().enumerate() {
            match *target_atom {
                Atom::Save(0) if target_index == 0 => {}
                Atom::Nop => {}
                Atom::Fuzzy(..) if !fuzzy => fuzzy = true,
                Atom::Byte(..) => {
                    width = width.checked_add(1)?;
                    fuzzy = false;
                }
                Atom::Skip(target_skip) if target_skip != 0 && !fuzzy => {
                    width = width.checked_add(target_skip)?;
                }
                _ => return None,
            }
        }

        (!fuzzy && width != 0).then_some(width)
    }

    /// Borrow the canonical bytes for static macro emission.
    #[inline]
    pub(super) fn bytes(&self) -> &[u8] {
        let Self { bytes, .. } = self;

        bytes
    }

    /// Borrow the canonical masks for static macro emission.
    #[inline]
    pub(super) fn masks(&self) -> &[u8] {
        let Self { masks, .. } = self;

        masks
    }
}

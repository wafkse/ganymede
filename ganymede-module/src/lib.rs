//! Format-neutral loaded-module domain layer.
//!
//! This crate normalizes loaded-image identity from process mappings without importing executable
//! format or runtime-linker representations. Backend crates contribute already-proven process
//! anchors and exact names, while this layer owns mapping membership and common lookup semantics.
#![deny(clippy::all, clippy::perf, clippy::nursery, clippy::pedantic)]
#![forbid(clippy::unwrap_used, clippy::panic, rustdoc::all)]
#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]

extern crate alloc;

use alloc::{boxed::Box, vec::Vec};

use catalejo::address::ViAddr;
use ganymede_process::process::{Backing, FileIdentity, Region, Snapshot};
use ganymede_text::BytePath;

/// Format-neutral observation of one loaded image.
#[derive(Debug, Clone, PartialEq, Eq)]
// NOTE(invariant): `mappings` is nonempty, sorted, internally nonoverlapping, and every file-backed mapping carries the same retained file identity.
pub struct Module {
    /// Exact loader-provided module name bytes.
    name: BytePath,

    /// Process mappings proven to belong to this module observation.
    mappings: Box<[Region]>,

    /// Shared file identity when at least one retained mapping is file-backed.
    file_identity: Option<FileIdentity>,
}

impl Module {
    /// Normalize one module from a process address known to belong to the loaded image.
    ///
    /// The containing kernel mapping is retained as the initial proven mapping set. Additional
    /// mappings should only be supplied through a future backend proof rather than inferred from
    /// matching path or inode values.
    ///
    /// # Errors
    ///
    /// This returns [`NormalizeError::MissingAnchor`] when the supplied address is absent from the
    /// process snapshot.
    #[inline]
    pub fn from_anchor(
        target_snapshot: &Snapshot,
        target_name: BytePath,
        target_anchor: ViAddr,
    ) -> Result<Self, NormalizeError> {
        let mapping = Snapshot::region_at(target_snapshot, target_anchor)
            .copied()
            .ok_or(NormalizeError::MissingAnchor(target_anchor))?;
        let mappings = [mapping];

        Self::from_mappings(target_name, mappings)
    }

    /// Normalize one module from mappings already proven by a backend to belong together.
    ///
    /// # Errors
    ///
    /// This rejects an empty mapping set, overlapping retained mappings, or conflicting file
    /// identities among file-backed mappings.
    #[inline]
    pub fn from_mappings(
        target_name: BytePath,
        target_mappings: impl IntoIterator<Item = Region>,
    ) -> Result<Self, NormalizeError> {
        let mut mappings = target_mappings.into_iter().collect::<Vec<_>>();

        mappings.sort_unstable_by_key(Region::range);

        let nonempty = !mappings.is_empty();
        let nonoverlap = mappings
            .windows(2)
            .all(|target_window| match target_window {
                [left, right] => {
                    Region::range(left).end_address <= Region::range(right).start_address
                }
                _ => true,
            });

        match (nonempty, nonoverlap) {
            (true, true) => Ok(()),
            (false, _) => Err(NormalizeError::EmptyMappings),
            (true, false) => Err(NormalizeError::OverlappingMappings),
        }?;

        let mut file_identity = None;

        mappings.iter().try_for_each(|target_mapping| {
            let identity = match Region::backing(target_mapping) {
                Backing::File(target_backing) => Some(target_backing.identity()),
                Backing::Anonymous | Backing::Special => None,
            };

            match (file_identity, identity) {
                (None, Some(identity)) => {
                    file_identity = Some(identity);
                    Ok(())
                }
                (Some(existing), Some(identity)) => {
                    if existing == identity {
                        Ok(())
                    } else {
                        Err(NormalizeError::ConflictingFileIdentity)
                    }
                }
                (_, None) => Ok(()),
            }
        })?;

        let name = target_name;
        let mappings = mappings.into_boxed_slice();

        Ok(Self {
            name,
            mappings,
            file_identity,
        })
    }

    /// Borrow the exact module name bytes.
    #[inline]
    #[must_use]
    pub const fn name(&self) -> &BytePath {
        let Self { name, .. } = self;

        name
    }

    /// Borrow the process mappings proven to belong to this module.
    #[inline]
    #[must_use]
    pub fn mappings(&self) -> &[Region] {
        let Self { mappings, .. } = self;

        mappings
    }

    /// Return the common file identity when the retained mappings establish one.
    #[inline]
    #[must_use]
    pub const fn file_identity(&self) -> Option<FileIdentity> {
        let Self { file_identity, .. } = self;

        *file_identity
    }

    /// Determine whether any retained mapping contains the supplied process address.
    #[inline]
    #[must_use]
    pub fn contains(&self, target_address: ViAddr) -> bool {
        let Self { mappings, .. } = self;

        mappings
            .iter()
            .any(|target_mapping| Region::contains(target_mapping, target_address))
    }

    /// Determine whether the complete module name equals the supplied bytes.
    #[inline]
    #[must_use]
    pub fn has_full_name(&self, target_name: &[u8]) -> bool {
        let Self { name, .. } = self;

        &**name == target_name
    }

    /// Determine whether the final path component equals the supplied bytes.
    #[inline]
    #[must_use]
    pub fn has_basename(&self, target_name: &[u8]) -> bool {
        let Self { name, .. } = self;

        BytePath::basename(name) == target_name
    }
}

/// Owned normalized module collection with unambiguous retained mapping ownership.
#[derive(Debug, Clone, PartialEq, Eq)]
// NOTE(invariant): No retained mapping range overlaps a mapping retained by another module, so address lookup has at most one result.
pub struct Modules(Box<[Module]>);

impl Modules {
    /// Construct a normalized module collection and prove retained mapping ownership is unambiguous.
    ///
    /// # Errors
    ///
    /// This rejects overlap between mappings retained by distinct modules.
    #[inline]
    pub fn new(target_modules: impl IntoIterator<Item = Module>) -> Result<Self, NormalizeError> {
        let modules = target_modules.into_iter().collect::<Vec<_>>();
        let mut ranges = modules
            .iter()
            .enumerate()
            .flat_map(|(target_module_index, target_module)| {
                Module::mappings(target_module)
                    .iter()
                    .map(move |target_mapping| (Region::range(target_mapping), target_module_index))
            })
            .collect::<Vec<_>>();

        ranges.sort_unstable_by_key(|(target_range, _)| *target_range);

        let unambiguous = ranges.windows(2).all(|target_window| match target_window {
            [(left_range, left_module), (right_range, right_module)] => {
                let is_same_module = left_module == right_module;
                let is_disjoint = left_range.end_address <= right_range.start_address;

                is_same_module || is_disjoint
            }
            _ => true,
        });

        if unambiguous {
            Ok(Self(modules.into_boxed_slice()))
        } else {
            Err(NormalizeError::AmbiguousMappingOwnership)
        }
    }

    /// Borrow normalized modules in backend-supplied order.
    #[inline]
    #[must_use]
    pub fn modules(&self) -> &[Module] {
        let Self(modules) = self;

        modules
    }

    /// Find the normalized module containing one retained process address.
    #[inline]
    #[must_use]
    pub fn module_at(&self, target_address: ViAddr) -> Option<&Module> {
        let Self(modules) = self;

        modules
            .iter()
            .find(|target_module| Module::contains(target_module, target_address))
    }

    /// Find the first module with an exact full name.
    #[inline]
    #[must_use]
    pub fn find_by_full_name(&self, target_name: &[u8]) -> Option<&Module> {
        let Self(modules) = self;

        modules
            .iter()
            .find(|target_module| Module::has_full_name(target_module, target_name))
    }

    /// Find the first module with a matching final path component.
    #[inline]
    #[must_use]
    pub fn find_by_basename(&self, target_name: &[u8]) -> Option<&Module> {
        let Self(modules) = self;

        modules
            .iter()
            .find(|target_module| Module::has_basename(target_module, target_name))
    }
}

/// Failure while constructing format-neutral module observations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, fack::prelude::Error)]
pub enum NormalizeError {
    /// A backend-supplied image anchor is not mapped in the process snapshot.
    #[error("module anchor is not mapped at {0:?}")]
    MissingAnchor(ViAddr),

    /// A module was constructed without any proven process mapping.
    #[error("module normalization requires at least one proven mapping")]
    EmptyMappings,

    /// Backend-supplied mappings overlap inside one normalized module.
    #[error("module normalization received overlapping mappings")]
    OverlappingMappings,

    /// File-backed mappings supplied for one module disagree on backing identity.
    #[error("module normalization received conflicting file identities")]
    ConflictingFileIdentity,

    /// Distinct normalized modules claim overlapping process mappings.
    #[error("normalized modules have ambiguous mapping ownership")]
    AmbiguousMappingOwnership,
}

pub mod prelude {
    //! Convenience imports for normalized loaded-module observations.
    //!
    //! This module exposes only format-neutral module and mapping concepts. Backend protocol types
    //! remain in their originating crates and must cross this boundary through validated inputs.

    pub use crate::{Module, Modules, NormalizeError};
}

#[cfg(test)]
mod tests {
    //! Regression coverage for normalized address and name lookup over real process regions.

    use super::*;
    use ganymede_process::process::Process;

    /// Extract one successful test result without unwrap-family shortcuts.
    fn test_ok<T, E: core::fmt::Debug>(target_result: Result<T, E>) -> T {
        target_result.expect("test operation should succeed")
    }

    #[test]
    #[ignore = "requires the mirilla kernel module to be loaded"]
    fn anchor_normalization_retains_address_membership() {
        let process = test_ok(Process::new(ganymede_process::process::ProcessId(
            std::process::id(),
        )));
        let snapshot = test_ok(process.snapshot());
        let anchor = ViAddr::new(
            anchor_normalization_retains_address_membership as *const () as usize as u64,
        );
        let module = test_ok(Module::from_anchor(
            &snapshot,
            BytePath::new(b"self"),
            anchor,
        ));
        let modules = test_ok(Modules::new([module]));

        assert!(modules.module_at(anchor).is_some());
        assert!(modules.find_by_full_name(b"self").is_some());
    }
}

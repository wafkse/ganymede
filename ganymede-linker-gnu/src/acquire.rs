//! Shared acquisition proof values for GNU snapshots.
//!
//! These values carry facts that are independent of ELF address width. Width-specific readers use
//! them without sharing pointer arithmetic or generated ABI interpretation.

extern crate alloc;

use alloc::{boxed::Box, vec::Vec};
use ganymede_process::process::{Process, Snapshot};
use ganymede_text::BytePath;

/// Process observation context shared by one complete GNU snapshot attempt.
#[derive(Debug, Clone, Copy)]
// NOTE(invariant): `process` and `snapshot` are caller-provided views of the same selected target for the complete attempt.
pub struct Target<'target> {
    /// Attached process used for foreign reads.
    process: &'target Process,

    /// Kernel process snapshot used for process metadata.
    snapshot: &'target Snapshot,
}

impl<'target> Target<'target> {
    /// Bind one process handle and kernel snapshot to a complete acquisition attempt.
    #[inline]
    #[must_use]
    pub const fn new(target_process: &'target Process, target_snapshot: &'target Snapshot) -> Self {
        Self {
            process: target_process,
            snapshot: target_snapshot,
        }
    }

    /// Return the attached process.
    #[inline]
    #[must_use]
    pub const fn process(&self) -> &'target Process {
        let Self { process, .. } = self;

        process
    }

    /// Return the kernel process snapshot.
    #[inline]
    #[must_use]
    pub const fn snapshot(&self) -> &'target Snapshot {
        let Self { snapshot, .. } = self;

        snapshot
    }
}

/// Interpreter path proven to identify the required GNU loader profile.
#[derive(Debug, Clone, PartialEq, Eq)]
// NOTE(invariant): Construction succeeds only when the final path component equals the caller-selected GNU interpreter basename.
pub struct Interpreter(BytePath);

impl Interpreter {
    /// Validate and retain one exact interpreter path.
    #[inline]
    pub fn new(target_path: BytePath, target_basename: &[u8]) -> Result<Self, BytePath> {
        let is_supported = target_path.basename() == target_basename;

        if !is_supported {
            return Err(target_path);
        }

        Ok(Self(target_path))
    }

    /// Consume the proof and return the exact path bytes.
    #[inline]
    #[must_use]
    pub fn finish(self) -> BytePath {
        let Self(path) = self;

        path
    }
}

/// Paired public module and stable ABI-node observations from one forward walk.
#[derive(Debug)]
// NOTE(invariant): Each retained pair describes the same `AbiType` link-map position, so module and stable-node cardinality or ABI identity cannot diverge.
pub struct Walk<AbiType>(
    /// Forward-order paired observations.
    Vec<(
        crate::snapshot::model::Module<AbiType>,
        crate::model::LinkMapRecord<AbiType>,
    )>,
)
where
    AbiType: crate::abi::Abi;

impl<AbiType> Walk<AbiType>
where
    AbiType: crate::abi::Abi,
{
    /// Retain paired forward observations.
    #[inline]
    #[must_use]
    pub const fn new(
        target_steps: Vec<(
            crate::snapshot::model::Module<AbiType>,
            crate::model::LinkMapRecord<AbiType>,
        )>,
    ) -> Self {
        Self(target_steps)
    }

    /// Iterate paired observations in forward order.
    #[inline]
    pub fn iter(
        &self,
    ) -> impl DoubleEndedIterator<
        Item = (
            &crate::snapshot::model::Module<AbiType>,
            &crate::model::LinkMapRecord<AbiType>,
        ),
    > {
        let Self(steps) = self;

        steps
            .iter()
            .map(|(target_module, target_node)| (target_module, target_node))
    }

    /// Consume the proof and retain only public module observations.
    #[inline]
    #[must_use]
    pub fn finish(self) -> Box<[crate::snapshot::model::Module<AbiType>]> {
        let Self(steps) = self;

        steps
            .into_iter()
            .map(|(target_module, _target_node)| target_module)
            .collect::<Vec<_>>()
            .into_boxed_slice()
    }
}

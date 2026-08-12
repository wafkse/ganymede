//! Finite resource policy for GNU runtime-linker snapshot acquisition.
//!
//! This module centralizes bounds for foreign-table inspection, graph traversal, string acquisition,
//! and stability retries. The policy prevents malformed or continuously changing process state from
//! turning inspection into unbounded work.

use core::num::NonZeroUsize;

/// Default GNU program-header bound.
const GNU_PROGRAM_HEADERS: NonZeroUsize =
    const { NonZeroUsize::new(4096).expect("GNU program-header limit must be nonzero") };

/// Default GNU dynamic-entry bound.
const GNU_DYNAMIC_ENTRIES: NonZeroUsize =
    const { NonZeroUsize::new(16_384).expect("GNU dynamic-entry limit must be nonzero") };

/// Default GNU namespace bound.
const GNU_NAMESPACES: NonZeroUsize =
    const { NonZeroUsize::new(64).expect("GNU namespace limit must be nonzero") };

/// Default GNU module bound per namespace.
const GNU_MODULES: NonZeroUsize =
    const { NonZeroUsize::new(16_384).expect("GNU module limit must be nonzero") };

/// Default GNU interpreter byte bound.
const GNU_INTERPRETER_BYTES: NonZeroUsize =
    const { NonZeroUsize::new(4096).expect("GNU interpreter byte limit must be nonzero") };

/// Default GNU module-name byte bound.
const GNU_MODULE_NAME_BYTES: NonZeroUsize =
    const { NonZeroUsize::new(64 * 1024).expect("GNU module-name byte limit must be nonzero") };

/// Default GNU complete-snapshot retry bound.
const GNU_SNAPSHOT_ATTEMPTS: NonZeroUsize =
    const { NonZeroUsize::new(4).expect("GNU snapshot attempt limit must be nonzero") };

/// Finite resource policy for GNU module snapshots.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// NOTE(invariant): Every stored limit is nonzero, so bounded acquisition always permits work while remaining finite.
pub struct SnapshotLimits {
    /// Maximum program-header entries accepted from the main ELF image.
    program_headers: NonZeroUsize,

    /// Maximum dynamic-table entries inspected before requiring `DT_NULL`.
    dynamic_entries: NonZeroUsize,

    /// Maximum GNU namespaces followed through the extended rendezvous chain.
    namespaces: NonZeroUsize,

    /// Maximum link-map nodes retained for any one namespace.
    modules_per_namespace: NonZeroUsize,

    /// Maximum bytes accepted for the ELF interpreter payload including its terminator.
    interpreter_bytes: NonZeroUsize,

    /// Maximum bytes copied for one module name including its terminator.
    module_name_bytes: NonZeroUsize,

    /// Maximum complete snapshot attempts used to outlast transient linker mutation.
    snapshot_attempts: NonZeroUsize,
}

impl SnapshotLimits {
    /// Construct a complete finite snapshot policy.
    #[inline]
    #[must_use]
    pub const fn new(
        target_program_headers: NonZeroUsize,
        target_dynamic_entries: NonZeroUsize,
        target_namespaces: NonZeroUsize,
        target_modules_per_namespace: NonZeroUsize,
        target_interpreter_bytes: NonZeroUsize,
        target_module_name_bytes: NonZeroUsize,
        target_snapshot_attempts: NonZeroUsize,
    ) -> Self {
        Self {
            program_headers: target_program_headers,
            dynamic_entries: target_dynamic_entries,
            namespaces: target_namespaces,
            modules_per_namespace: target_modules_per_namespace,
            interpreter_bytes: target_interpreter_bytes,
            module_name_bytes: target_module_name_bytes,
            snapshot_attempts: target_snapshot_attempts,
        }
    }

    /// Return the default GNU x86-64 resource policy.
    #[inline]
    #[must_use]
    pub const fn amd64() -> Self {
        Self::new(
            GNU_PROGRAM_HEADERS,
            GNU_DYNAMIC_ENTRIES,
            GNU_NAMESPACES,
            GNU_MODULES,
            GNU_INTERPRETER_BYTES,
            GNU_MODULE_NAME_BYTES,
            GNU_SNAPSHOT_ATTEMPTS,
        )
    }

    /// Return the default GNU i386 resource policy.
    #[inline]
    #[must_use]
    pub const fn i386() -> Self {
        Self::new(
            GNU_PROGRAM_HEADERS,
            GNU_DYNAMIC_ENTRIES,
            GNU_NAMESPACES,
            GNU_MODULES,
            GNU_INTERPRETER_BYTES,
            GNU_MODULE_NAME_BYTES,
            GNU_SNAPSHOT_ATTEMPTS,
        )
    }

    /// Determine the program-header count limit.
    #[inline]
    #[must_use]
    pub const fn phdrs(&self) -> NonZeroUsize {
        let Self {
            program_headers, ..
        } = self;

        *program_headers
    }

    /// Determine the dynamic-entry count limit.
    #[inline]
    #[must_use]
    pub const fn dynamics(&self) -> NonZeroUsize {
        let Self {
            dynamic_entries, ..
        } = self;

        *dynamic_entries
    }

    /// Determine the namespace count limit.
    #[inline]
    #[must_use]
    pub const fn namespaces(&self) -> NonZeroUsize {
        let Self { namespaces, .. } = self;

        *namespaces
    }

    /// Determine the module count limit per namespace.
    #[inline]
    #[must_use]
    pub const fn modules(&self) -> NonZeroUsize {
        let Self {
            modules_per_namespace,
            ..
        } = self;

        *modules_per_namespace
    }

    /// Determine the interpreter byte limit.
    #[inline]
    #[must_use]
    pub const fn interpreter(&self) -> NonZeroUsize {
        let Self {
            interpreter_bytes, ..
        } = self;

        *interpreter_bytes
    }

    /// Determine the module-name byte limit including the terminator.
    #[inline]
    #[must_use]
    pub const fn names(&self) -> NonZeroUsize {
        let Self {
            module_name_bytes, ..
        } = self;

        *module_name_bytes
    }

    /// Determine the complete snapshot attempt limit.
    #[inline]
    #[must_use]
    pub const fn attempts(&self) -> NonZeroUsize {
        let Self {
            snapshot_attempts, ..
        } = self;

        *snapshot_attempts
    }
}

impl Default for SnapshotLimits {
    #[inline]
    fn default() -> Self {
        Self::amd64()
    }
}

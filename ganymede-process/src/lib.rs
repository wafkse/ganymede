//! Format-neutral process inspection over Catalejo-managed foreign memory.
//!
//! This crate owns process attachment, typed access, owned byte acquisition, and kernel
//! address-space observations. Executable formats and runtime-linker protocols remain outside
//! this boundary so other image formats can reuse the same process machinery.
#![deny(clippy::all, clippy::perf, clippy::nursery, clippy::pedantic)]
#![forbid(clippy::unwrap_used, clippy::panic, rustdoc::all)]
#![forbid(missing_docs, missing_abi)]
#![deny(clippy::missing_docs_in_private_items)]

pub mod process;

pub mod prelude {
    //! Convenience imports for the process-inspection boundary.
    //!
    //! This module exists only to provide one import path for the process-facing concepts that are
    //! commonly composed by downstream crates. It adds no behavior, validation, or interpretation.

    pub use crate::process::{
        AccessError, Attributes, AuxiliaryVectorEntry, Backing, FileBacking, FileIdentity, Process,
        ProcessId, ReadError, Region, Snapshot, SnapshotError,
    };
}

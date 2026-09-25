//! Format-neutral process inspection over Catalejo-managed foreign memory.
//!
//! This crate owns process attachment, typed access, peephole management, and kernel
//! address-space snapshots. Executable formats and runtime-linker protocols remain outside
//! this boundary so other image formats can reuse the same process machinery.
#![deny(clippy::all, clippy::perf, clippy::nursery, clippy::pedantic)]
#![forbid(clippy::unwrap_used, clippy::panic, rustdoc::all)]
#![forbid(missing_docs, missing_abi)]
#![deny(clippy::missing_docs_in_private_items)]

pub mod process;

pub mod snapshot;

pub mod prelude {
    //! This is the `ganymede-process` prelude.
    //!
    //! It re-exports process access, snapshot metadata, and their structured failures.

    pub use crate::snapshot::{
        Attributes, AuxiliaryVectorEntry, Backing, FileBacking, FileIdentity, Region, Snapshot,
        SnapshotError,
    };

    pub use crate::process::{AccessError, Process, ProcessId, ReadError};
}

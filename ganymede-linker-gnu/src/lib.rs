//! GNU runtime-linker interpretation over validated process images.
//!
//! This crate owns GNU-specific ABI observations, rendezvous semantics, namespace traversal,
//! and stable loaded-image discovery. It depends on format and process layers without moving GNU
//! protocol assumptions into either lower-level crate.
#![deny(clippy::all, clippy::perf, clippy::nursery, clippy::pedantic)]
#![forbid(clippy::unwrap_used, clippy::panic, rustdoc::all)]
#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]

/// Complete foreign lifts compared when proving one GNU ABI structure stable.
const STABLE_READ_LIFTS: usize = 8;

mod acquire;

pub mod abi;

pub mod binding32 {
    //! GNU runtime-linker ABI declarations for 32-bit x86 processes.
    //!
    //! This module isolates externally defined names and layouts for the narrower ABI. Keeping the
    //! declarations separate preserves pointer-width identity before any local interpretation.

    #![allow(
        nonstandard_style,
        missing_docs,
        clippy::use_self,
        reason = "bindgen generated declarations preserve GNU linker header names and recursive type spelling"
    )]

    use ganymede_elf::binding::{Elf32_Addr, Elf32_Dyn};

    include!(concat!(env!("OUT_DIR"), "/ganymede-linker-gnu-32.rs"));
}

pub mod binding64 {
    //! GNU runtime-linker ABI declarations for 64-bit x86 processes.
    //!
    //! This module isolates externally defined names and layouts for the wider ABI. Keeping the
    //! declarations separate prevents accidental normalization across process architectures.

    #![allow(
        nonstandard_style,
        missing_docs,
        clippy::use_self,
        reason = "bindgen generated declarations preserve GNU linker header names and recursive type spelling"
    )]

    use ganymede_elf::binding::{Elf64_Addr, Elf64_Dyn};

    include!(concat!(env!("OUT_DIR"), "/ganymede-linker-gnu-64.rs"));
}

pub mod error;

pub mod model;

mod reader;

pub mod failure;

pub mod snapshot;

pub mod prelude {
    //! This is the `ganymede-linker-gnu` prelude.
    //!
    //! It re-exports the generic GNU ABI, observation, snapshot, and failure concepts without
    //! selecting one target width or introducing convenience aliases.

    pub use crate::{
        abi::{Abi, GNU_EXTENDED_PROTOCOL_VERSION, Gnu32, Gnu64},
        error::{AddressOperation, BusyReason, InconsistentReason, LinkerError, StructureKind},
        failure::SnapshotError,
        model::{DebugRecord, ExtendedRecord, LinkMapRecord},
        snapshot::{Module, Namespace, Rendezvous, RetryPolicy, Snapshot},
    };
}

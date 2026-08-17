//! Coherent GNU runtime-linker snapshots for x86-64 processes.
//!
//! This module is the concrete x86-64 profile surface over the shared GNU ABI family, snapshot
//! model, and acquisition implementation.

mod error;

mod retry;

pub mod model;

pub use ganymede_text::BytePath;

use crate::abi::{Abi, Gnu64};

pub use crate::error::{AddressOperation, StructureKind};
pub use error::{BusyReason, InconsistentReason, SnapshotError};
pub use retry::RetryPolicy;

/// Concrete GNU x86-64 module observation.
pub type Module = model::Module<Gnu64>;

/// Concrete GNU x86-64 rendezvous observation.
pub type Rendezvous = model::Rendezvous<Gnu64>;

/// Coherent GNU x86-64 namespace.
pub type Namespace = model::Namespace<Gnu64>;

/// Complete coherent GNU x86-64 module snapshot.
pub type ModuleSnapshot = model::Snapshot<Gnu64>;

pub mod prelude {
    //! Convenience imports for GNU x86-64 coherent snapshots.
    //!
    //! The prelude keeps the target width explicit while grouping the public snapshot, failure,
    //! retry policy and module concepts commonly consumed together.

    pub use super::{
        AddressOperation, BusyReason, GNU_EXTENDED_PROTOCOL_VERSION,
        GNU_X86_64_INTERPRETER_BASENAME, InconsistentReason, Module, ModuleSnapshot, Namespace,
        Rendezvous, RetryPolicy, SnapshotError, StructureKind,
    };
}

/// GNU x86-64 interpreter basename accepted by this snapshot profile.
pub const GNU_X86_64_INTERPRETER_BASENAME: &[u8] = Gnu64::INTERPRETER_BASENAME;

/// First GNU rendezvous protocol version with `r_debug_extended`.
pub const GNU_EXTENDED_PROTOCOL_VERSION: core::ffi::c_int = 2;

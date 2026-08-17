//! Coherent GNU runtime-linker snapshots for i386 processes.
//!
//! This module is the concrete i386 profile surface over the shared GNU ABI family, snapshot model,
//! and acquisition implementation.

mod error;

pub use ganymede_text::BytePath;

use crate::abi::{Abi, Gnu32};

pub use crate::snapshot::{
    AddressOperation, GNU_EXTENDED_PROTOCOL_VERSION, RetryPolicy, StructureKind,
};
pub use error::{BusyReason, InconsistentReason, SnapshotError};

/// Concrete GNU i386 module observation.
pub type Module = crate::snapshot::model::Module<Gnu32>;

/// Concrete GNU i386 rendezvous observation.
pub type Rendezvous = crate::snapshot::model::Rendezvous<Gnu32>;

/// Coherent GNU i386 namespace.
pub type Namespace = crate::snapshot::model::Namespace<Gnu32>;

/// Complete coherent GNU i386 module snapshot.
pub type ModuleSnapshot = crate::snapshot::model::Snapshot<Gnu32>;

pub mod prelude {
    //! Convenience imports for GNU i386 coherent snapshots.
    //!
    //! The prelude keeps 32-bit pointer identity explicit while grouping the public snapshot,
    //! failure, retry policy, and module concepts commonly consumed together.

    pub use super::{
        AddressOperation, BusyReason, GNU_EXTENDED_PROTOCOL_VERSION, GNU_I386_INTERPRETER_BASENAME,
        InconsistentReason, Module, ModuleSnapshot, Namespace, Rendezvous, RetryPolicy,
        SnapshotError, StructureKind,
    };
}

/// GNU i386 interpreter basename accepted by this snapshot profile.
pub const GNU_I386_INTERPRETER_BASENAME: &[u8] = Gnu32::INTERPRETER_BASENAME;

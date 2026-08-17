//! Shared outer failure model for coherent GNU snapshot acquisition.
//!
//! One ABI family selects the width-preserving values stored by failure variants. The outer error
//! taxonomy remains common because malformed metadata, foreign access, retry exhaustion, and graph
//! inconsistency have the same semantics for both supported GNU profiles.

use ganymede_elf::{lift::ElfError, process::ProcessImageError};
use ganymede_process::process::ReadError;
use ganymede_text::BytePath;

use crate::{
    abi::{Abi, ElfAddress},
    error::{AddressOperation, BusyReason, InconsistentReason, LinkerError, StructureKind},
};

/// Failure that prevents one coherent GNU loader snapshot from being returned.
#[derive(Debug, thiserror::Error)]
pub enum SnapshotError<AbiType>
where
    AbiType: Abi,
{
    /// Main ELF process-image interpretation failed.
    #[error(transparent)]
    ElfImage(ProcessImageError),

    /// The ELF interpreter does not identify the supported GNU loader profile.
    #[error("unsupported interpreter bytes {0:?}")]
    UnsupportedInterpreter(BytePath),

    /// Dynamic segment size cannot form a nonempty table of complete entries.
    #[error("invalid dynamic segment size {0:?}")]
    InvalidDynamicSize(ElfAddress<AbiType>),

    /// Complete dynamic segment has no `DT_NULL` terminator.
    #[error("dynamic table lacks DT_NULL")]
    MissingDynamicTerminator,

    /// Dynamic table has no debugger rendezvous entry.
    #[error("dynamic table lacks DT_DEBUG")]
    MissingDebugEntry,

    /// Dynamic table contains multiple debugger rendezvous entries.
    #[error("dynamic table contains duplicate DT_DEBUG")]
    DuplicateDebugEntry,

    /// Debugger rendezvous pointer is null.
    #[error("DT_DEBUG is null")]
    NullDebugEntry,

    /// Checked GNU snapshot address derivation overflowed.
    #[error("target address overflow while {0}")]
    AddressOverflow(AddressOperation),

    /// Catalejo failed while opening foreign process access.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// Generated structure cannot fit in a managed foreign window.
    #[error("foreign {structure:?} access is unavailable at {address:?}")]
    ForeignAccess {
        /// Generated structure category that could not be opened.
        structure: StructureKind,

        /// Foreign structure address.
        address: catalejo::address::ViAddr,
    },

    /// ELF dynamic-entry lift failed.
    #[error("ELF lift failed at {address:?} with {source}")]
    ElfLift {
        /// Foreign ELF structure address.
        address: catalejo::address::ViAddr,

        /// ELF construction failure.
        #[source]
        source: ElfError,
    },

    /// GNU linker lift failed.
    #[error("GNU linker lift failed at {address:?} with {source}")]
    LinkerLift {
        /// Foreign GNU structure address.
        address: catalejo::address::ViAddr,

        /// GNU linker construction failure.
        #[source]
        source: LinkerError,
    },

    /// A loader-provided name does not begin in readable mapped process memory.
    #[error("GNU loader name at {0:?} is not readable in the retained process snapshot")]
    UnreadableName(catalejo::address::ViAddr),

    /// Foreign process byte read failed.
    #[error(transparent)]
    Read(#[from] ReadError),

    /// Linker mutation remained visible through every complete snapshot attempt.
    #[error("GNU linker remained busy after {attempts} attempts with {reason}")]
    Busy {
        /// Complete attempts performed.
        attempts: usize,

        /// Final observed mutation reason.
        reason: BusyReason<AbiType>,
    },

    /// Linker graph inconsistency remained visible through every complete snapshot attempt.
    #[error("GNU linker remained inconsistent after {attempts} attempts with {reason}")]
    Inconsistent {
        /// Complete attempts performed.
        attempts: usize,

        /// Final observed graph inconsistency.
        reason: InconsistentReason<AbiType>,
    },
}

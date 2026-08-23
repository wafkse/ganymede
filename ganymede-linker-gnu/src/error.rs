//! Shared GNU runtime-linker failure semantics.
//!
//! Pointer-bearing reasons retain one sealed GNU ABI family. The family determines every pointer and
//! state type together, so failures cannot accidentally combine observations from different target
//! widths.

use crate::abi::{Abi, DebugPointer, ExtendedPointer, MapPointer};

/// Failure while lifting GNU dynamic linker state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, fack::prelude::Error)]
pub enum LinkerError {
    /// A projected foreign field faulted.
    #[error("foreign GNU linker read faulted")]
    Faulted,
}

/// Address calculation that can overflow during GNU snapshot acquisition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, fack::prelude::Error)]
pub enum AddressOperation {
    /// Computing a byte offset into the ELF dynamic table.
    #[error("indexing the dynamic table")]
    DynamicOffset,

    /// Locating one process-resident dynamic entry.
    #[error("locating a dynamic entry")]
    DynamicEntry,
}

/// Generated foreign structure category observed by GNU snapshot acquisition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StructureKind {
    /// Generated ELF dynamic value.
    Dynamic,

    /// Generated base rendezvous value.
    Debug,

    /// Generated extended rendezvous value.
    ExtendedDebug,

    /// Generated link-map value.
    LinkMap,
}

/// Retryable loader mutation retained after one complete acquisition attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, fack::prelude::Error)]
pub enum BusyReason<AbiType>
where
    AbiType: Abi,
{
    /// Sequential complete lifts did not establish stability.
    #[error("{structure:?} remained unstable at {address:?}")]
    UnstableStructure {
        /// Generated structure category that remained unstable.
        structure: StructureKind,

        /// Foreign structure address represented in process space.
        address: catalejo::address::ViAddr,
    },

    /// GNU rendezvous state was not consistent.
    #[error("GNU rendezvous {debug:?} remained in state {state:?}")]
    LinkerState {
        /// Namespace rendezvous pointer with target width preserved.
        debug: DebugPointer<AbiType>,

        /// Loader mutation state with generated ABI type preserved.
        state: AbiType::State,
    },

    /// A stable composite changed during traversal.
    #[error("{structure:?} changed at {address:?}")]
    StructureChanged {
        /// Generated structure category that changed.
        structure: StructureKind,

        /// Foreign structure address represented in process space.
        address: catalejo::address::ViAddr,
    },
}

/// Retryable stable graph inconsistency retained after one acquisition attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, fack::prelude::Error)]
pub enum InconsistentReason<AbiType>
where
    AbiType: Abi,
{
    /// Extended namespace chain contains a cycle.
    #[error("GNU namespace cycle at {0:?}")]
    NamespaceCycle(ExtendedPointer<AbiType>),

    /// Secondary namespace lacks the required extended GNU protocol.
    #[error("GNU namespace {debug:?} uses unsupported protocol version {version}")]
    NamespaceProtocol {
        /// Namespace rendezvous pointer.
        debug: DebugPointer<AbiType>,

        /// Observed GNU protocol version.
        version: core::ffi::c_int,
    },

    /// Namespace link-map chain contains a cycle.
    #[error("GNU link-map cycle at {0:?}")]
    ModuleCycle(MapPointer<AbiType>),

    /// Forward traversal observed an unexpected previous edge.
    #[error("GNU link-map {map:?} expected previous {expected:?} but observed {observed:?}")]
    PreviousMismatch {
        /// Affected link-map pointer.
        map: MapPointer<AbiType>,

        /// Required previous link-map pointer.
        expected: MapPointer<AbiType>,

        /// Observed previous link-map pointer.
        observed: MapPointer<AbiType>,
    },

    /// Reverse traversal reached a link-map node other than the expected node.
    #[error("GNU reverse walk expected map {expected:?} but observed {observed:?}")]
    ReverseMapMismatch {
        /// Required link-map pointer.
        expected: MapPointer<AbiType>,

        /// Observed link-map pointer.
        observed: MapPointer<AbiType>,
    },

    /// Reverse traversal observed an unexpected next edge.
    #[error("GNU link-map {map:?} expected next {expected:?} but observed {observed:?}")]
    NextMismatch {
        /// Affected link-map pointer.
        map: MapPointer<AbiType>,

        /// Required next link-map pointer.
        expected: MapPointer<AbiType>,

        /// Observed next link-map pointer.
        observed: MapPointer<AbiType>,
    },

    /// Reverse traversal did not terminate at a null previous pointer.
    #[error("GNU reverse walk did not terminate at {0:?}")]
    ReverseDidNotTerminate(MapPointer<AbiType>),
}

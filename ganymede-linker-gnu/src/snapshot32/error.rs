//! GNU i386 snapshot failure aliases.

use crate::abi::Gnu32;

/// Retryable GNU i386 loader mutation.
pub type BusyReason = crate::error::BusyReason<Gnu32>;

/// Retryable GNU i386 graph inconsistency.
pub type InconsistentReason = crate::error::InconsistentReason<Gnu32>;

/// Failure while capturing a coherent GNU i386 module snapshot.
pub type SnapshotError = crate::failure::SnapshotError<Gnu32>;

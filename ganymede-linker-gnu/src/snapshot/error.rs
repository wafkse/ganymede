//! GNU x86-64 snapshot failure aliases.

use crate::abi::Gnu64;

/// Retryable GNU x86-64 loader mutation.
pub type BusyReason = crate::error::BusyReason<Gnu64>;

/// Retryable GNU x86-64 graph inconsistency.
pub type InconsistentReason = crate::error::InconsistentReason<Gnu64>;

/// Failure while capturing a coherent GNU x86-64 module snapshot.
pub type SnapshotError = crate::failure::SnapshotError<Gnu64>;

//! Bounded retry execution for coherent GNU acquisition.
//!
//! Retry owns only the nonzero attempt budget. The selected GNU ABI appears in the attempt result and
//! final typed reason rather than in the retry executor representation.

use core::num::NonZeroUsize;

use super::{Abi, ModuleSnapshot, SnapshotError};
use crate::error::{BusyReason, InconsistentReason};

/// Failure classification for one complete snapshot attempt.
#[derive(Debug, thiserror::Error)]
pub enum AttemptError<AbiType>
where
    AbiType: Abi,
{
    /// A stable validation or foreign access failure.
    #[error(transparent)]
    Fatal(#[from] SnapshotError<AbiType>),

    /// A foreign mutation that can become stable on retry.
    #[error(transparent)]
    Busy(BusyReason<AbiType>),

    /// A graph inconsistency that can disappear on retry.
    #[error(transparent)]
    Inconsistent(InconsistentReason<AbiType>),
}

/// Final retryable outcome from a complete attempt.
#[derive(Debug, Clone, Copy)]
enum Outcome<AbiType>
where
    AbiType: Abi,
{
    /// The process was actively mutating linker state.
    Busy(BusyReason<AbiType>),

    /// The observed linker graph was inconsistent.
    Inconsistent(InconsistentReason<AbiType>),
}

impl<AbiType> Outcome<AbiType>
where
    AbiType: Abi,
{
    /// Convert retry exhaustion into the public snapshot failure.
    #[inline]
    const fn error(self, target_attempts: usize) -> SnapshotError<AbiType> {
        match self {
            Self::Busy(reason) => SnapshotError::Busy {
                attempts: target_attempts,
                reason,
            },
            Self::Inconsistent(reason) => SnapshotError::Inconsistent {
                attempts: target_attempts,
                reason,
            },
        }
    }
}

/// Nonzero complete-attempt retry budget.
#[derive(Debug, Clone, Copy)]
// NOTE(invariant): The retained attempt budget is nonzero, so exhaustion after only retryable outcomes always retains a final outcome.
pub struct Retry(NonZeroUsize);

impl Retry {
    /// Construct a retry executor from a proven nonzero budget.
    #[inline]
    #[must_use]
    pub const fn new(target_attempts: NonZeroUsize) -> Self {
        Self(target_attempts)
    }

    /// Execute attempts until one completes or the budget is exhausted.
    #[inline]
    pub fn run<AbiType>(
        self,
        mut target_attempt: impl FnMut() -> Result<ModuleSnapshot<AbiType>, AttemptError<AbiType>>,
    ) -> Result<ModuleSnapshot<AbiType>, SnapshotError<AbiType>>
    where
        AbiType: Abi,
    {
        let Self(attempts) = self;
        let attempts = attempts.get();
        let mut last = None;

        for _target_attempt in 0..attempts {
            match target_attempt() {
                Ok(target_snapshot) => return Ok(target_snapshot),
                Err(AttemptError::Fatal(target_error)) => return Err(target_error),
                Err(AttemptError::Busy(target_reason)) => last = Some(Outcome::Busy(target_reason)),
                Err(AttemptError::Inconsistent(target_reason)) => {
                    last = Some(Outcome::Inconsistent(target_reason));
                }
            }
        }

        Err(last
            .expect("a nonzero retry budget must retain a retryable outcome")
            .error(attempts))
    }
}

//! Retry policy for coherent GNU runtime-linker snapshot acquisition.
//!
//! Retry policy governs only repeated complete observations of mutable loader state. Target data
//! validity is derived from ELF geometry, GNU terminators, pointer identity, and cycle detection.
//! The policy therefore cannot make an otherwise valid target structure malformed.

use core::num::NonZeroUsize;

/// Default complete snapshot attempt count.
const SNAPSHOT_ATTEMPTS: NonZeroUsize =
    const { NonZeroUsize::new(4).expect("snapshot attempt count must be nonzero") };

/// Finite retry policy for complete coherent snapshot attempts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
// NOTE(invariant): The retained attempt count is nonzero, so retry exhaustion always follows at least one complete observation.
pub struct RetryPolicy(NonZeroUsize);

impl RetryPolicy {
    /// Construct a retry policy from a nonzero complete attempt count.
    #[inline]
    #[must_use]
    pub const fn new(target_attempts: NonZeroUsize) -> Self {
        Self(target_attempts)
    }

    /// Return the standard complete snapshot retry policy.
    #[inline]
    #[must_use]
    pub const fn standard() -> Self {
        Self(SNAPSHOT_ATTEMPTS)
    }

    /// Return the number of complete snapshot attempts permitted.
    #[inline]
    #[must_use]
    pub const fn attempts(self) -> NonZeroUsize {
        let Self(attempts) = self;

        attempts
    }
}

impl Default for RetryPolicy {
    #[inline]
    fn default() -> Self {
        Self::standard()
    }
}

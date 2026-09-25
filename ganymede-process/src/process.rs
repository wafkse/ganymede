//! Managed typed access to one foreign process.
//!
//! This module owns process attachment and Catalejo manager composition. Address-space snapshots
//! live in [`crate::snapshot`] so typed access does not accumulate kernel metadata representations.

use std::{io, sync::Arc};

use catalejo::ffi::binding;
use catalejo::{
    address::ViAddr,
    manage::{Access, Granule, Manage, Rebased},
    prelude::{Faultable, Foreign, Target, Unassociated},
};

/// A newtype capable of representing a process identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProcessId(pub u32);

/// A handle to one engaged process and its peephole manager.
#[derive(Debug, Clone)]
// NOTE(invariant): the shared manager remains engaged for the complete process handle lifetime, and every awarded foreign handle retains its backing peephole independently.
pub struct Process(Arc<Rebased>);

impl Process {
    /// Attach to the target process through its process identifier.
    ///
    /// # Errors
    ///
    /// This returns an error when Catalejo cannot engage the target process or the identifier cannot
    /// be represented by the platform process identifier type.
    ///
    /// # Panics
    ///
    /// This panics when the Catalejo subsystem has not been initialized.
    #[inline]
    pub fn new(target_process_id: ProcessId) -> io::Result<Self> {
        let ProcessId(target_id) = target_process_id;
        let target_engaged = Target::engage(
            binding::pid_t::try_from(target_id)
                .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?,
        )?;

        Ok(Self::new_with(target_engaged))
    }

    /// Attach through an existing [`Target`] handle.
    #[inline]
    #[must_use]
    pub fn new_with(target_engaged: Target) -> Self {
        let manager_context = Arc::new(Rebased::new(target_engaged));

        Self(manager_context)
    }

    /// Borrow the engaged Catalejo target for sibling process-observation modules.
    #[inline]
    pub(crate) fn target(&self) -> &Target {
        let Self(manager_context) = self;

        manager_context.engaged()
    }

    /// Open typed foreign access at a process virtual address.
    ///
    /// # Errors
    ///
    /// This returns an error when Catalejo cannot open a suitable peephole or when the requested
    /// value cannot fit in a managed foreign window.
    #[inline]
    pub fn open<T>(&self, target_address: ViAddr) -> Result<Foreign<T>, AccessError>
    where
        T: Unassociated,
    {
        let Self(manager_context) = self;

        manager_context
            .source::<T>(target_address)
            .map_err(AccessError::Io)?
            .and_then(Access::foreign)
            .ok_or(AccessError::Unavailable(target_address))
    }

    /// Resolve a typed sparse access intent through this process manager.
    ///
    /// The original peephole is reused when it can still contain the projected value. Otherwise
    /// Catalejo may locate or open another managed peephole for the same process address.
    #[inline]
    #[must_use]
    pub fn resolve<T>(&self, target_access: Access<T>) -> Option<Foreign<T>>
    where
        T: Unassociated,
    {
        let Self(manager_context) = self;

        manager_context.refresh(target_access)
    }

    /// Read one fault-safe primitive from the target process.
    ///
    /// # Errors
    ///
    /// This returns [`ReadError::Access`] when typed foreign access cannot be opened and
    /// [`ReadError::Fault`] when the protected primitive read faults.
    #[inline]
    pub fn read<F>(&self, target_address: ViAddr) -> Result<F, ReadError>
    where
        F: Faultable,
    {
        Self::open::<F>(self, target_address)?
            .read()
            .ok_or(ReadError::Fault(target_address))
    }
}

impl Manage for Process {
    #[inline]
    fn absolute<U>(&self, target_address: ViAddr) -> Option<Access<U>>
    where
        U: Unassociated,
    {
        let Self(manager_context) = self;

        manager_context.absolute(target_address)
    }

    #[inline]
    fn source<U>(&self, target_address: ViAddr) -> io::Result<Option<Access<U>>>
    where
        U: Unassociated,
    {
        let Self(manager_context) = self;

        manager_context.source(target_address)
    }

    #[inline]
    fn granule(&self) -> Granule {
        let Self(manager_context) = self;

        manager_context.granule()
    }
}

/// An error while opening typed access to process memory.
#[derive(Debug, fack::prelude::Error)]
pub enum AccessError {
    /// Catalejo failed while opening or locating a peephole.
    #[error("input-output error {0}")]
    #[error(source(0))]
    Io(io::Error),

    /// No managed peephole can provide the requested typed access.
    #[error("foreign virtual address is unavailable {0:?}")]
    Unavailable(ViAddr),
}

/// A failure while reading one fault-safe primitive.
#[derive(Debug, fack::prelude::Error)]
pub enum ReadError {
    /// Opening the required typed foreign access failed.
    #[error(transparent(0))]
    Access(AccessError),

    /// A foreign access fault occurred.
    #[error("foreign read faulted at {0:?}")]
    Fault(ViAddr),

    /// Checked foreign address progression overflowed.
    #[error("foreign address overflow at {0:?} after {1} bytes")]
    AddressOverflow(ViAddr, usize),
}

impl From<AccessError> for ReadError {
    #[inline]
    fn from(source: AccessError) -> Self {
        Self::Access(source)
    }
}

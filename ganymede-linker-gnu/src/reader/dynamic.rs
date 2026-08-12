//! Validated GNU dynamic-table acquisition shared by supported ABIs.
//!
//! Construction proves table geometry once. Scanning operates over bounded complete entries while
//! the selected ELF word retains target width until each entry address crosses into process space.

use catalejo::ffi;
use ganymede_elf::{binding, lift::Dynamic as ElfDynamic};
use num_traits::{CheckedAdd, CheckedMul, Zero};

use super::{
    Abi, AccessError, AddressOperation, DynamicSize, ElfError, Process, RawDynamic, SnapshotError,
    SnapshotLimits, StructureKind, ViAddr,
};
use crate::abi::DebugPointer;

/// Validated process-resident GNU dynamic table.
#[derive(Debug, Clone, Copy)]
// NOTE(invariant): `base` and `stride` retain the selected ELF width, `count` is nonzero and policy-bounded, and every entry address is checked before widening into process space.
pub struct Table<'target, AbiType>
where
    AbiType: Abi,
{
    /// Process containing this dynamic table.
    process: &'target Process,

    /// Target-width address of the first dynamic entry.
    base: DynamicSize<AbiType>,

    /// Generated dynamic-entry width in the selected ELF class.
    stride: DynamicSize<AbiType>,

    /// Number of complete entries permitted by validated segment geometry.
    count: usize,
}

impl<'target, AbiType> Table<'target, AbiType>
where
    AbiType: Abi,
    ElfDynamic<AbiType::Elf>:
        catalejo::prelude::Lift<Value = RawDynamic<AbiType>, Context = (), Error = ElfError>,
{
    /// Validate dynamic segment geometry and bind it to one process.
    #[inline]
    pub fn new(
        target_process: &'target Process,
        target_dynamic: ViAddr,
        target_size: DynamicSize<AbiType>,
        target_limits: SnapshotLimits,
    ) -> Result<Self, SnapshotError<AbiType>> {
        let stride_host = u64::try_from(core::mem::size_of::<RawDynamic<AbiType>>())
            .map_err(|_| SnapshotError::AddressOverflow(AddressOperation::DynamicOffset))?;
        let stride = DynamicSize::<AbiType>::try_from(stride_host)
            .map_err(|_| SnapshotError::AddressOverflow(AddressOperation::DynamicOffset))?;
        let zero = DynamicSize::<AbiType>::zero();
        let is_nonzero = target_size != zero;
        let is_aligned = is_nonzero && target_size % stride == zero;
        let count_word = is_aligned.then(|| target_size / stride);
        let count = count_word.and_then(|target_count| target_count.try_into().ok());
        let is_bounded = count.is_some_and(|target_count| {
            target_count != 0 && target_count <= target_limits.dynamics().get()
        });

        if !is_bounded {
            return Err(SnapshotError::InvalidDynamicSize(target_size));
        }

        let ViAddr(base) = target_dynamic;
        let base = DynamicSize::<AbiType>::try_from(base)
            .map_err(|_| SnapshotError::AddressOverflow(AddressOperation::DynamicEntry))?;
        let count = count.expect("a validated dynamic count must be present");

        Ok(Self {
            process: target_process,
            base,
            stride,
            count,
        })
    }

    /// Resolve the unique nonnull debugger rendezvous pointer.
    #[inline]
    pub fn debug(&self) -> Result<DebugPointer<AbiType>, SnapshotError<AbiType>> {
        let Self { count, .. } = self;

        (0..*count)
            .try_fold(DebugSlot::Missing, |target_slot, target_index| {
                let entry = self.entry(target_index).map_err(Scan::Error)?;
                let tag = entry.tag();

                if tag == i64::from(binding::DT_NULL) {
                    return Err(Scan::Done(target_slot.finish()));
                }

                if tag == i64::from(binding::DT_DEBUG) {
                    let pointer = DebugPointer::<AbiType>::new(entry.value());

                    return target_slot.insert(pointer).map_err(Scan::Error);
                }

                Ok(target_slot)
            })
            .map_or_else(
                |target_scan| match target_scan {
                    Scan::Done(target_result) => target_result,
                    Scan::Error(target_error) => Err(target_error),
                },
                |_target_slot| Err(SnapshotError::MissingDynamicTerminator),
            )
    }

    /// Lift one validated table position.
    fn entry(
        &self,
        target_index: usize,
    ) -> Result<ElfDynamic<AbiType::Elf>, SnapshotError<AbiType>> {
        let Self {
            process,
            base,
            stride,
            ..
        } = self;
        let index = u64::try_from(target_index)
            .ok()
            .and_then(|target_index| DynamicSize::<AbiType>::try_from(target_index).ok())
            .ok_or(SnapshotError::AddressOverflow(
                AddressOperation::DynamicOffset,
            ))?;
        let offset = index
            .checked_mul(stride)
            .ok_or(SnapshotError::AddressOverflow(
                AddressOperation::DynamicOffset,
            ))?;
        let address = base
            .checked_add(&offset)
            .map(Into::<ffi::binding::virtual_address_t>::into)
            .map(ViAddr::new)
            .ok_or(SnapshotError::AddressOverflow(
                AddressOperation::DynamicEntry,
            ))?;

        Process::open::<RawDynamic<AbiType>>(process, address)
            .map_err(|target_error| match target_error {
                AccessError::Io(target_error) => SnapshotError::from(target_error),
                AccessError::Unavailable(..) => SnapshotError::ForeignAccess {
                    structure: StructureKind::Dynamic,
                    address,
                },
            })?
            .lift::<ElfDynamic<AbiType::Elf>>()
            .map_err(|source| SnapshotError::ElfLift { address, source })
    }
}

/// Accumulated `DT_DEBUG` state before the dynamic terminator.
#[derive(Debug, Clone, Copy)]
enum DebugSlot<AbiType>
where
    AbiType: Abi,
{
    /// No debugger pointer has been observed.
    Missing,

    /// Exactly one nonnull debugger pointer has been observed.
    Found(DebugPointer<AbiType>),
}

impl<AbiType> DebugSlot<AbiType>
where
    AbiType: Abi,
{
    /// Insert one debugger pointer while preserving uniqueness and nonnullness.
    #[inline]
    fn insert(self, target_pointer: DebugPointer<AbiType>) -> Result<Self, SnapshotError<AbiType>> {
        if target_pointer.null() {
            return Err(SnapshotError::NullDebugEntry);
        }

        match self {
            Self::Missing => Ok(Self::Found(target_pointer)),
            Self::Found(..) => Err(SnapshotError::DuplicateDebugEntry),
        }
    }

    /// Finish debugger discovery at `DT_NULL`.
    #[inline]
    const fn finish(self) -> Result<DebugPointer<AbiType>, SnapshotError<AbiType>> {
        match self {
            Self::Missing => Err(SnapshotError::MissingDebugEntry),
            Self::Found(target_pointer) => Ok(target_pointer),
        }
    }
}

/// Internal short-circuit state for iterator-driven dynamic scanning.
#[derive(Debug)]
enum Scan<AbiType>
where
    AbiType: Abi,
{
    /// The terminator completed scanning with the retained debugger result.
    Done(Result<DebugPointer<AbiType>, SnapshotError<AbiType>>),

    /// Scanning failed before the terminator.
    Error(SnapshotError<AbiType>),
}

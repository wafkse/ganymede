//! Process access and kernel address-space observation.
//!
//! This module is the format-neutral boundary between Ganymede and Catalejo. It turns process
//! identities and virtual addresses into managed foreign access, performs owned byte acquisition,
//! and retains kernel mapping metadata without interpreting executable formats.

use std::{io, num::NonZeroUsize, sync::Arc};

use bitflags::bitflags;
use catalejo::ffi::binding;
use catalejo::{
    address::{ViAddr, ViRange},
    ffi,
    manage::{Manage, Rebased},
    prelude::{ByteCopyStatus, Faultable, Foreign, Target, Unassociated},
};

/// A newtype capable of representing a process identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProcessId(pub u32);

/// A handle to an engaged process.
#[derive(Debug, Clone)]
pub struct Process(Arc<Rebased>);

impl Process {
    /// Attach to the target process through its process identifier.
    ///
    /// # Errors
    ///
    /// This returns an error when Catalejo cannot engage the target process or the provided process identifier could not be converted.
    ///
    /// # Panics
    ///
    /// This panics when the Catalejo subsystem has not been initialized.
    #[inline]
    pub fn new(target_process_id: ProcessId) -> io::Result<Self> {
        let ProcessId(target_id) = target_process_id;

        Ok(Self::new_with(Target::engage(
            binding::pid_t::try_from(target_id)
                .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?,
        )?))
    }

    /// Attach through an existing [`Target`] handle.
    #[inline]
    #[must_use]
    pub fn new_with(target_engaged: Target) -> Self {
        let manager_context = Arc::new(Rebased::new(target_engaged));

        Self(manager_context)
    }
}

impl Process {
    /// Open typed foreign access at a process virtual address.
    ///
    /// # Errors
    ///
    /// This returns an error when Catalejo cannot open a suitable peephole or when the
    /// requested value cannot fit in a managed foreign window.
    #[inline]
    pub fn open<T>(&self, target_address: ViAddr) -> Result<Foreign<T>, AccessError>
    where
        T: Unassociated,
    {
        let Self(manager_context) = self;

        manager_context
            .source::<T>(target_address)
            .map_err(AccessError::Io)?
            .and_then(catalejo::manage::Access::foreign)
            .ok_or(AccessError::Unavailable(target_address))
    }

    /// Read a fault-safe primitive from the target process.
    ///
    /// The returned value is a machine-word-coherent observation. Every bit pattern of `F` is
    /// valid because `F` implements [`Faultable`].
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

    /// Read exactly `size` bytes from the target process into owned storage.
    ///
    /// The read advances across managed peephole boundaries as needed. A protected foreign fault
    /// fails the complete operation rather than returning a partial byte vector.
    ///
    /// # Errors
    ///
    /// This returns an I/O error when Catalejo cannot open process access, an unavailable-address
    /// error when a byte cannot be represented by a managed foreign handle, a fault error when the
    /// protected copy stops at foreign memory, or an overflow error when address progression cannot
    /// be represented.
    #[inline]
    pub fn read_bytes(
        &self,
        target_address: ViAddr,
        target_size: usize,
    ) -> Result<Vec<u8>, ReadError> {
        let ViAddr(base_address) = target_address;

        let mut bytes = Vec::with_capacity(target_size);

        let mut offset = 0_usize;

        loop {
            let remaining_bytes = target_size.saturating_sub(offset);

            let remaining_bytes = match NonZeroUsize::new(remaining_bytes) {
                Some(remaining_bytes) => remaining_bytes.get(),
                None => break Ok(bytes),
            };

            let offset_value = u64::try_from(offset)
                .map_err(|_| ReadError::AddressOverflow(target_address, offset))?;

            let chunk_address = base_address
                .checked_add(offset_value)
                .map(ViAddr::new)
                .ok_or(ReadError::AddressOverflow(target_address, offset))?;

            let foreign = Self::open::<u8>(self, chunk_address)?;

            let requested_bytes = remaining_bytes.min(foreign.leftover().get());

            let byte_copy = foreign
                .append(&mut bytes, requested_bytes)
                .ok_or(AccessError::Unavailable(chunk_address))?;

            let copied_bytes = byte_copy.copied();

            let copy_status = byte_copy.status();

            match copy_status {
                ByteCopyStatus::Complete => {
                    offset = offset
                        .checked_add(copied_bytes)
                        .ok_or(ReadError::AddressOverflow(target_address, offset))?;
                }
                ByteCopyStatus::Faulted => {
                    let fault_offset = offset
                        .checked_add(copied_bytes)
                        .ok_or(ReadError::AddressOverflow(target_address, offset))?;
                    let fault_offset_value = u64::try_from(fault_offset)
                        .map_err(|_| ReadError::AddressOverflow(target_address, fault_offset))?;
                    let fault_address = base_address
                        .checked_add(fault_offset_value)
                        .map(ViAddr::new)
                        .ok_or(ReadError::AddressOverflow(target_address, fault_offset))?;

                    break Err(ReadError::Fault(fault_address));
                }
            }
        }
    }

    /// Read a NUL-terminated byte string within a nonzero byte limit.
    ///
    /// Foreign bytes are copied directly into owned storage and scanned locally. The returned
    /// vector excludes the terminator and preserves the remaining bytes without text decoding.
    ///
    /// # Errors
    ///
    /// This returns the same access, fault, and overflow failures as [`Self::read_bytes`]. It also
    /// returns [`ReadError::MissingTerminator`] when the complete limit is readable but contains no
    /// NUL byte.
    #[inline]
    pub fn read_c_string_bytes(
        &self,
        target_address: ViAddr,
        target_limit: NonZeroUsize,
    ) -> Result<Vec<u8>, ReadError> {
        let ViAddr(base_address) = target_address;
        let limit = target_limit.get();
        let mut bytes = Vec::new();
        let mut offset = 0_usize;

        loop {
            let remaining_bytes = limit.saturating_sub(offset);
            let remaining_bytes = match NonZeroUsize::new(remaining_bytes) {
                Some(remaining_bytes) => remaining_bytes.get(),
                None => {
                    break Err(ReadError::MissingTerminator(target_address, limit));
                }
            };
            let offset_value = u64::try_from(offset)
                .map_err(|_| ReadError::AddressOverflow(target_address, offset))?;
            let chunk_address = base_address
                .checked_add(offset_value)
                .map(ViAddr::new)
                .ok_or(ReadError::AddressOverflow(target_address, offset))?;
            let foreign = Self::open::<u8>(self, chunk_address)?;
            let requested_bytes = remaining_bytes.min(foreign.leftover().get());
            let original_length = bytes.len();
            let (copied_bytes, terminator_offset, copy_status) = {
                let byte_copy = foreign
                    .append(&mut bytes, requested_bytes)
                    .ok_or(AccessError::Unavailable(chunk_address))?;
                let copied_bytes = byte_copy.copied();
                let terminator_offset = byte_copy
                    .bytes()
                    .iter()
                    .position(|target_byte| *target_byte == 0);
                let copy_status = byte_copy.status();

                (copied_bytes, terminator_offset, copy_status)
            };
            let retained_bytes =
                terminator_offset.map_or(copied_bytes, |target_offset| target_offset);

            bytes.truncate(original_length + retained_bytes);

            match (terminator_offset, copy_status) {
                (Some(..), _) => break Ok(bytes),
                (None, ByteCopyStatus::Faulted) => {
                    let fault_offset = offset
                        .checked_add(copied_bytes)
                        .ok_or(ReadError::AddressOverflow(target_address, offset))?;
                    let fault_offset_value = u64::try_from(fault_offset)
                        .map_err(|_| ReadError::AddressOverflow(target_address, fault_offset))?;
                    let fault_address = base_address
                        .checked_add(fault_offset_value)
                        .map(ViAddr::new)
                        .ok_or(ReadError::AddressOverflow(target_address, fault_offset))?;

                    break Err(ReadError::Fault(fault_address));
                }
                (None, ByteCopyStatus::Complete) => {
                    offset = offset
                        .checked_add(copied_bytes)
                        .ok_or(ReadError::AddressOverflow(target_address, offset))?;
                }
            }
        }
    }
}

/// An error while opening typed access to process memory.
#[derive(Debug, thiserror::Error)]
pub enum AccessError {
    /// Catalejo failed while opening or locating a peephole.
    #[error("input-output error: {0}")]
    Io(#[source] io::Error),

    /// No managed peephole can provide the requested typed access.
    #[error("foreign virtual address is unavailable: {0:?}")]
    Unavailable(ViAddr),
}

/// An error originating from a process-interaction.
#[derive(Debug, thiserror::Error)]
pub enum ReadError {
    /// Opening the required typed foreign access failed.
    #[error(transparent)]
    Access(#[from] AccessError),

    /// A foreign-access fault occurred.
    #[error("foreign read faulted at {0:?}")]
    Fault(ViAddr),

    /// A foreign address overflowed.
    #[error("foreign address overflow: ({0:?}, @{1}p)")]
    AddressOverflow(ViAddr, usize),

    /// A bounded C string read found no NUL terminator.
    #[error("C string at {0:?} has no NUL terminator within {1} bytes")]
    MissingTerminator(ViAddr, usize),
}

/// Kernel-provided auxiliary vector metadata retained by a process snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuxiliaryVectorEntry {
    /// Linux auxiliary-vector key reported by the kernel for this entry.
    entry_type: ffi::binding::mirilla_auxiliary_vector_type_t,

    /// Raw auxiliary-vector payload associated with `entry_type`.
    entry_value: ffi::binding::mirilla_auxiliary_vector_value_t,
}

impl AuxiliaryVectorEntry {
    /// Determine the auxiliary vector entry type.
    #[inline]
    #[must_use]
    pub const fn entry_type(&self) -> ffi::binding::mirilla_auxiliary_vector_type_t {
        let Self { entry_type, .. } = self;

        *entry_type
    }
    /// Determine the auxiliary vector entry value.
    #[inline]
    #[must_use]
    pub const fn entry_value(&self) -> ffi::binding::mirilla_auxiliary_vector_value_t {
        let Self { entry_value, .. } = self;

        *entry_value
    }
}

/// Stable identity of a file backing a process mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
// NOTE(invariant): The device pair and inode originate from the same kernel `vm_file` observed while the process VMA lock was held.
pub struct FileIdentity {
    /// Major device number of the backing inode.
    device_major: u32,

    /// Minor device number of the backing inode.
    device_minor: u32,

    /// Inode number within the backing device.
    inode_number: u64,
}

impl FileIdentity {
    /// Return the backing device major number.
    #[inline]
    #[must_use]
    pub const fn device_major(&self) -> u32 {
        let Self { device_major, .. } = self;

        *device_major
    }

    /// Return the backing device minor number.
    #[inline]
    #[must_use]
    pub const fn device_minor(&self) -> u32 {
        let Self { device_minor, .. } = self;

        *device_minor
    }

    /// Return the backing inode number.
    #[inline]
    #[must_use]
    pub const fn inode_number(&self) -> u64 {
        let Self { inode_number, .. } = self;

        *inode_number
    }
}

/// File provenance retained for one process mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
// NOTE(invariant): `identity` and `offset` were sampled from the same file-backed VMA while its address-space mapping lock was held.
pub struct FileBacking {
    /// Stable device and inode identity of the backing file.
    identity: FileIdentity,

    /// Byte offset in the backing file corresponding to the mapping start.
    offset: u64,
}

impl FileBacking {
    /// Return the backing file identity.
    #[inline]
    #[must_use]
    pub const fn identity(&self) -> FileIdentity {
        let Self { identity, .. } = self;

        *identity
    }

    /// Return the backing file byte offset at the mapping start.
    #[inline]
    #[must_use]
    pub const fn offset(&self) -> u64 {
        let Self { offset, .. } = self;

        *offset
    }
}

/// Kernel-level backing classification for one mapped process region.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Backing {
    /// Mapping backed by a kernel file object with retained file provenance.
    File(FileBacking),

    /// Private anonymous mapping as classified by the kernel VMA helper.
    Anonymous,

    /// Mapping with neither file backing nor ordinary anonymous classification.
    Special,
}

/// Validated mapped region retained in snapshot address order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(
    clippy::struct_field_names,
    reason = "the established Region representation uses explicit region-prefixed field names"
)]
// NOTE(invariant): The range is nonempty, belongs to an ordered nonoverlapping snapshot, and `region_backing` agrees with the kernel backing attributes and provenance fields.
pub struct Region {
    /// The mapped process virtual address range.
    region_range: ViRange,

    /// The kernel reported attributes.
    region_attributes: Attributes,

    /// Validated mapping backing classification and provenance.
    region_backing: Backing,
}

impl Region {
    /// Determine the mapped virtual address range.
    #[inline]
    #[must_use]
    pub const fn range(&self) -> ViRange {
        let Self { region_range, .. } = self;

        *region_range
    }

    /// Determine the kernel reported attributes.
    #[inline]
    #[must_use]
    pub const fn attributes(&self) -> Attributes {
        let Self {
            region_attributes, ..
        } = self;

        *region_attributes
    }

    /// Determine the validated backing classification for this mapping.
    #[inline]
    #[must_use]
    pub const fn backing(&self) -> Backing {
        let Self { region_backing, .. } = self;

        *region_backing
    }

    /// Determine whether this region contains the supplied process address.
    #[inline]
    #[must_use]
    pub fn contains(&self, target_address: ViAddr) -> bool {
        let Self { region_range, .. } = self;

        region_range.start_address <= target_address && target_address < region_range.end_address
    }
}

bitflags! {
    /// Kernel reported mapped region attributes.
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
    pub struct Attributes: ffi::binding::mirilla_map_layout_attributes_t {
        /// The region is readable.
        const READ = ffi::binding::MIRILLA_MAP_LAYOUT_ATTRIBUTE_READ;

        /// The region is writable.
        const WRITE = ffi::binding::MIRILLA_MAP_LAYOUT_ATTRIBUTE_WRITE;

        /// The region is executable.
        const EXEC = ffi::binding::MIRILLA_MAP_LAYOUT_ATTRIBUTE_EXEC;

        /// The region is anonymous.
        const ANONYMOUS = ffi::binding::MIRILLA_MAP_LAYOUT_ATTRIBUTE_ANONYMOUS;

        /// The region is shared.
        const SHARED = ffi::binding::MIRILLA_MAP_LAYOUT_ATTRIBUTE_SHARED;

        /// The region grows downward as a stack mapping.
        const STACK = ffi::binding::MIRILLA_MAP_LAYOUT_ATTRIBUTE_STACK;

        /// The region is backed by a kernel file object with retained provenance.
        const FILE = ffi::binding::MIRILLA_MAP_LAYOUT_ATTRIBUTE_FILE;
    }
}

/// An owned kernel view of a process address space.
#[derive(Debug, Clone)]
// NOTE(invariant): Regions are nonempty, ordered by address, and pairwise nonoverlapping.
pub struct Snapshot {
    /// The ordered mapped regions.
    region_list: Vec<Region>,

    /// The kernel resident auxiliary vector.
    auxiliary_vector: Vec<AuxiliaryVectorEntry>,

    /// The process environment address range.
    environment_range: ViRange,

    /// The process argument address range.
    argument_range: ViRange,
}

impl Snapshot {
    /// Borrow the ordered mapped regions.
    #[inline]
    #[must_use]
    pub fn regions(&self) -> &[Region] {
        let Self { region_list, .. } = self;

        region_list
    }

    /// Find the unique mapped region containing one process address.
    #[inline]
    #[must_use]
    pub fn region_at(&self, target_address: ViAddr) -> Option<&Region> {
        let Self { region_list, .. } = self;
        let index = region_list.partition_point(|target_region| {
            Region::range(target_region).end_address <= target_address
        });

        region_list
            .get(index)
            .filter(|target_region| Region::contains(target_region, target_address))
    }

    /// Borrow the kernel resident auxiliary vector.
    #[inline]
    #[must_use]
    pub fn auxiliary_vector(&self) -> &[AuxiliaryVectorEntry] {
        let Self {
            auxiliary_vector, ..
        } = self;

        auxiliary_vector
    }
    /// Determine the process environment address range.
    #[inline]
    #[must_use]
    pub const fn environment_range(&self) -> ViRange {
        let Self {
            environment_range, ..
        } = self;

        *environment_range
    }

    /// Determine the process argument address range.
    #[inline]
    #[must_use]
    pub const fn argument_range(&self) -> ViRange {
        let Self { argument_range, .. } = self;

        *argument_range
    }
}

/// An error while capturing or validating a process snapshot.
#[derive(Debug, thiserror::Error)]
pub enum SnapshotError {
    /// The kernel query failed.
    #[error("process address space query failed: {0}")]
    Io(#[source] io::Error),

    /// A kernel region was empty or reversed.
    #[error("invalid mapped region {0:?}")]
    InvalidRegion(ViRange),

    /// A kernel region overlapped its predecessor.
    #[error("overlapping mapped region {0:?}")]
    OverlappingRegion(ViRange),

    /// Kernel mapping attributes described mutually exclusive backing classes.
    #[error("mapped region {0:?} has conflicting backing attributes")]
    ConflictingBackingAttributes(ViRange),

    /// A non-file mapping carried file provenance despite lacking the file attribute.
    #[error("mapped region {0:?} carries file provenance without file backing")]
    UnexpectedFileProvenance(ViRange),
}

impl Process {
    /// Capture the current kernel address space information for this process.
    ///
    /// # Errors
    ///
    /// This returns an error when the kernel query fails or reports malformed regions.
    #[inline]
    pub fn snapshot(&self) -> Result<Snapshot, SnapshotError> {
        let Self(manager_context) = self;
        let engaged = manager_context.engaged();

        // SAFETY: The target handle and identifier are retained by the Catalejo manager.
        let (metadata, layouts, auxiliary) =
            unsafe { ffi::command::address_space_layout(engaged.device(), engaged.id()) }
                .map_err(SnapshotError::Io)?;

        let mut region_list = Vec::<Region>::with_capacity(layouts.len());

        layouts.into_iter().try_for_each(|target_layout| {
            let region_range = ViRange::new(
                ViAddr::new(target_layout.start_address),
                ViAddr::new(target_layout.end_address),
            );
            let region_nonempty = region_range.start_address < region_range.end_address;
            let region_nonoverlap = region_list.last().is_none_or(|target_previous_region| {
                target_previous_region.range().end_address <= region_range.start_address
            });

            match (region_nonempty, region_nonoverlap) {
                (false, _) => Err(SnapshotError::InvalidRegion(region_range)),
                (true, false) => Err(SnapshotError::OverlappingRegion(region_range)),
                (true, true) => {
                    let region_attributes =
                        Attributes::from_bits_retain(target_layout.attribute_list);
                    let file_backed = region_attributes.contains(Attributes::FILE);
                    let anonymous = region_attributes.contains(Attributes::ANONYMOUS);
                    let provenance_clear = target_layout.file_offset == 0
                        && target_layout.device_major == 0
                        && target_layout.device_minor == 0
                        && target_layout.inode_number == 0;
                    let backing_valid = match (file_backed, anonymous, provenance_clear) {
                        (true, false, _) | (false, false | true, true) => Ok(()),
                        (true, true, _) => {
                            Err(SnapshotError::ConflictingBackingAttributes(region_range))
                        }
                        (false, _, false) => {
                            Err(SnapshotError::UnexpectedFileProvenance(region_range))
                        }
                    };

                    backing_valid?;

                    let region_backing = match (file_backed, anonymous) {
                        (true, false) => {
                            let identity = FileIdentity {
                                device_major: target_layout.device_major,
                                device_minor: target_layout.device_minor,
                                inode_number: target_layout.inode_number,
                            };
                            let offset = target_layout.file_offset;
                            let backing = FileBacking { identity, offset };

                            Backing::File(backing)
                        }
                        (false, true) => Backing::Anonymous,
                        (false, false) => Backing::Special,
                        (true, true) => unreachable!(
                            "conflicting backing attributes were rejected before construction"
                        ),
                    };

                    region_list.push(Region {
                        region_range,
                        region_attributes,
                        region_backing,
                    });

                    Ok(())
                }
            }
        })?;

        let auxiliary_vector = auxiliary
            .into_iter()
            .map(|target_entry| AuxiliaryVectorEntry {
                entry_type: target_entry.entry_type,
                entry_value: target_entry.entry_value,
            })
            .collect();
        let environment_range = ViRange::new(
            ViAddr::new(metadata.environment_start),
            ViAddr::new(metadata.environment_end),
        );
        let argument_range = ViRange::new(
            ViAddr::new(metadata.argument_start),
            ViAddr::new(metadata.argument_end),
        );

        Ok(Snapshot {
            region_list,
            auxiliary_vector,
            environment_range,
            argument_range,
        })
    }
}

#[cfg(test)]
mod tests {
    //! Regression coverage for process-region containment and snapshot address lookup.

    use super::*;

    /// Construct one internally valid anonymous region for pure lookup tests.
    fn anonymous_region(target_start: u64, target_end: u64) -> Region {
        let region_range = ViRange::new(ViAddr::new(target_start), ViAddr::new(target_end));
        let region_attributes = Attributes::READ | Attributes::ANONYMOUS;
        let region_backing = Backing::Anonymous;

        Region {
            region_range,
            region_attributes,
            region_backing,
        }
    }

    #[test]
    fn region_containment_is_half_open() {
        let region = anonymous_region(0x1000, 0x2000);

        assert!(region.contains(ViAddr::new(0x1000)));
        assert!(region.contains(ViAddr::new(0x1fff)));
        assert!(!region.contains(ViAddr::new(0x2000)));
        assert_eq!(region.backing(), Backing::Anonymous);
    }

    #[test]
    fn snapshot_address_lookup_selects_the_unique_region() {
        let region_list = vec![
            anonymous_region(0x1000, 0x2000),
            anonymous_region(0x3000, 0x4000),
        ];
        let auxiliary_vector = Vec::new();
        let environment_range = ViRange::new(ViAddr::new(0), ViAddr::new(0));
        let argument_range = ViRange::new(ViAddr::new(0), ViAddr::new(0));
        let snapshot = Snapshot {
            region_list,
            auxiliary_vector,
            environment_range,
            argument_range,
        };

        assert_eq!(
            snapshot.region_at(ViAddr::new(0x3100)).map(Region::range),
            Some(ViRange::new(ViAddr::new(0x3000), ViAddr::new(0x4000)))
        );
        assert!(snapshot.region_at(ViAddr::new(0x2800)).is_none());
    }
}

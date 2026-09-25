//! Kernel-backed process address-space snapshots.
//!
//! Snapshot construction uses only the Catalejo kernel query retained by the parent process handle.
//! No procfs or filesystem process metadata participates in this boundary.

use std::io;

use bitflags::bitflags;
use catalejo::{
    address::{ViAddr, ViRange},
    ffi,
};

use crate::process::Process;

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
// NOTE(invariant): The range is nonempty and `region_backing` agrees with the kernel backing attributes and provenance fields.
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
///
/// This value does not retain the identity of the process that produced it. Callers that later pair
/// a snapshot with a [`Process`] must preserve that relationship.
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

    /// Determine the readable byte extent beginning at one mapped process address.
    ///
    /// The returned extent ends at the containing kernel mapping boundary. Unmapped or unreadable
    /// addresses return [`None`]. The value is suitable for structurally bounding foreign byte
    /// strings without imposing a format-specific size policy.
    #[inline]
    #[must_use]
    pub fn readable_bytes(&self, target_address: ViAddr) -> Option<usize> {
        let region = self.region_at(target_address)?;

        if !region.attributes().contains(Attributes::READ) {
            return None;
        }

        let range = region.range();

        let ViAddr(start) = target_address;

        let ViAddr(end) = range.end_address;

        let bytes = end.checked_sub(start)?;

        usize::try_from(bytes).ok()
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
#[derive(Debug, fack::prelude::Error)]
pub enum SnapshotError {
    /// The kernel query failed.
    #[error("process address space query failed with {0}")]
    #[error(source(0))]
    Io(io::Error),

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
        let engaged = Self::target(self);

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
    fn snapshot_readable_extent_uses_containing_mapping_boundary() {
        let region_list = vec![anonymous_region(0x1000, 0x2000)];
        let snapshot = Snapshot {
            region_list,
            auxiliary_vector: Vec::new(),
            environment_range: ViRange::new(ViAddr::new(0), ViAddr::new(0)),
            argument_range: ViRange::new(ViAddr::new(0), ViAddr::new(0)),
        };

        assert_eq!(snapshot.readable_bytes(ViAddr::new(0x1800)), Some(0x800));
        assert_eq!(snapshot.readable_bytes(ViAddr::new(0x2000)), None);
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

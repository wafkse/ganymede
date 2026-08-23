//! Validated program tables for process-resident ELF images.
//!
//! A loaded image binds one selected ELF class and load bias to the complete program table copied
//! from that image. Executable ranges come only from validated `PT_LOAD` records with `PF_X` and
//! never from path or file-identity coincidence.

extern crate alloc;

use alloc::{boxed::Box, vec::Vec};
use core::mem::MaybeUninit;

use catalejo::{
    address::{ViAddr, ViRange},
    prelude::Unassociated,
};
use ganymede_process::process::{AccessError, Process};
use num_traits::{CheckedAdd, CheckedMul};

use crate::{
    binding,
    class::{Class, ElfClass, Header, ProgramHeader},
    image::LoadBias,
};

/// One nonempty process range proven to be file-backed executable ELF payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
// NOTE(invariant): The range is the checked load-bias translation of a nonempty `PT_LOAD` file extent whose flags include `PF_X` and whose file extent does not exceed its memory extent.
pub struct ExecutableSegment(ViRange);

impl ExecutableSegment {
    /// Return the complete process range containing file-backed executable bytes.
    #[inline]
    #[must_use]
    pub const fn range(self) -> ViRange {
        let Self(range) = self;

        range
    }
}

/// Validated loaded-image header and program table.
#[derive(Debug)]
// NOTE(invariant): The header matches `ClassType`, every program header was copied from its described table through checked class-width arithmetic, and executable segments were derived only from validated program records.
pub struct LoadedImage<'target, ClassType>
where
    ClassType: Class,
{
    /// Process that owns every retained image observation.
    process: &'target Process,

    /// Load bias used for every image-relative translation.
    load_bias: LoadBias<ClassType>,

    /// Program headers retained in original table order.
    program_headers: Box<[ClassType::ProgramHeader]>,

    /// Nonempty executable file ranges retained in program order.
    executables: Box<[ExecutableSegment]>,
}

impl<'target, ClassType> LoadedImage<'target, ClassType>
where
    ClassType: Class,
{
    /// Read and validate one process-resident image header and complete program table.
    ///
    /// # Errors
    ///
    /// This preserves typed process access and copy faults. It rejects wrong ELF identity, invalid
    /// program-table geometry, inconsistent load extents, and selected-width address overflow.
    #[allow(
        clippy::missing_inline_in_public_items,
        reason = "loaded image acquisition copies and validates a foreign program table"
    )]
    pub fn read(
        process: &'target Process,
        load_bias: LoadBias<ClassType>,
    ) -> Result<Self, LoadedImageError> {
        let header_address = load_bias
            .address(ClassType::Word::default())
            .ok_or(LoadedImageError::AddressOverflow)?;
        let header = Self::copy::<ClassType::Header>(process, header_address)?;

        Self::identity(&header)?;

        let actual = header.program_size();
        let expected =
            u16::try_from(core::mem::size_of::<ClassType::ProgramHeader>()).map_err(|_| {
                LoadedImageError::ProgramHeaderSize {
                    actual,
                    expected: u16::MAX,
                }
            })?;

        if actual != expected {
            return Err(LoadedImageError::ProgramHeaderSize { actual, expected });
        }

        let count = usize::from(header.program_count());

        if count == 0 {
            return Err(LoadedImageError::ProgramHeaderCount);
        }

        let program_headers = Self::programs(process, load_bias, &header, count)?;
        let executables = Self::executables(load_bias, &program_headers)?;
        let program_headers = program_headers.into_boxed_slice();
        let executables = executables.into_boxed_slice();

        Ok(Self {
            process,
            load_bias,
            program_headers,
            executables,
        })
    }

    /// Copy one complete foreign record through the process access capability.
    fn copy<ValueType>(process: &Process, address: ViAddr) -> Result<ValueType, LoadedImageError>
    where
        ValueType: Unassociated + Copy,
    {
        let foreign = process.open::<ValueType>(address)?;
        let mut storage = MaybeUninit::<ValueType>::uninit();
        let value = foreign
            .copy(&mut storage)
            .map_err(|_| LoadedImageError::Fault(address))?;

        Ok(*value)
    }

    /// Validate ELF magic, class, and little-endian identity.
    fn identity(header: &ClassType::Header) -> Result<(), LoadedImageError> {
        let identity = header.identity();
        let magic = identity.get(..4);
        let class = identity.get(binding::EI_CLASS as usize).copied();
        let data = identity.get(binding::EI_DATA as usize).copied();
        let expected_class = match ClassType::CLASS {
            ElfClass::Elf32 => binding::ELFCLASS32,
            ElfClass::Elf64 => binding::ELFCLASS64,
        };
        let expected_class = u8::try_from(expected_class)
            .map_err(|_| LoadedImageError::Identity(ClassType::CLASS))?;
        let expected_data = u8::try_from(binding::ELFDATA2LSB)
            .map_err(|_| LoadedImageError::Identity(ClassType::CLASS))?;
        let valid = magic == Some(b"\x7fELF".as_slice())
            && class == Some(expected_class)
            && data == Some(expected_data);

        if valid {
            Ok(())
        } else {
            Err(LoadedImageError::Identity(ClassType::CLASS))
        }
    }

    /// Read the complete program table described by one validated header.
    fn programs(
        process: &Process,
        load_bias: LoadBias<ClassType>,
        header: &ClassType::Header,
        count: usize,
    ) -> Result<Vec<ClassType::ProgramHeader>, LoadedImageError> {
        let stride = u64::from(header.program_size());
        let stride = ClassType::Word::try_from(stride)
            .ok()
            .ok_or(LoadedImageError::AddressOverflow)?;
        let table = header.program_offset();
        let mut program_headers = Vec::with_capacity(count);

        for index in 0..count {
            let index = u64::try_from(index).map_err(|_| LoadedImageError::AddressOverflow)?;
            let index = ClassType::Word::try_from(index)
                .ok()
                .ok_or(LoadedImageError::AddressOverflow)?;
            let offset = index
                .checked_mul(&stride)
                .and_then(|offset| table.checked_add(&offset))
                .ok_or(LoadedImageError::AddressOverflow)?;
            let address = load_bias
                .address(offset)
                .ok_or(LoadedImageError::AddressOverflow)?;
            let program_header = Self::copy::<ClassType::ProgramHeader>(process, address)?;

            program_headers.push(program_header);
        }

        Ok(program_headers)
    }

    /// Derive every executable file range from validated load records.
    fn executables(
        load_bias: LoadBias<ClassType>,
        program_headers: &[ClassType::ProgramHeader],
    ) -> Result<Vec<ExecutableSegment>, LoadedImageError> {
        let mut executables = Vec::new();

        for (index, program_header) in program_headers.iter().enumerate() {
            if program_header.kind() != binding::PT_LOAD as u32 {
                continue;
            }

            let file = program_header.file();
            let memory = program_header.memory();

            if file > memory {
                return Err(LoadedImageError::FileExceedsMemory { index });
            }

            let executable = program_header.flags() & binding::PF_X as u32 != 0;

            if !executable || file == ClassType::Word::default() {
                continue;
            }

            let range = load_bias
                .range(program_header.address(), file)
                .ok_or(LoadedImageError::AddressOverflow)?;

            executables.push(ExecutableSegment(range));
        }

        Ok(executables)
    }

    /// Borrow the process that supplied this image.
    #[inline]
    #[must_use]
    pub const fn process(&self) -> &'target Process {
        let Self { process, .. } = self;

        process
    }

    /// Return the selected-width load bias used by this image.
    #[inline]
    #[must_use]
    pub const fn load_bias(&self) -> LoadBias<ClassType> {
        let Self { load_bias, .. } = self;

        *load_bias
    }

    /// Borrow program headers in their original table order.
    #[inline]
    #[must_use]
    pub fn program_headers(&self) -> &[ClassType::ProgramHeader] {
        let Self {
            program_headers, ..
        } = self;

        program_headers
    }

    /// Borrow nonempty executable file ranges in original program order.
    #[inline]
    #[must_use]
    pub fn executable_segments(&self) -> &[ExecutableSegment] {
        let Self { executables, .. } = self;

        executables
    }

    /// Resolve one live dynamic-table pointer against this image.
    ///
    /// GNU loaders relocate pointer-valued dynamic entries in memory. An unrelocated image value
    /// is still accepted when adding the load bias places it inside a validated `PT_LOAD` segment.
    #[inline]
    pub fn resolve_dynamic_pointer(&self, target_pointer: ClassType::Word) -> Option<ViAddr> {
        let Self {
            load_bias,
            program_headers,
            ..
        } = self;

        Self::resolve_pointer(*load_bias, program_headers, target_pointer)
    }

    /// Resolve one pointer against supplied validated image geometry.
    fn resolve_pointer(
        target_load_bias: LoadBias<ClassType>,
        target_program_headers: &[ClassType::ProgramHeader],
        target_pointer: ClassType::Word,
    ) -> Option<ViAddr> {
        let absolute = ViAddr::new(target_pointer.into());

        if Self::contains_load(target_load_bias, target_program_headers, absolute) {
            return Some(absolute);
        }

        target_load_bias
            .address(target_pointer)
            .filter(|target_address| {
                Self::contains_load(target_load_bias, target_program_headers, *target_address)
            })
    }

    /// Determine whether one process address belongs to a validated load segment.
    #[inline]
    #[must_use]
    pub fn contains(&self, target_address: ViAddr) -> bool {
        let Self {
            load_bias,
            program_headers,
            ..
        } = self;

        Self::contains_load(*load_bias, program_headers, target_address)
    }

    /// Return the bytes remaining in the load segment containing one process address.
    ///
    /// The extent is derived from validated `PT_LOAD` memory geometry. An address outside every
    /// load segment or an extent that cannot fit host indexing returns [`None`].
    #[inline]
    #[must_use]
    pub fn load_bytes(&self, target_address: ViAddr) -> Option<usize> {
        let Self {
            load_bias,
            program_headers,
            ..
        } = self;

        program_headers.iter().find_map(|target_header| {
            if target_header.kind() != binding::PT_LOAD as u32 {
                return None;
            }

            let range = load_bias.range(target_header.address(), target_header.memory())?;
            let contains =
                range.start_address <= target_address && target_address < range.end_address;

            if !contains {
                return None;
            }

            let ViAddr(address) = target_address;
            let ViAddr(end) = range.end_address;
            let bytes = end.checked_sub(address)?;

            usize::try_from(bytes).ok()
        })
    }

    /// Return the exact process range of the unique nonempty dynamic segment.
    ///
    /// Multiple `PT_DYNAMIC` records are rejected by returning [`None`] because no unique table can
    /// be proven from the program table. File extent must not exceed memory extent.
    #[inline]
    #[must_use]
    pub fn dynamic_range(&self) -> Option<ViRange> {
        let Self {
            load_bias,
            program_headers,
            ..
        } = self;
        let mut dynamic = None;

        for target_header in program_headers {
            if target_header.kind() != binding::PT_DYNAMIC as u32 {
                continue;
            }

            let file = target_header.file();
            let memory = target_header.memory();

            if file > memory || memory == ClassType::Word::default() {
                return None;
            }

            let range = load_bias.range(target_header.address(), memory)?;

            if dynamic.replace(range).is_some() {
                return None;
            }
        }

        dynamic
    }

    /// Determine whether one process address belongs to a validated load segment.
    fn contains_load(
        target_load_bias: LoadBias<ClassType>,
        target_program_headers: &[ClassType::ProgramHeader],
        target_address: ViAddr,
    ) -> bool {
        target_program_headers.iter().any(|target_header| {
            if target_header.kind() != binding::PT_LOAD as u32 {
                return false;
            }

            target_load_bias
                .range(target_header.address(), target_header.memory())
                .is_some_and(|target_range| {
                    target_range.start_address <= target_address
                        && target_address < target_range.end_address
                })
        })
    }
}

/// Failure while validating one process-resident loaded image.
#[derive(Debug, fack::prelude::Error)]
pub enum LoadedImageError {
    /// Typed process access could not be opened.
    #[error(transparent(0))]
    Access(AccessError),

    /// A protected typed copy faulted.
    #[error("foreign ELF record faulted at {0:?}")]
    Fault(ViAddr),

    /// The loaded image did not begin with a supported ELF identity.
    #[error("loaded image has invalid or unsupported {0:?} ELF identity")]
    Identity(ElfClass),

    /// The program-header entry size differs from the selected generated representation.
    #[error("loaded image program-header size {actual} differs from expected {expected}")]
    ProgramHeaderSize {
        /// Entry size observed in the ELF header.
        actual: u16,

        /// Generated representation size.
        expected: u16,
    },

    /// The program-header table is empty.
    #[error("loaded image has no program headers")]
    ProgramHeaderCount,

    /// One load segment has an impossible file and memory extent relationship.
    #[error("loaded image program header {index} has a file extent larger than memory")]
    FileExceedsMemory {
        /// Program-header index containing the invalid relationship.
        index: usize,
    },

    /// Address arithmetic overflowed in the selected ELF width.
    #[error("loaded image address arithmetic overflowed")]
    AddressOverflow,
}

impl From<AccessError> for LoadedImageError {
    #[inline]
    fn from(source: AccessError) -> Self {
        Self::Access(source)
    }
}

/// ELF32 loaded image.
pub type Elf32LoadedImage<'target> = LoadedImage<'target, crate::class::Elf32>;

/// ELF64 loaded image.
pub type Elf64LoadedImage<'target> = LoadedImage<'target, crate::class::Elf64>;

#[cfg(test)]
mod tests {
    //! Dynamic pointer translation coverage independent of process acquisition.

    use super::*;
    use crate::class::Elf64;

    #[test]
    fn live_dynamic_pointers_resolve_absolute_before_relative() {
        let program_headers = [binding::Elf64_Phdr {
            p_type: binding::PT_LOAD as u32,
            p_flags: binding::PF_R as u32,
            p_offset: 0,
            p_vaddr: 0,
            p_paddr: 0,
            p_filesz: 0x1000,
            p_memsz: 0x1000,
            p_align: 0x1000,
        }];
        let load_bias = LoadBias::<Elf64>::new(0x5000);

        assert_eq!(
            LoadedImage::<Elf64>::resolve_pointer(load_bias, &program_headers, 0x5010,),
            Some(ViAddr::new(0x5010))
        );
        assert_eq!(
            LoadedImage::<Elf64>::resolve_pointer(load_bias, &program_headers, 0x10),
            Some(ViAddr::new(0x5010))
        );
        assert_eq!(
            LoadedImage::<Elf64>::resolve_pointer(load_bias, &program_headers, 0x7000,),
            None
        );
    }
}

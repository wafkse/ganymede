//! Validation of running ELF images from process metadata and foreign memory.
//!
//! The complete image algorithm is shared by ELF32 and ELF64. One compile-time class family selects
//! the generated program-header representation and target word width. Kernel auxiliary values are
//! narrowed into that width before address arithmetic, and only proven runtime addresses become
//! [`ViAddr`] values.

extern crate alloc;

use alloc::{boxed::Box, vec::Vec};
use core::mem::MaybeUninit;

use catalejo::{address::ViAddr, ffi};
use ganymede_process::process::{AccessError, Process, ReadError, Snapshot};
use ganymede_text::BytePath;
use num_traits::{CheckedAdd, CheckedMul, CheckedSub};

use crate::{
    binding,
    class::{Class, Elf32, Elf64, ElfClass, ElfClassError, ProgramHeader},
    dynamic::{DynamicSymbols, DynamicSymbolsError},
    image::LoadBias,
    lift::{Dynamic, ElfError},
    symbol::Symbol,
};

/// Address calculation that can overflow while interpreting a process-resident ELF image.
#[derive(Debug, Clone, Copy, PartialEq, Eq, fack::prelude::Error)]
pub enum AddressOperation {
    /// Computing a byte offset into the program-header table.
    #[error("indexing the program-header table")]
    ProgramHeaderOffset,

    /// Locating one process-resident program header.
    #[error("locating a program header")]
    ProgramHeader,

    /// Deriving the main-image load bias from `AT_PHDR` and `PT_PHDR`.
    #[error("deriving the main-image load bias")]
    LoadBias,

    /// Translating the interpreter virtual address into the process address space.
    #[error("locating the interpreter path")]
    Interpreter,

    /// Translating the dynamic-segment virtual address into the process address space.
    #[error("locating the dynamic table")]
    Dynamic,
}

/// Runtime location and extent of the unique `PT_DYNAMIC` segment for one ELF class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// NOTE(invariant): `address` is produced by checked class-width load-bias translation and `size` is the selected-class `p_memsz` after proving it covers the complete file extent.
pub struct DynamicSegment<ClassType>
where
    ClassType: Class,
{
    /// Runtime address of the first dynamic entry.
    address: ViAddr,

    /// Validated in-memory dynamic-segment extent in the selected ELF width.
    size: ClassType::Word,
}

impl<ClassType> DynamicSegment<ClassType>
where
    ClassType: Class,
{
    /// Return the runtime dynamic-table address.
    #[inline]
    #[must_use]
    pub const fn address(&self) -> ViAddr {
        let Self { address, .. } = self;

        *address
    }

    /// Return the dynamic segment memory size without widening it.
    #[inline]
    #[must_use]
    pub const fn size(&self) -> ClassType::Word {
        let Self { size, .. } = self;

        *size
    }
}

/// Segment relationships proven before a process image can be constructed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// NOTE(invariant): `load_bias` is derived from the unique `PT_PHDR`, `interpreter_address` and `dynamic` are translated with that same bias, and `interpreter_size` is nonzero, host-representable, and covered by its segment memory extent.
struct Segments<ClassType>
where
    ClassType: Class,
{
    /// Main-image load bias proven from `AT_PHDR` and `PT_PHDR`.
    load_bias: LoadBias<ClassType>,

    /// Runtime address of the validated interpreter payload.
    interpreter_address: ViAddr,

    /// Validated interpreter file extent in the selected ELF width.
    interpreter_size: ClassType::Word,

    /// Runtime location and validated extent of the dynamic segment.
    dynamic: DynamicSegment<ClassType>,
}

/// Process-bound ELF image observation for one selected class.
///
/// This capability retains the exact process handle and kernel snapshot used to construct the
/// validated image. Downstream format consumers can therefore reuse the image without accepting a
/// separately supplied process or snapshot that could describe another observation context.
#[derive(Debug)]
// NOTE(invariant): `image` was constructed from exactly `process` and `snapshot` during `read`, and no public constructor can assemble the three fields independently.
pub struct Observation<'target, ClassType>
where
    ClassType: Class,
{
    /// Attached process used to read the ELF image.
    process: &'target Process,

    /// Kernel process snapshot used for auxiliary metadata.
    snapshot: &'target Snapshot,

    /// Validated ELF image derived from this process observation.
    image: ProcessImage<ClassType>,
}

impl<'target, ClassType> Observation<'target, ClassType>
where
    ClassType: Class,
{
    /// Read one class-specific ELF image and bind it to its process observation.
    ///
    /// # Errors
    ///
    /// This returns the same validation and foreign-access failures as [`ProcessImage::read`].
    #[inline]
    pub fn read(
        target_process: &'target Process,
        target_snapshot: &'target Snapshot,
    ) -> Result<Self, ProcessImageError> {
        let image = ProcessImage::read(target_process, target_snapshot)?;

        Ok(Self {
            process: target_process,
            snapshot: target_snapshot,
            image,
        })
    }

    /// Return the exact process handle used to construct this observation.
    #[inline]
    #[must_use]
    pub const fn process(&self) -> &'target Process {
        let Self { process, .. } = self;

        process
    }

    /// Return the exact kernel snapshot used to construct this observation.
    #[inline]
    #[must_use]
    pub const fn snapshot(&self) -> &'target Snapshot {
        let Self { snapshot, .. } = self;

        snapshot
    }

    /// Borrow the validated ELF image tied to this observation.
    #[inline]
    #[must_use]
    pub const fn image(&self) -> &ProcessImage<ClassType> {
        let Self { image, .. } = self;

        image
    }
}

/// Validated main image for one selected ELF class.
///
/// Construction ties Linux auxiliary metadata to the process-resident program-header table, proves
/// the load bias from the unique `PT_PHDR`, validates exact interpreter bytes, and retains the unique
/// dynamic segment from validated segment geometry.
#[derive(Debug, Clone)]
// NOTE(invariant): The runtime class equals `ClassType`, every auxiliary address fits `ClassType::Word`, program headers retain the matching generated representation, and `PT_PHDR`, `PT_INTERP`, and `PT_DYNAMIC` satisfy the uniqueness and extent checks performed during construction.
pub struct ProcessImage<ClassType>
where
    ClassType: Class,
{
    /// Proven main-image load bias in the selected ELF width.
    load_bias: LoadBias<ClassType>,

    /// Owned process-resident program headers in original table order.
    program_headers: Box<[ClassType::ProgramHeader]>,

    /// Exact interpreter path bytes without the validated final NUL.
    interpreter: BytePath,

    /// Runtime location and extent of the unique dynamic segment.
    dynamic: DynamicSegment<ClassType>,
}

impl<ClassType> ProcessImage<ClassType>
where
    ClassType: Class,
{
    /// Read and validate the main image described by one process snapshot.
    ///
    /// The runtime class must match `ClassType`. Kernel-widened auxiliary values are narrowed before
    /// program-table arithmetic, so an ELF32 image cannot accidentally inherit observer-width
    /// calculations.
    ///
    /// # Errors
    ///
    /// This fails when class proof, auxiliary metadata, program headers, interpreter bytes, dynamic
    /// segment geometry, or protected process reads violate the image invariants.
    #[inline]
    pub fn read(
        target_process: &Process,
        target_snapshot: &Snapshot,
    ) -> Result<Self, ProcessImageError> {
        let class = ElfClass::from_snapshot(target_snapshot)?;

        if class != ClassType::CLASS {
            return Err(ProcessImageError::UnsupportedClass {
                expected: ClassType::CLASS,
                actual: class,
            });
        }

        let target_phdr = Self::auxiliary(target_snapshot, binding::AT_PHDR)?;
        let target_phnum = Self::auxiliary(target_snapshot, binding::AT_PHNUM)?;
        let target_phent = Self::auxiliary(target_snapshot, binding::AT_PHENT)?;

        Self::table(target_phnum, target_phent)?;

        let program_headers =
            Self::headers(target_process, target_phdr, target_phnum, target_phent)?;
        let segments = Self::segments(target_phdr, &program_headers)?;
        let Segments {
            load_bias,
            interpreter_address,
            interpreter_size,
            dynamic,
        } = segments;
        let interpreter_count: usize = interpreter_size
            .try_into()
            .map_err(|_| ProcessImageError::InvalidInterpreterSize(interpreter_size.into()))?;
        let interpreter_bytes =
            Process::read_bytes(target_process, interpreter_address, interpreter_count)?;
        let interpreter = Self::path(&interpreter_bytes)?;
        let program_headers = program_headers.into_boxed_slice();

        Ok(Self {
            load_bias,
            program_headers,
            interpreter,
            dynamic,
        })
    }

    /// Borrow the proven main-image load bias.
    #[inline]
    #[must_use]
    pub const fn load_bias(&self) -> &LoadBias<ClassType> {
        let Self { load_bias, .. } = self;

        load_bias
    }

    /// Borrow the owned program-header table in process table order.
    #[inline]
    #[must_use]
    pub fn program_headers(&self) -> &[ClassType::ProgramHeader] {
        let Self {
            program_headers, ..
        } = self;

        program_headers
    }

    /// Borrow the exact interpreter path bytes.
    #[inline]
    #[must_use]
    pub const fn interpreter(&self) -> &BytePath {
        let Self { interpreter, .. } = self;

        interpreter
    }

    /// Return the validated dynamic segment.
    #[inline]
    #[must_use]
    pub const fn dynamic(&self) -> DynamicSegment<ClassType> {
        let Self { dynamic, .. } = self;

        *dynamic
    }

    /// Read one required auxiliary value exactly once and prove it fits the selected ELF width.
    fn auxiliary(
        target_snapshot: &Snapshot,
        target_entry_type: u64,
    ) -> Result<ClassType::Word, ProcessImageError> {
        let mut value = None;

        Snapshot::auxiliary_vector(target_snapshot)
            .iter()
            .try_for_each(|target_entry| {
                let matches_type = target_entry.entry_type() == target_entry_type;

                if !matches_type {
                    return Ok(());
                }

                if value.replace(target_entry.entry_value()).is_some() {
                    return Err(ProcessImageError::DuplicateAuxiliary(target_entry_type));
                }

                Ok(())
            })?;

        let value = value.ok_or(ProcessImageError::MissingAuxiliary(target_entry_type))?;

        ClassType::Word::try_from(value)
            .ok()
            .ok_or(ProcessImageError::AuxiliaryOutOfRange {
                class: ClassType::CLASS,
                entry_type: target_entry_type,
                value,
            })
    }

    /// Validate the program-header count and generated entry stride.
    fn table(
        target_count: ClassType::Word,
        target_stride: ClassType::Word,
    ) -> Result<(), ProcessImageError> {
        let count: Option<usize> = target_count.try_into().ok();
        let count_valid = count.is_some_and(|target_count| target_count != 0);
        let host_stride = u64::try_from(core::mem::size_of::<ClassType::ProgramHeader>())
            .map_err(|_| ProcessImageError::InvalidClassLayout(ClassType::CLASS))?;
        let expected_stride = ClassType::Word::try_from(host_stride)
            .ok()
            .ok_or(ProcessImageError::InvalidClassLayout(ClassType::CLASS))?;
        let stride_valid = target_stride == expected_stride;

        if !count_valid {
            return Err(ProcessImageError::InvalidProgramHeaderCount(
                target_count.into(),
            ));
        }

        if !stride_valid {
            return Err(ProcessImageError::InvalidProgramHeaderSize(
                target_stride.into(),
            ));
        }

        Ok(())
    }

    /// Copy the validated process-resident program-header table into matching raw records.
    fn headers(
        target_process: &Process,
        target_phdr: ClassType::Word,
        target_phnum: ClassType::Word,
        target_phent: ClassType::Word,
    ) -> Result<Vec<ClassType::ProgramHeader>, ProcessImageError> {
        let capacity: usize = target_phnum
            .try_into()
            .map_err(|_| ProcessImageError::InvalidProgramHeaderCount(target_phnum.into()))?;
        let mut program_headers = Vec::with_capacity(capacity);

        for index in 0..capacity {
            let index = u64::try_from(index)
                .ok()
                .and_then(|target_index| ClassType::Word::try_from(target_index).ok())
                .ok_or(ProcessImageError::AddressOverflow(
                    AddressOperation::ProgramHeaderOffset,
                ))?;
            let offset =
                index
                    .checked_mul(&target_phent)
                    .ok_or(ProcessImageError::AddressOverflow(
                        AddressOperation::ProgramHeaderOffset,
                    ))?;
            let address = target_phdr
                .checked_add(&offset)
                .map(Into::<ffi::binding::virtual_address_t>::into)
                .map(ViAddr::new)
                .ok_or(ProcessImageError::AddressOverflow(
                    AddressOperation::ProgramHeader,
                ))?;
            let foreign = Process::open::<ClassType::ProgramHeader>(target_process, address)
                .map_err(|target_error| match target_error {
                    AccessError::Io(target_error) => ProcessImageError::Io(target_error),
                    AccessError::Unavailable(..) => ProcessImageError::ForeignAccess(address),
                })?;
            let mut storage = MaybeUninit::<ClassType::ProgramHeader>::uninit();
            let program_header =
                foreign
                    .copy(&mut storage)
                    .map_err(|_| ProcessImageError::Lift {
                        address,
                        source: ElfError::Faulted,
                    })?;

            program_headers.push(*program_header);
        }

        Ok(program_headers)
    }

    /// Derive load bias and validate the unique interpreter and dynamic segments.
    fn segments(
        target_phdr: ClassType::Word,
        target_headers: &[ClassType::ProgramHeader],
    ) -> Result<Segments<ClassType>, ProcessImageError> {
        let mut load_bias_value = None;
        let mut interpreter_segment = None;
        let mut dynamic_segment = None;

        target_headers.iter().try_for_each(|target_header| {
            let kind = ProgramHeader::kind(target_header);
            let address = ProgramHeader::address(target_header);
            let file = ProgramHeader::file(target_header);
            let memory = ProgramHeader::memory(target_header);
            if kind == binding::PT_PHDR as u32 {
                let value =
                    target_phdr
                        .checked_sub(&address)
                        .ok_or(ProcessImageError::AddressOverflow(
                            AddressOperation::LoadBias,
                        ))?;

                if load_bias_value.replace(value).is_some() {
                    return Err(ProcessImageError::DuplicateProgramHeaderSegment);
                }

                return Ok(());
            }

            if kind == binding::PT_INTERP as u32 {
                if interpreter_segment
                    .replace((address, file, memory))
                    .is_some()
                {
                    return Err(ProcessImageError::DuplicateInterpreter);
                }

                return Ok(());
            }

            if kind == binding::PT_DYNAMIC as u32
                && dynamic_segment.replace((address, file, memory)).is_some()
            {
                return Err(ProcessImageError::DuplicateDynamicSegment);
            }

            Ok(())
        })?;

        let load_bias_value =
            load_bias_value.ok_or(ProcessImageError::MissingProgramHeaderSegment)?;
        let (interpreter_virtual, interpreter_size, interpreter_memory) =
            interpreter_segment.ok_or(ProcessImageError::MissingInterpreter)?;
        let interpreter_size_host: Option<usize> = interpreter_size.try_into().ok();
        let interpreter_size_valid =
            interpreter_size_host.is_some_and(|target_size| target_size != 0);
        let interpreter_memory_valid = interpreter_size <= interpreter_memory;

        if !interpreter_size_valid {
            return Err(ProcessImageError::InvalidInterpreterSize(
                interpreter_size.into(),
            ));
        }

        if !interpreter_memory_valid {
            return Err(ProcessImageError::InterpreterFileSizeExceedsMemory);
        }

        let (dynamic_virtual, dynamic_file_size, dynamic_size) =
            dynamic_segment.ok_or(ProcessImageError::MissingDynamicSegment)?;

        if dynamic_file_size > dynamic_size {
            return Err(ProcessImageError::DynamicFileSizeExceedsMemory);
        }

        let load_bias = LoadBias::<ClassType>::new(load_bias_value);
        let interpreter_address =
            load_bias
                .address(interpreter_virtual)
                .ok_or(ProcessImageError::AddressOverflow(
                    AddressOperation::Interpreter,
                ))?;
        let dynamic_address =
            load_bias
                .address(dynamic_virtual)
                .ok_or(ProcessImageError::AddressOverflow(
                    AddressOperation::Dynamic,
                ))?;
        let dynamic = DynamicSegment::<ClassType> {
            address: dynamic_address,
            size: dynamic_size,
        };

        Ok(Segments {
            load_bias,
            interpreter_address,
            interpreter_size,
            dynamic,
        })
    }

    /// Validate the exact interpreter payload and retain path bytes without its final NUL.
    fn path(target_payload: &[u8]) -> Result<BytePath, ProcessImageError> {
        let (&terminator, path) = target_payload
            .split_last()
            .ok_or(ProcessImageError::MissingInterpreterTerminator)?;
        if terminator != 0 {
            return Err(ProcessImageError::MissingInterpreterTerminator);
        }

        if path.contains(&0) {
            return Err(ProcessImageError::InteriorInterpreterTerminator);
        }

        Ok(BytePath::new(path))
    }
}

impl<ClassType> ProcessImage<ClassType>
where
    ClassType: Class,
    Dynamic<ClassType>:
        catalejo::prelude::Lift<Value = ClassType::Dynamic, Context = (), Error = ElfError>,
    Symbol<ClassType>:
        catalejo::prelude::Lift<Value = ClassType::Symbol, Context = (), Error = ElfError>,
{
    /// Discover process-resident dynamic symbols for this validated image.
    ///
    /// # Errors
    ///
    /// This returns an error when dynamic metadata, hash metadata, or foreign symbol tables violate
    /// their validated image geometry.
    #[inline]
    pub fn dynamic_symbols(
        &self,
        target_process: &Process,
    ) -> Result<DynamicSymbols<ClassType>, DynamicSymbolsError> {
        let Self {
            load_bias, dynamic, ..
        } = self;
        let image = crate::loaded::LoadedImage::<ClassType>::read(target_process, *load_bias)?;

        DynamicSymbols::read_loaded(&image, dynamic.address())
    }
}

/// Failure while interpreting a running ELF image.
#[derive(Debug, fack::prelude::Error)]
pub enum ProcessImageError {
    /// ELF class proof failed.
    #[error(transparent(0))]
    Class(ElfClassError),

    /// The process class differs from the class selected by the caller's image type.
    #[error("expected {expected:?} but process image is {actual:?}")]
    UnsupportedClass {
        /// Compile-time class requested by the image type.
        expected: ElfClass,

        /// Runtime class proven from process metadata.
        actual: ElfClass,
    },

    /// Required auxiliary metadata is absent.
    #[error("missing auxiliary vector entry {0}")]
    MissingAuxiliary(u64),

    /// Required auxiliary metadata appears more than once.
    #[error("duplicate auxiliary vector entry {0}")]
    DuplicateAuxiliary(u64),

    /// Kernel-widened auxiliary metadata does not fit the selected ELF class.
    #[error("auxiliary vector entry {entry_type} value {value} exceeds {class:?} width")]
    AuxiliaryOutOfRange {
        /// Selected ELF class.
        class: ElfClass,

        /// Auxiliary vector key.
        entry_type: u64,

        /// Kernel-widened value that did not fit.
        value: u64,
    },

    /// The sealed class family selected a generated layout that cannot fit its own word width.
    #[error("generated layout does not fit {0:?}")]
    InvalidClassLayout(ElfClass),

    /// Program-header count is empty or cannot fit host indexing.
    #[error("invalid ELF program header count {0}")]
    InvalidProgramHeaderCount(u64),

    /// Program-header stride does not match the selected generated representation.
    #[error("invalid ELF program header size {0}")]
    InvalidProgramHeaderSize(u64),

    /// Main image contains multiple `PT_PHDR` segments.
    #[error("duplicate PT_PHDR segment")]
    DuplicateProgramHeaderSegment,

    /// Main image has no `PT_PHDR` segment.
    #[error("missing PT_PHDR segment")]
    MissingProgramHeaderSegment,

    /// Main image contains multiple interpreter segments.
    #[error("duplicate PT_INTERP segment")]
    DuplicateInterpreter,

    /// Main image has no interpreter segment.
    #[error("missing PT_INTERP segment")]
    MissingInterpreter,

    /// Interpreter payload is empty or cannot fit host indexing.
    #[error("invalid interpreter size {0}")]
    InvalidInterpreterSize(u64),

    /// Interpreter file extent exceeds memory extent.
    #[error("interpreter file size exceeds memory size")]
    InterpreterFileSizeExceedsMemory,

    /// Interpreter payload lacks its final NUL byte.
    #[error("interpreter path lacks a final NUL byte")]
    MissingInterpreterTerminator,

    /// Interpreter payload contains an interior NUL byte.
    #[error("interpreter path contains an interior NUL byte")]
    InteriorInterpreterTerminator,

    /// Main image contains multiple dynamic segments.
    #[error("duplicate PT_DYNAMIC segment")]
    DuplicateDynamicSegment,

    /// Main image has no dynamic segment.
    #[error("missing PT_DYNAMIC segment")]
    MissingDynamicSegment,

    /// Dynamic file extent exceeds memory extent.
    #[error("dynamic file size exceeds memory size")]
    DynamicFileSizeExceedsMemory,

    /// Checked target-width address derivation overflowed.
    #[error("target address overflow while {0}")]
    AddressOverflow(AddressOperation),

    /// Catalejo failed while opening foreign process access.
    #[error(transparent(0))]
    Io(std::io::Error),

    /// A required process-resident program header cannot be opened.
    #[error("foreign ELF program header is unavailable at {0:?}")]
    ForeignAccess(ViAddr),

    /// A protected ELF record copy failed at a foreign address.
    #[error("ELF record copy failed at {address:?} with {source}")]
    #[error(source(source))]
    Lift {
        /// Foreign ELF structure address.
        address: ViAddr,

        /// ELF copy failure.
        source: ElfError,
    },

    /// A foreign process byte read failed.
    #[error(transparent(0))]
    Read(ReadError),
}

impl From<ElfClassError> for ProcessImageError {
    #[inline]
    fn from(source: ElfClassError) -> Self {
        Self::Class(source)
    }
}

impl From<std::io::Error> for ProcessImageError {
    #[inline]
    fn from(source: std::io::Error) -> Self {
        Self::Io(source)
    }
}

impl From<ReadError> for ProcessImageError {
    #[inline]
    fn from(source: ReadError) -> Self {
        Self::Read(source)
    }
}

/// Process-bound validated ELF32 image observation.
pub type Elf32Observation<'target> = Observation<'target, Elf32>;

/// Process-bound validated ELF64 image observation.
pub type Elf64Observation<'target> = Observation<'target, Elf64>;

/// Validated ELF32 dynamic segment.
pub type Elf32DynamicSegment = DynamicSegment<Elf32>;

/// Validated ELF64 dynamic segment.
pub type Elf64DynamicSegment = DynamicSegment<Elf64>;

/// Validated ELF32 process image.
pub type Elf32ProcessImage = ProcessImage<Elf32>;

/// Validated ELF64 process image.
pub type Elf64ProcessImage = ProcessImage<Elf64>;

/// Compatibility name for ELF32 process-image failures.
pub type Elf32ProcessImageError = ProcessImageError;

/// Compatibility name for ELF64 process-image failures.
pub type Elf64ProcessImageError = ProcessImageError;

#[cfg(test)]
mod tests {
    //! Regression coverage for shared image validation and class-width segment derivation.

    use super::*;

    /// Extract one successful test result without unwrap-family shortcuts.
    fn test_ok<T, E: core::fmt::Debug>(target_result: Result<T, E>) -> T {
        target_result.expect("test operation should succeed")
    }

    #[test]
    fn program_table_validation_uses_each_generated_stride() {
        let stride32 = u32::try_from(core::mem::size_of::<binding::Elf32_Phdr>())
            .expect("ELF32 program-header size must fit u32");
        let stride64 = u64::try_from(core::mem::size_of::<binding::Elf64_Phdr>())
            .expect("ELF64 program-header size must fit u64");

        assert!(ProcessImage::<Elf32>::table(1, stride32).is_ok());
        assert!(ProcessImage::<Elf64>::table(1, stride64).is_ok());
        assert!(ProcessImage::<Elf32>::table(0, stride32).is_err());
        assert!(ProcessImage::<Elf64>::table(5, stride64).is_ok());
    }

    #[test]
    fn interpreter_path_preserves_exact_bytes() {
        let path = test_ok(ProcessImage::<Elf64>::path(b"/lib/ld.so\0"));

        assert_eq!(&*path, b"/lib/ld.so");
        assert!(ProcessImage::<Elf32>::path(b"/lib/ld.so").is_err());
        assert!(ProcessImage::<Elf64>::path(b"/lib\0/ld.so\0").is_err());
    }

    #[test]
    fn elf32_segment_derivation_preserves_32_bit_width() {
        let headers = [
            binding::Elf32_Phdr {
                p_type: binding::PT_PHDR as u32,
                p_offset: 0,
                p_vaddr: 0x34,
                p_paddr: 0,
                p_filesz: 0,
                p_memsz: 0,
                p_flags: 0,
                p_align: 0,
            },
            binding::Elf32_Phdr {
                p_type: binding::PT_INTERP as u32,
                p_offset: 0,
                p_vaddr: 0x200,
                p_paddr: 0,
                p_filesz: 24,
                p_memsz: 24,
                p_flags: 0,
                p_align: 1,
            },
            binding::Elf32_Phdr {
                p_type: binding::PT_DYNAMIC as u32,
                p_offset: 0,
                p_vaddr: 0x400,
                p_paddr: 0,
                p_filesz: 32,
                p_memsz: 32,
                p_flags: 0,
                p_align: 4,
            },
        ];
        let segments = test_ok(ProcessImage::<Elf32>::segments(0x1034, &headers));
        let Segments {
            load_bias,
            interpreter_address,
            dynamic,
            ..
        } = segments;

        assert_eq!(*load_bias, 0x1000_u32);
        assert_eq!(interpreter_address, ViAddr::new(0x1200));
        assert_eq!(dynamic.address(), ViAddr::new(0x1400));
        assert_eq!(dynamic.size(), 32_u32);
    }

    #[test]
    fn elf64_segment_derivation_uses_same_algorithm() {
        let headers = [
            binding::Elf64_Phdr {
                p_type: binding::PT_PHDR as u32,
                p_flags: 0,
                p_offset: 0,
                p_vaddr: 0x40,
                p_paddr: 0,
                p_filesz: 0,
                p_memsz: 0,
                p_align: 0,
            },
            binding::Elf64_Phdr {
                p_type: binding::PT_INTERP as u32,
                p_flags: 0,
                p_offset: 0,
                p_vaddr: 0x200,
                p_paddr: 0,
                p_filesz: 32,
                p_memsz: 32,
                p_align: 1,
            },
            binding::Elf64_Phdr {
                p_type: binding::PT_DYNAMIC as u32,
                p_flags: 0,
                p_offset: 0,
                p_vaddr: 0x400,
                p_paddr: 0,
                p_filesz: 64,
                p_memsz: 64,
                p_align: 8,
            },
        ];
        let segments = test_ok(ProcessImage::<Elf64>::segments(0x1040, &headers));
        let Segments {
            load_bias,
            interpreter_address,
            dynamic,
            ..
        } = segments;

        assert_eq!(*load_bias, 0x1000_u64);
        assert_eq!(interpreter_address, ViAddr::new(0x1200));
        assert_eq!(dynamic.address(), ViAddr::new(0x1400));
        assert_eq!(dynamic.size(), 64_u64);
    }
}

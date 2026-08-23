//! Runtime ELF classification and compile-time ELF class families.
//!
//! Runtime classification selects the foreign layout once from process metadata. The sealed class
//! family then carries the matching word width and generated records through shared algorithms. A
//! selected class cannot combine records from different ELF widths.

use core::{fmt, hash::Hash};

use catalejo::{ffi, pointer::Address, prelude::Unassociated};
use ganymede_process::process::Snapshot;
use num_traits::{PrimInt, Unsigned};

use crate::binding;

mod detail {
    //! Sealing markers for the supported ELF class and word families.

    /// Prevent downstream implementations of the coherent ELF class family.
    pub trait Class {}

    /// Prevent downstream integer widths from entering class-width arithmetic.
    pub trait Word {}

    /// Prevent downstream program-header layouts from entering image validation.
    pub trait Program {}

    /// Prevent downstream ELF-header layouts from entering image validation.
    pub trait Header {}

    impl Class for super::Elf32 {}
    impl Class for super::Elf64 {}

    impl Word for u32 {}
    impl Word for u64 {}

    impl Program for super::binding::Elf32_Phdr {}
    impl Program for super::binding::Elf64_Phdr {}

    impl Header for super::binding::Elf32_Ehdr {}
    impl Header for super::binding::Elf64_Ehdr {}
}

/// ELF object class proven from process auxiliary metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfClass {
    /// ELF32 layout.
    Elf32,

    /// ELF64 layout.
    Elf64,
}

impl ElfClass {
    /// Classify the ELF image described by a process snapshot.
    ///
    /// # Errors
    ///
    /// This fails when `AT_PHENT` is missing, duplicated, or does not match a generated ELF
    /// program-header representation supported by this crate.
    #[inline]
    pub fn from_snapshot(target_snapshot: &Snapshot) -> Result<Self, ElfClassError> {
        let mut entry_size = None;

        Snapshot::auxiliary_vector(target_snapshot)
            .iter()
            .try_for_each(|target_entry| {
                let is_program_header = target_entry.entry_type() == binding::AT_PHENT;

                if !is_program_header {
                    return Ok(());
                }

                if entry_size.replace(target_entry.entry_value()).is_some() {
                    return Err(ElfClassError::DuplicateProgramHeaderSize);
                }

                Ok(())
            })?;

        let entry_size = entry_size.ok_or(ElfClassError::MissingProgramHeaderSize)?;
        let elf32_size = core::mem::size_of::<binding::Elf32_Phdr>() as u64;
        let elf64_size = core::mem::size_of::<binding::Elf64_Phdr>() as u64;
        if entry_size == elf32_size {
            return Ok(Self::Elf32);
        }

        if entry_size == elf64_size {
            return Ok(Self::Elf64);
        }

        Err(ElfClassError::UnsupportedProgramHeaderSize(entry_size))
    }
}

/// Compile-time marker selecting the ELF32 ABI family.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Elf32;

/// Compile-time marker selecting the ELF64 ABI family.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Elf64;

/// Integer width used by one supported ELF class.
///
/// Numeric behavior comes from [`PrimInt`] and [`Unsigned`]. This sealed contract adds only the
/// Catalejo foreign-memory capability and conversion relationships that are true for the supported
/// ELF32 and ELF64 word types. Downstream code cannot introduce another integer width.
pub trait Word:
    detail::Word
    + Address
    + PrimInt
    + Unsigned
    + Default
    + fmt::Debug
    + Hash
    + Into<ffi::binding::virtual_address_t>
    + TryFrom<ffi::binding::virtual_address_t>
    + TryInto<usize>
{
}

impl Word for u32 {}

impl Word for u64 {}

/// Width-preserving access to the program-header fields used by process-image validation.
///
/// The generated ELF32 and ELF64 records have different physical layouts. This trait exposes only
/// the common semantic fields needed by the shared image algorithm while retaining their class word
/// width.
pub trait ProgramHeader: detail::Program + Unassociated + Copy + fmt::Debug {
    /// ELF word width carried by address and extent fields.
    type Word: Word;

    /// Return the `p_type` segment kind.
    #[must_use]
    fn kind(&self) -> u32;

    /// Return the `p_flags` segment permissions.
    #[must_use]
    fn flags(&self) -> u32;

    /// Return the segment virtual address in the selected ELF width.
    #[must_use]
    fn address(&self) -> Self::Word;

    /// Return the segment file extent in the selected ELF width.
    #[must_use]
    fn file(&self) -> Self::Word;

    /// Return the segment memory extent in the selected ELF width.
    #[must_use]
    fn memory(&self) -> Self::Word;
}

/// Width-preserving access to the ELF header fields required for loaded-image notes.
///
/// The generated ELF32 and ELF64 headers have different physical layouts. This sealed contract
/// exposes only identity and program-table geometry while retaining the selected class width.
pub trait Header: detail::Header + Unassociated + Copy + fmt::Debug {
    /// ELF word width carried by the program-table offset.
    type Word: Word;

    /// Return the exact ELF identification bytes.
    #[must_use]
    fn identity(&self) -> &[u8; binding::EI_NIDENT as usize];

    /// Return the program-table byte offset from the image base.
    #[must_use]
    fn program_offset(&self) -> Self::Word;

    /// Return the generated program-header entry size.
    #[must_use]
    fn program_size(&self) -> u16;

    /// Return the program-header entry count.
    #[must_use]
    fn program_count(&self) -> u16;
}

impl Header for binding::Elf32_Ehdr {
    type Word = u32;

    #[inline]
    fn identity(&self) -> &[u8; binding::EI_NIDENT as usize] {
        let Self { e_ident, .. } = self;

        e_ident
    }

    #[inline]
    fn program_offset(&self) -> Self::Word {
        let Self { e_phoff, .. } = self;

        *e_phoff
    }

    #[inline]
    fn program_size(&self) -> u16 {
        let Self { e_phentsize, .. } = self;

        *e_phentsize
    }

    #[inline]
    fn program_count(&self) -> u16 {
        let Self { e_phnum, .. } = self;

        *e_phnum
    }
}

impl Header for binding::Elf64_Ehdr {
    type Word = u64;

    #[inline]
    fn identity(&self) -> &[u8; binding::EI_NIDENT as usize] {
        let Self { e_ident, .. } = self;

        e_ident
    }

    #[inline]
    fn program_offset(&self) -> Self::Word {
        let Self { e_phoff, .. } = self;

        *e_phoff
    }

    #[inline]
    fn program_size(&self) -> u16 {
        let Self { e_phentsize, .. } = self;

        *e_phentsize
    }

    #[inline]
    fn program_count(&self) -> u16 {
        let Self { e_phnum, .. } = self;

        *e_phnum
    }
}

impl ProgramHeader for binding::Elf32_Phdr {
    type Word = u32;

    #[inline]
    fn kind(&self) -> u32 {
        let Self { p_type, .. } = self;

        *p_type
    }

    #[inline]
    fn flags(&self) -> u32 {
        let Self { p_flags, .. } = self;

        *p_flags
    }

    #[inline]
    fn address(&self) -> Self::Word {
        let Self { p_vaddr, .. } = self;

        *p_vaddr
    }

    #[inline]
    fn file(&self) -> Self::Word {
        let Self { p_filesz, .. } = self;

        *p_filesz
    }

    #[inline]
    fn memory(&self) -> Self::Word {
        let Self { p_memsz, .. } = self;

        *p_memsz
    }
}

impl ProgramHeader for binding::Elf64_Phdr {
    type Word = u64;

    #[inline]
    fn kind(&self) -> u32 {
        let Self { p_type, .. } = self;

        *p_type
    }

    #[inline]
    fn flags(&self) -> u32 {
        let Self { p_flags, .. } = self;

        *p_flags
    }

    #[inline]
    fn address(&self) -> Self::Word {
        let Self { p_vaddr, .. } = self;

        *p_vaddr
    }

    #[inline]
    fn file(&self) -> Self::Word {
        let Self { p_filesz, .. } = self;

        *p_filesz
    }

    #[inline]
    fn memory(&self) -> Self::Word {
        let Self { p_memsz, .. } = self;

        *p_memsz
    }
}

/// Coherent ABI family selected by one ELF class.
///
/// Associated types encode relationships that callers cannot choose independently. Selecting
/// [`Elf32`] or [`Elf64`] therefore selects one matching word width and one matching set of generated
/// foreign records without a runtime width flag.
pub trait Class: detail::Class + Copy + fmt::Debug + Eq + 'static {
    /// Address, size, dynamic-value, symbol-value, and GNU bloom width for this class.
    type Word: Word;

    /// Generated process-resident ELF-header representation.
    type Header: Header<Word = Self::Word>;

    /// Generated process-resident program-header representation.
    type ProgramHeader: ProgramHeader<Word = Self::Word>;

    /// Generated process-resident dynamic-entry representation.
    type Dynamic: Unassociated;

    /// Generated process-resident symbol representation.
    type Symbol: Unassociated + fmt::Debug;

    /// Number of bits in one address-sized word for this class.
    const BITS: u32;

    /// Runtime class represented by this compile-time family.
    const CLASS: ElfClass;
}

impl Class for Elf32 {
    type Word = u32;
    type Header = binding::Elf32_Ehdr;
    type ProgramHeader = binding::Elf32_Phdr;
    type Dynamic = binding::Elf32_Dyn;
    type Symbol = binding::Elf32_Sym;

    const BITS: u32 = 32;
    const CLASS: ElfClass = ElfClass::Elf32;
}

impl Class for Elf64 {
    type Word = u64;
    type Header = binding::Elf64_Ehdr;
    type ProgramHeader = binding::Elf64_Phdr;
    type Dynamic = binding::Elf64_Dyn;
    type Symbol = binding::Elf64_Sym;

    const BITS: u32 = 64;
    const CLASS: ElfClass = ElfClass::Elf64;
}

/// Failure while proving an ELF class from process metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, fack::prelude::Error)]
pub enum ElfClassError {
    /// The auxiliary vector has no `AT_PHENT` entry.
    #[error("missing AT_PHENT auxiliary vector entry")]
    MissingProgramHeaderSize,

    /// The auxiliary vector contains multiple `AT_PHENT` entries.
    #[error("duplicate AT_PHENT auxiliary vector entry")]
    DuplicateProgramHeaderSize,

    /// The reported program-header size does not identify a supported ELF class.
    #[error("unsupported program header size {0}")]
    UnsupportedProgramHeaderSize(u64),
}

//! ELF symbol semantics independent of table discovery and ELF class.
//!
//! Raw ELF32 and ELF64 records are lifted through small class-specific boundaries. Every semantic
//! operation after that point is shared while target-width values remain represented by the selected
//! class word until a checked process-address conversion is required.

extern crate alloc;

use alloc::boxed::Box;
use core::mem::MaybeUninit;

use catalejo::{
    address::ViAddr,
    prelude::{Foreign, Lift},
};

use crate::{
    binding,
    class::{Class, Elf32, Elf64},
    image::LoadBias,
    lift::ElfError,
};

/// ELF symbol binding classification with unknown values preserved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfSymbolBinding {
    /// Translation-unit local symbol.
    Local,

    /// Process-global symbol.
    Global,

    /// Weak process-global symbol.
    Weak,

    /// GNU process-wide unique symbol.
    GnuUnique,

    /// Binding value not interpreted by this crate.
    Other(u8),
}

/// ELF symbol kind classification with unknown values preserved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfSymbolType {
    /// Symbol without a more specific type.
    None,

    /// Data object.
    Object,

    /// Function entry.
    Function,

    /// Section identity.
    Section,

    /// Source file identity.
    File,

    /// Common data object.
    Common,

    /// Thread-local object.
    ThreadLocal,

    /// GNU indirect-function resolver.
    GnuIndirectFunction,

    /// Type value not interpreted by this crate.
    Other(u8),
}

/// ELF symbol visibility classification with unknown values preserved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfSymbolVisibility {
    /// Ordinary preemptible visibility.
    Default,

    /// Processor-defined internal visibility.
    Internal,

    /// Hidden visibility.
    Hidden,

    /// Externally visible but non-preemptible visibility.
    Protected,

    /// Visibility value not interpreted by this crate.
    Other(u8),
}

/// Runtime location semantics derived from one class-preserving ELF symbol definition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymbolLocation<ClassType>
where
    ClassType: Class,
{
    /// The symbol is undefined in this image.
    Undefined,

    /// The symbol has one fixed process virtual address.
    Process(ViAddr),

    /// The symbol identifies a GNU indirect-function resolver rather than its eventual result.
    IndirectFunction(ViAddr),

    /// The symbol value is a thread-local offset rather than one process address.
    ThreadLocal(ClassType::Word),

    /// The symbol retains common-allocation semantics in the selected ELF width.
    Common(ClassType::Word),

    /// The symbol uses the extended section-index mechanism.
    ExtendedSection,
}

/// Owned symbol record with target-width value and size fields preserved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// NOTE(invariant): All fields originate from one complete generated symbol record and `value` plus `size` retain the selected ELF class width without normalization.
pub struct Symbol<ClassType>
where
    ClassType: Class,
{
    /// Offset into the associated string table.
    name_offset: u32,

    /// Packed binding and type byte.
    information: u8,

    /// Packed visibility byte.
    other: u8,

    /// Raw section index from the symbol record.
    section_index: u16,

    /// ELF symbol value in the selected class width.
    value: ClassType::Word,

    /// ELF symbol extent in the selected class width.
    size: ClassType::Word,
}

impl<ClassType> Symbol<ClassType>
where
    ClassType: Class,
{
    /// Construct one semantic record from fields already copied from a matching raw symbol.
    #[inline]
    const fn from_parts(
        name_offset: u32,
        information: u8,
        other: u8,
        section_index: u16,
        value: ClassType::Word,
        size: ClassType::Word,
    ) -> Self {
        Self {
            name_offset,
            information,
            other,
            section_index,
            value,
            size,
        }
    }

    /// Return the offset into the associated string table.
    #[inline]
    #[must_use]
    pub const fn name_offset(&self) -> u32 {
        let Self { name_offset, .. } = self;

        *name_offset
    }

    /// Classify the symbol binding.
    #[inline]
    #[must_use]
    pub const fn binding(&self) -> ElfSymbolBinding {
        let Self { information, .. } = self;
        let binding = *information >> 4;

        match binding {
            0 => ElfSymbolBinding::Local,
            1 => ElfSymbolBinding::Global,
            2 => ElfSymbolBinding::Weak,
            10 => ElfSymbolBinding::GnuUnique,
            other => ElfSymbolBinding::Other(other),
        }
    }

    /// Classify the symbol type.
    #[inline]
    #[must_use]
    pub const fn symbol_type(&self) -> ElfSymbolType {
        let Self { information, .. } = self;
        let symbol_type = *information & 0x0f;

        match symbol_type {
            0 => ElfSymbolType::None,
            1 => ElfSymbolType::Object,
            2 => ElfSymbolType::Function,
            3 => ElfSymbolType::Section,
            4 => ElfSymbolType::File,
            5 => ElfSymbolType::Common,
            6 => ElfSymbolType::ThreadLocal,
            10 => ElfSymbolType::GnuIndirectFunction,
            other => ElfSymbolType::Other(other),
        }
    }

    /// Classify symbol visibility.
    #[inline]
    #[must_use]
    pub const fn visibility(&self) -> ElfSymbolVisibility {
        let Self { other, .. } = self;
        let visibility = *other & 0x03;

        match visibility {
            0 => ElfSymbolVisibility::Default,
            1 => ElfSymbolVisibility::Internal,
            2 => ElfSymbolVisibility::Hidden,
            3 => ElfSymbolVisibility::Protected,
            other => ElfSymbolVisibility::Other(other),
        }
    }

    /// Return the raw section index.
    #[inline]
    #[must_use]
    pub const fn section_index(&self) -> u16 {
        let Self { section_index, .. } = self;

        *section_index
    }

    /// Return the raw ELF symbol value without widening it.
    #[inline]
    #[must_use]
    pub const fn value(&self) -> ClassType::Word {
        let Self { value, .. } = self;

        *value
    }

    /// Return the symbol extent without widening it.
    #[inline]
    #[must_use]
    pub const fn size(&self) -> ClassType::Word {
        let Self { size, .. } = self;

        *size
    }

    /// Determine whether the symbol can participate in external lookup.
    #[inline]
    #[must_use]
    pub const fn externally_visible(&self) -> bool {
        let binding_visible = matches!(
            Self::binding(self),
            ElfSymbolBinding::Global | ElfSymbolBinding::Weak | ElfSymbolBinding::GnuUnique
        );
        let visibility_visible = matches!(
            Self::visibility(self),
            ElfSymbolVisibility::Default | ElfSymbolVisibility::Protected
        );

        binding_visible && visibility_visible
    }

    /// Derive the runtime location semantics for this symbol.
    ///
    /// TLS and common values retain the target ELF width. Absolute values widen directly because no
    /// arithmetic is required. Section-relative values cross into [`ViAddr`] only after checked
    /// class-width load-bias addition.
    ///
    /// # Errors
    ///
    /// This returns an error when section-relative address translation overflows the selected ELF
    /// width.
    #[inline]
    pub fn location(
        &self,
        target_load_bias: LoadBias<ClassType>,
    ) -> Result<SymbolLocation<ClassType>, SymbolError> {
        let section_index = i32::from(Self::section_index(self));
        let value = Self::value(self);
        let symbol_type = Self::symbol_type(self);
        if section_index == binding::SHN_UNDEF {
            return Ok(SymbolLocation::Undefined);
        }

        if section_index == binding::SHN_COMMON {
            return Ok(SymbolLocation::Common(value));
        }

        if section_index == binding::SHN_XINDEX {
            return Ok(SymbolLocation::ExtendedSection);
        }

        if symbol_type == ElfSymbolType::ThreadLocal {
            return Ok(SymbolLocation::ThreadLocal(value));
        }

        if section_index == binding::SHN_ABS {
            let address = ViAddr::new(value.into());

            return if symbol_type == ElfSymbolType::GnuIndirectFunction {
                Ok(SymbolLocation::IndirectFunction(address))
            } else {
                Ok(SymbolLocation::Process(address))
            };
        }

        let address = target_load_bias
            .address(value)
            .ok_or(SymbolError::AddressOverflow)?;

        if symbol_type == ElfSymbolType::GnuIndirectFunction {
            Ok(SymbolLocation::IndirectFunction(address))
        } else {
            Ok(SymbolLocation::Process(address))
        }
    }
}

impl Lift for Symbol<Elf32> {
    type Value = binding::Elf32_Sym;
    type Context = ();
    type Error = ElfError;

    #[inline]
    fn construct_with(
        target_handle: Foreign<Self::Value>,
        _target_context: &Self::Context,
    ) -> Result<Self, Self::Error> {
        let mut storage = MaybeUninit::<binding::Elf32_Sym>::uninit();
        let symbol = target_handle
            .copy(&mut storage)
            .map_err(|_| ElfError::Faulted)?;
        let binding::Elf32_Sym {
            st_name: name_offset,
            st_value: value,
            st_size: size,
            st_info: information,
            st_other: other,
            st_shndx: section_index,
        } = *symbol;

        Ok(Self::from_parts(
            name_offset,
            information,
            other,
            section_index,
            value,
            size,
        ))
    }
}

impl Lift for Symbol<Elf64> {
    type Value = binding::Elf64_Sym;
    type Context = ();
    type Error = ElfError;

    #[inline]
    fn construct_with(
        target_handle: Foreign<Self::Value>,
        _target_context: &Self::Context,
    ) -> Result<Self, Self::Error> {
        let mut storage = MaybeUninit::<binding::Elf64_Sym>::uninit();
        let symbol = target_handle
            .copy(&mut storage)
            .map_err(|_| ElfError::Faulted)?;
        let binding::Elf64_Sym {
            st_name: name_offset,
            st_info: information,
            st_other: other,
            st_shndx: section_index,
            st_value: value,
            st_size: size,
        } = *symbol;

        Ok(Self::from_parts(
            name_offset,
            information,
            other,
            section_index,
            value,
            size,
        ))
    }
}

/// A dynamic symbol paired with its exact string-table name.
#[derive(Debug, Clone, PartialEq, Eq)]
// NOTE(invariant): The symbol record and paired name bytes belong to one dynamic-table index and retain exact name bytes without encoding conversion or target-width loss.
pub struct DynamicSymbol<ClassType>
where
    ClassType: Class,
{
    /// Index within the dynamic symbol table.
    index: u32,

    /// Class-preserving symbol record.
    symbol: Symbol<ClassType>,

    /// Exact symbol-name bytes without the NUL terminator.
    name: Box<[u8]>,
}

impl<ClassType> DynamicSymbol<ClassType>
where
    ClassType: Class,
{
    /// Construct a dynamic-symbol observation from one validated table record and exact name.
    #[inline]
    #[must_use]
    pub fn new(index: u32, symbol: Symbol<ClassType>, target_name: &[u8]) -> Self {
        let name = target_name.into();

        Self {
            index,
            symbol,
            name,
        }
    }

    /// Return the dynamic symbol index.
    #[inline]
    #[must_use]
    pub const fn index(&self) -> u32 {
        let Self { index, .. } = self;

        *index
    }

    /// Borrow the underlying class-preserving ELF symbol semantics.
    #[inline]
    #[must_use]
    pub const fn symbol(&self) -> &Symbol<ClassType> {
        let Self { symbol, .. } = self;

        symbol
    }

    /// Derive runtime location semantics using the owning image load bias.
    ///
    /// # Errors
    ///
    /// This returns an error when section-relative address translation overflows the selected ELF
    /// width.
    #[inline]
    pub fn location(
        &self,
        target_load_bias: LoadBias<ClassType>,
    ) -> Result<SymbolLocation<ClassType>, SymbolError> {
        let Self { symbol, .. } = self;

        Symbol::location(symbol, target_load_bias)
    }

    /// Borrow the exact symbol name bytes.
    #[inline]
    #[must_use]
    pub fn name(&self) -> &[u8] {
        let Self { name, .. } = self;

        name
    }
}

/// Externally visible dynamic symbol with one fixed process address.
#[derive(Debug, Clone, PartialEq, Eq)]
// NOTE(invariant): The retained symbol is externally visible, defined, non-TLS, non-common, non-IFUNC, and resolves to exactly `address` under its selected-class load bias.
pub struct Export<ClassType>
where
    ClassType: Class,
{
    /// Dynamic symbol that established the export.
    symbol: DynamicSymbol<ClassType>,

    /// Fixed process address derived from ELF symbol semantics.
    address: ViAddr,
}

impl<ClassType> Export<ClassType>
where
    ClassType: Class,
{
    /// Attempt to promote a dynamic symbol into an addressable export.
    ///
    /// # Errors
    ///
    /// This returns an error when symbol address translation overflows the selected ELF width.
    #[inline]
    pub fn new(
        symbol: DynamicSymbol<ClassType>,
        target_load_bias: LoadBias<ClassType>,
    ) -> Result<Option<Self>, SymbolError> {
        let visible = Symbol::externally_visible(DynamicSymbol::symbol(&symbol));
        let location = Symbol::location(DynamicSymbol::symbol(&symbol), target_load_bias)?;

        match location {
            SymbolLocation::Process(address) if visible => Ok(Some(Self { symbol, address })),
            _ => Ok(None),
        }
    }

    /// Borrow the dynamic symbol that established this export.
    #[inline]
    #[must_use]
    pub const fn symbol(&self) -> &DynamicSymbol<ClassType> {
        let Self { symbol, .. } = self;

        symbol
    }

    /// Return the fixed process address of the export.
    #[inline]
    #[must_use]
    pub const fn address(&self) -> ViAddr {
        let Self { address, .. } = self;

        *address
    }
}

/// Failure while deriving symbol address semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, fack::prelude::Error)]
pub enum SymbolError {
    /// Section-relative symbol address translation overflowed its selected ELF width.
    #[error("ELF symbol runtime address overflow")]
    AddressOverflow,
}

/// ELF32 symbol record with 32-bit value and size semantics.
pub type Elf32Symbol = Symbol<Elf32>;

/// ELF64 symbol record with 64-bit value and size semantics.
pub type Elf64Symbol = Symbol<Elf64>;

/// ELF32 symbol location semantics.
pub type Elf32SymbolLocation = SymbolLocation<Elf32>;

/// ELF64 symbol location semantics.
pub type Elf64SymbolLocation = SymbolLocation<Elf64>;

/// ELF32 dynamic symbol paired with exact name bytes.
pub type Elf32DynamicSymbol = DynamicSymbol<Elf32>;

/// ELF64 dynamic symbol paired with exact name bytes.
pub type Elf64DynamicSymbol = DynamicSymbol<Elf64>;

/// Addressable ELF32 dynamic export.
pub type Elf32Export = Export<Elf32>;

/// Addressable ELF64 dynamic export.
pub type Elf64Export = Export<Elf64>;

/// Compatibility name for ELF32 symbol-address failures.
pub type Elf32SymbolError = SymbolError;

/// Compatibility name for ELF64 symbol-address failures.
pub type Elf64SymbolError = SymbolError;

#[cfg(test)]
mod tests {
    //! Regression coverage for class-shared symbol classification and width-preserving locations.

    use super::*;

    /// Extract one successful test result without unwrap-family shortcuts.
    fn test_ok<T, E: core::fmt::Debug>(target_result: Result<T, E>) -> T {
        target_result.expect("test operation should succeed")
    }

    /// Extract one present test value without unwrap-family shortcuts.
    fn test_some<T>(target_value: Option<T>) -> T {
        target_value.expect("test expected a present value")
    }

    fn symbol<ClassType>(
        information: u8,
        other: u8,
        section_index: u16,
        value: ClassType::Word,
    ) -> Symbol<ClassType>
    where
        ClassType: Class,
    {
        Symbol::from_parts(
            0,
            information,
            other,
            section_index,
            value,
            <ClassType::Word as num_traits::Zero>::zero(),
        )
    }

    fn visible<ClassType>(value: ClassType::Word, bias: ClassType::Word) -> ViAddr
    where
        ClassType: Class,
    {
        let symbol = symbol::<ClassType>(0x12, 0, 1, value);
        let dynamic = DynamicSymbol::new(1, symbol, b"sample");
        let load_bias = LoadBias::<ClassType>::new(bias);
        let export = test_some(test_ok(Export::new(dynamic, load_bias)));

        export.address()
    }

    #[test]
    fn global_default_symbol_promotes_for_both_classes() {
        assert_eq!(visible::<Elf32>(0x120, 0x1000), ViAddr::new(0x1120));
        assert_eq!(visible::<Elf64>(0x120, 0x1000), ViAddr::new(0x1120));
    }

    #[test]
    fn hidden_and_undefined_symbols_do_not_promote() {
        let hidden = symbol::<Elf64>(0x12, 2, 1, 0x120);
        let undefined = symbol::<Elf64>(
            0x12,
            0,
            u16::try_from(binding::SHN_UNDEF).expect("SHN_UNDEF must fit a symbol section index"),
            0x120,
        );
        let load_bias = LoadBias::<Elf64>::new(0x1000);

        assert!(
            test_ok(Export::new(
                DynamicSymbol::new(1, hidden, b"hidden"),
                load_bias,
            ))
            .is_none()
        );
        assert!(
            test_ok(Export::new(
                DynamicSymbol::new(2, undefined, b"undefined"),
                load_bias,
            ))
            .is_none()
        );
    }

    #[test]
    fn thread_local_symbol_preserves_each_class_width() {
        let symbol32 = symbol::<Elf32>(0x16, 0, 1, 0x88);
        let symbol64 = symbol::<Elf64>(0x16, 0, 1, 0x88);

        assert_eq!(
            test_ok(symbol32.location(LoadBias::new(0x1000))),
            SymbolLocation::ThreadLocal(0x88_u32)
        );
        assert_eq!(
            test_ok(symbol64.location(LoadBias::new(0x1000))),
            SymbolLocation::ThreadLocal(0x88_u64)
        );
    }

    #[test]
    fn indirect_function_preserves_resolver_identity() {
        let symbol = symbol::<Elf64>(0x1a, 0, 1, 0x220);
        let dynamic = DynamicSymbol::new(1, symbol, b"indirect");
        let load_bias = LoadBias::new(0x1000);

        assert_eq!(
            test_ok(dynamic.location(load_bias)),
            SymbolLocation::IndirectFunction(ViAddr::new(0x1220))
        );
        assert!(test_ok(Export::new(dynamic, load_bias)).is_none());
    }
}

//! Compile-time GNU runtime-linker ABI families.
//!
//! One sealed family selects the matching ELF class, foreign pointer encoding, generated GNU
//! records, linker state, and interpreter profile. Generated field projection
//! remains specialized at this boundary while protocol algorithms operate over one `AbiType`.

use core::fmt;

use catalejo::{
    pointer::Pointer,
    prelude::{Foreign, Lift, Unassociated},
};
use ganymede_elf::class::{Class, Elf32, Elf64};

use crate::{
    binding32, binding64,
    error::LinkerError,
    model::{DebugRecord, ExtendedRecord, LinkMapRecord},
};

mod detail {
    //! Sealing markers for supported GNU ABI families.

    /// Prevent downstream implementations from combining unrelated ABI components.
    pub trait Abi {}

    impl Abi for super::Gnu32 {}

    impl Abi for super::Gnu64 {}
}

/// GNU i386 ABI family.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Gnu32;

/// GNU x86-64 ABI family.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Gnu64;

/// Coherent GNU runtime-linker ABI family.
///
/// The associated types are selected together and cannot be independently supplied by callers. A
/// GNU family therefore preserves the relationship between ELF width, encoded pointer width,
/// generated loader records, and loader state throughout acquisition.
pub trait Abi: detail::Abi + Copy + fmt::Debug + Eq + 'static {
    /// ELF class used by this GNU ABI.
    type Elf: Class;

    /// Generated base GNU rendezvous record.
    type RawDebug: Unassociated;

    /// Generated extended GNU rendezvous record.
    type RawExtended: Unassociated;

    /// Generated GNU link-map record.
    type RawMap: Unassociated;

    /// Generated GNU loader mutation state.
    type State: Copy + fmt::Debug + Eq;

    /// Exact interpreter basename supported by this ABI profile.
    const INTERPRETER_BASENAME: &'static [u8];

    /// Generated loader state that proves a stable link map.
    const CONSISTENT: Self::State;
}

impl Abi for Gnu32 {
    type Elf = Elf32;
    type RawDebug = binding32::r_debug_32;
    type RawExtended = binding32::r_debug_extended_32;
    type RawMap = binding32::link_map_32;
    type State = binding32::r_debug_32__bindgen_ty_1;

    const INTERPRETER_BASENAME: &'static [u8] = b"ld-linux.so.2";
    const CONSISTENT: Self::State = binding32::r_debug_32_RT_CONSISTENT;
}

impl Abi for Gnu64 {
    type Elf = Elf64;
    type RawDebug = binding64::r_debug_64;
    type RawExtended = binding64::r_debug_extended_64;
    type RawMap = binding64::link_map_64;
    type State = binding64::r_debug_64__bindgen_ty_1;

    const INTERPRETER_BASENAME: &'static [u8] = b"ld-linux-x86-64.so.2";
    const CONSISTENT: Self::State = binding64::r_debug_64_RT_CONSISTENT;
}

/// Target ELF address width selected by one GNU ABI family.
pub type ElfAddress<AbiType> = <<AbiType as Abi>::Elf as Class>::Word;

/// Typed pointer to the GNU base rendezvous selected by one ABI family.
pub type DebugPointer<AbiType> = Pointer<*mut <AbiType as Abi>::RawDebug, ElfAddress<AbiType>>;

/// Typed pointer to the GNU extended rendezvous selected by one ABI family.
pub type ExtendedPointer<AbiType> =
    Pointer<*mut <AbiType as Abi>::RawExtended, ElfAddress<AbiType>>;

/// Typed pointer to the GNU link-map record selected by one ABI family.
pub type MapPointer<AbiType> = Pointer<*mut <AbiType as Abi>::RawMap, ElfAddress<AbiType>>;

/// Typed pointer to a loader-provided C string selected by one ABI family.
pub type NamePointer<AbiType> = Pointer<*mut core::ffi::c_char, ElfAddress<AbiType>>;

/// Typed pointer to an ELF dynamic record selected by one GNU ABI family.
pub type DynamicPointer<AbiType> =
    Pointer<*mut <<AbiType as Abi>::Elf as Class>::Dynamic, ElfAddress<AbiType>>;

impl Lift for DebugRecord<Gnu32> {
    type Value = binding32::r_debug_32;
    type Context = ();
    type Error = LinkerError;

    #[inline]
    fn construct_with(
        target_handle: Foreign<Self::Value>,
        _target_context: &Self::Context,
    ) -> Result<Self, Self::Error> {
        let version = target_handle
            .project(binding32::r_debug_32::r_version)
            .read()
            .ok_or(LinkerError::Faulted)?;
        let map = target_handle
            .project(binding32::r_debug_32::r_map)
            .read()
            .ok_or(LinkerError::Faulted)?;
        let breakpoint = target_handle
            .project(binding32::r_debug_32::r_brk)
            .read()
            .ok_or(LinkerError::Faulted)?;
        let state = target_handle
            .project(binding32::r_debug_32::r_state)
            .read()
            .ok_or(LinkerError::Faulted)?;
        let linker_base = target_handle
            .project(binding32::r_debug_32::r_ldbase)
            .read()
            .ok_or(LinkerError::Faulted)?;

        Ok(Self::new(version, map, breakpoint, state, linker_base))
    }
}

impl Lift for DebugRecord<Gnu64> {
    type Value = binding64::r_debug_64;
    type Context = ();
    type Error = LinkerError;

    #[inline]
    fn construct_with(
        target_handle: Foreign<Self::Value>,
        _target_context: &Self::Context,
    ) -> Result<Self, Self::Error> {
        let version = target_handle
            .project(binding64::r_debug_64::r_version)
            .read()
            .ok_or(LinkerError::Faulted)?;
        let map = target_handle
            .project(binding64::r_debug_64::r_map)
            .read()
            .ok_or(LinkerError::Faulted)?;
        let breakpoint = target_handle
            .project(binding64::r_debug_64::r_brk)
            .read()
            .ok_or(LinkerError::Faulted)?;
        let state = target_handle
            .project(binding64::r_debug_64::r_state)
            .read()
            .ok_or(LinkerError::Faulted)?;
        let linker_base = target_handle
            .project(binding64::r_debug_64::r_ldbase)
            .read()
            .ok_or(LinkerError::Faulted)?;

        Ok(Self::new(version, map, breakpoint, state, linker_base))
    }
}

impl Lift for ExtendedRecord<Gnu32> {
    type Value = binding32::r_debug_extended_32;
    type Context = ();
    type Error = LinkerError;

    #[inline]
    fn construct_with(
        target_handle: Foreign<Self::Value>,
        _target_context: &Self::Context,
    ) -> Result<Self, Self::Error> {
        let base = target_handle
            .project(binding32::r_debug_extended_32::base)
            .lift::<DebugRecord<Gnu32>>()?;
        let next = target_handle
            .project(binding32::r_debug_extended_32::r_next)
            .read()
            .ok_or(LinkerError::Faulted)?;

        Ok(Self::new(base, next))
    }
}

impl Lift for ExtendedRecord<Gnu64> {
    type Value = binding64::r_debug_extended_64;
    type Context = ();
    type Error = LinkerError;

    #[inline]
    fn construct_with(
        target_handle: Foreign<Self::Value>,
        _target_context: &Self::Context,
    ) -> Result<Self, Self::Error> {
        let base = target_handle
            .project(binding64::r_debug_extended_64::base)
            .lift::<DebugRecord<Gnu64>>()?;
        let next = target_handle
            .project(binding64::r_debug_extended_64::r_next)
            .read()
            .ok_or(LinkerError::Faulted)?;

        Ok(Self::new(base, next))
    }
}

impl Lift for LinkMapRecord<Gnu32> {
    type Value = binding32::link_map_32;
    type Context = ();
    type Error = LinkerError;

    #[inline]
    fn construct_with(
        target_handle: Foreign<Self::Value>,
        _target_context: &Self::Context,
    ) -> Result<Self, Self::Error> {
        let address = target_handle
            .project(binding32::link_map_32::l_addr)
            .read()
            .ok_or(LinkerError::Faulted)?;
        let name = target_handle
            .project(binding32::link_map_32::l_name)
            .read()
            .ok_or(LinkerError::Faulted)?;
        let dynamic = target_handle
            .project(binding32::link_map_32::l_ld)
            .read()
            .ok_or(LinkerError::Faulted)?;
        let next = target_handle
            .project(binding32::link_map_32::l_next)
            .read()
            .ok_or(LinkerError::Faulted)?;
        let previous = target_handle
            .project(binding32::link_map_32::l_prev)
            .read()
            .ok_or(LinkerError::Faulted)?;

        Ok(Self::new(address, name, dynamic, next, previous))
    }
}

impl Lift for LinkMapRecord<Gnu64> {
    type Value = binding64::link_map_64;
    type Context = ();
    type Error = LinkerError;

    #[inline]
    fn construct_with(
        target_handle: Foreign<Self::Value>,
        _target_context: &Self::Context,
    ) -> Result<Self, Self::Error> {
        let address = target_handle
            .project(binding64::link_map_64::l_addr)
            .read()
            .ok_or(LinkerError::Faulted)?;
        let name = target_handle
            .project(binding64::link_map_64::l_name)
            .read()
            .ok_or(LinkerError::Faulted)?;
        let dynamic = target_handle
            .project(binding64::link_map_64::l_ld)
            .read()
            .ok_or(LinkerError::Faulted)?;
        let next = target_handle
            .project(binding64::link_map_64::l_next)
            .read()
            .ok_or(LinkerError::Faulted)?;
        let previous = target_handle
            .project(binding64::link_map_64::l_prev)
            .read()
            .ok_or(LinkerError::Faulted)?;

        Ok(Self::new(address, name, dynamic, next, previous))
    }
}

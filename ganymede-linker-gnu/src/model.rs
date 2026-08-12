//! Width-preserving observations of GNU runtime-linker ABI records.
//!
//! Generated C layouts are projected at the ABI boundary. These records retain the selected GNU
//! family as one compile-time parameter, so pointer width, ELF address width, and loader state cannot
//! be recombined independently after lifting.

use crate::abi::{Abi, DynamicPointer, ElfAddress, ExtendedPointer, MapPointer, NamePointer};

/// One stable observation of GNU `r_debug` with target ABI identities preserved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// NOTE(invariant): Every field belongs to the one coherent GNU ABI family selected by `AbiType` and originates from one stabilized foreign `r_debug` value.
pub struct DebugRecord<AbiType>
where
    AbiType: Abi,
{
    /// GNU debugger protocol version.
    version: core::ffi::c_int,

    /// Foreign pointer to the first link-map node.
    map: MapPointer<AbiType>,

    /// Runtime notification address in the selected ELF width.
    breakpoint: ElfAddress<AbiType>,

    /// Loader mutation state selected by the GNU ABI.
    state: AbiType::State,

    /// Runtime load address of the dynamic linker.
    linker_base: ElfAddress<AbiType>,
}

impl<AbiType> DebugRecord<AbiType>
where
    AbiType: Abi,
{
    /// Assemble one semantic rendezvous observation from a matching raw lift.
    #[inline]
    #[must_use]
    pub const fn new(
        target_version: core::ffi::c_int,
        target_map: MapPointer<AbiType>,
        target_breakpoint: ElfAddress<AbiType>,
        target_state: AbiType::State,
        target_linker_base: ElfAddress<AbiType>,
    ) -> Self {
        Self {
            version: target_version,
            map: target_map,
            breakpoint: target_breakpoint,
            state: target_state,
            linker_base: target_linker_base,
        }
    }

    /// Return the GNU debugger protocol version.
    #[inline]
    #[must_use]
    pub const fn version(&self) -> core::ffi::c_int {
        let Self { version, .. } = self;

        *version
    }

    /// Return the target-width pointer that roots this namespace link-map chain.
    #[inline]
    #[must_use]
    pub const fn map(&self) -> MapPointer<AbiType> {
        let Self { map, .. } = self;

        *map
    }

    /// Return the target ELF address of the debugger notification hook.
    #[inline]
    #[must_use]
    pub const fn breakpoint(&self) -> ElfAddress<AbiType> {
        let Self { breakpoint, .. } = self;

        *breakpoint
    }

    /// Return the generated loader state observed during stabilization.
    #[inline]
    #[must_use]
    pub const fn state(&self) -> AbiType::State {
        let Self { state, .. } = self;

        *state
    }

    /// Return the target ELF address where the runtime linker itself is loaded.
    #[inline]
    #[must_use]
    pub const fn linker(&self) -> ElfAddress<AbiType> {
        let Self { linker_base, .. } = self;

        *linker_base
    }
}

/// One stable GNU extended-rendezvous observation for namespace chaining.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// NOTE(invariant): The embedded base record and next edge were lifted from one extended record under the same `AbiType` family.
pub struct ExtendedRecord<AbiType>
where
    AbiType: Abi,
{
    /// Embedded stable base debug record.
    base: DebugRecord<AbiType>,

    /// Pointer to the next extended namespace record.
    next: ExtendedPointer<AbiType>,
}

impl<AbiType> ExtendedRecord<AbiType>
where
    AbiType: Abi,
{
    /// Pair the embedded base rendezvous with the next namespace edge from one lift.
    #[inline]
    #[must_use]
    pub const fn new(
        target_base: DebugRecord<AbiType>,
        target_next: ExtendedPointer<AbiType>,
    ) -> Self {
        Self {
            base: target_base,
            next: target_next,
        }
    }

    /// Return the stabilized base rendezvous embedded in this record.
    #[inline]
    #[must_use]
    pub const fn base(&self) -> DebugRecord<AbiType> {
        let Self { base, .. } = self;

        *base
    }

    /// Return the target-width edge to the next GNU namespace rendezvous.
    #[inline]
    #[must_use]
    pub const fn next(&self) -> ExtendedPointer<AbiType> {
        let Self { next, .. } = self;

        *next
    }
}

/// One stable observation of a GNU `link_map` node before graph-level validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// NOTE(invariant): Every field belongs to one GNU ABI family and was projected from the same stabilized foreign link-map record.
pub struct LinkMapRecord<AbiType>
where
    AbiType: Abi,
{
    /// Module relocation base.
    address: ElfAddress<AbiType>,

    /// Pointer to the NUL-terminated module path.
    name: NamePointer<AbiType>,

    /// Pointer to the module dynamic table.
    dynamic: DynamicPointer<AbiType>,

    /// Forward link-map edge.
    next: MapPointer<AbiType>,

    /// Reverse link-map edge.
    previous: MapPointer<AbiType>,
}

impl<AbiType> LinkMapRecord<AbiType>
where
    AbiType: Abi,
{
    /// Assemble one link-map observation from fields produced by the same stabilized lift.
    #[inline]
    #[must_use]
    pub const fn new(
        target_address: ElfAddress<AbiType>,
        target_name: NamePointer<AbiType>,
        target_dynamic: DynamicPointer<AbiType>,
        target_next: MapPointer<AbiType>,
        target_previous: MapPointer<AbiType>,
    ) -> Self {
        Self {
            address: target_address,
            name: target_name,
            dynamic: target_dynamic,
            next: target_next,
            previous: target_previous,
        }
    }

    /// Return the target ELF relocation base recorded by the loader.
    #[inline]
    #[must_use]
    pub const fn address(&self) -> ElfAddress<AbiType> {
        let Self { address, .. } = self;

        *address
    }

    /// Return the target-width pointer used to acquire the loader-provided module name.
    #[inline]
    #[must_use]
    pub const fn name(&self) -> NamePointer<AbiType> {
        let Self { name, .. } = self;

        *name
    }

    /// Return the target-width pointer to this module's resident dynamic table.
    #[inline]
    #[must_use]
    pub const fn dynamic(&self) -> DynamicPointer<AbiType> {
        let Self { dynamic, .. } = self;

        *dynamic
    }

    /// Return the target-width edge to the next link-map node.
    #[inline]
    #[must_use]
    pub const fn next(&self) -> MapPointer<AbiType> {
        let Self { next, .. } = self;

        *next
    }

    /// Return the target-width edge to the previous link-map node.
    #[inline]
    #[must_use]
    pub const fn previous(&self) -> MapPointer<AbiType> {
        let Self { previous, .. } = self;

        *previous
    }
}

/// Stable i386 GNU debugger rendezvous observation.
pub type GnuDebug32 = DebugRecord<crate::abi::Gnu32>;

/// Stable x86-64 GNU debugger rendezvous observation.
pub type GnuDebug64 = DebugRecord<crate::abi::Gnu64>;

/// Stable i386 GNU extended rendezvous observation.
pub type GnuDebugExtended32 = ExtendedRecord<crate::abi::Gnu32>;

/// Stable x86-64 GNU extended rendezvous observation.
pub type GnuDebugExtended64 = ExtendedRecord<crate::abi::Gnu64>;

/// Stable i386 GNU link-map observation.
pub type GnuLinkMap32 = LinkMapRecord<crate::abi::Gnu32>;

/// Stable x86-64 GNU link-map observation.
pub type GnuLinkMap64 = LinkMapRecord<crate::abi::Gnu64>;

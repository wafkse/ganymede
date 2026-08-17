//! Coherent GNU snapshot records shared by supported target ABIs.
//!
//! These values are constructed only after stable foreign reads and complete graph validation. One
//! sealed `AbiType` retains all target pointer and ELF width relationships without independent generic
//! choices.

extern crate alloc;

use alloc::boxed::Box;
use catalejo::address::ViAddr;
use ganymede_elf::{
    class::Class,
    dynamic::{DynamicSymbols, DynamicSymbolsError},
    image::LoadBias,
    lift::{Dynamic, ElfError},
    loaded::LoadedImage,
    symbol::Symbol,
};
use ganymede_text::BytePath;

use crate::{
    abi::{
        Abi, DebugPointer, DynamicPointer, ElfAddress, ExtendedPointer, MapPointer, NamePointer,
    },
    model::DebugRecord,
};

/// Validated GNU module observation retained after bidirectional link-map checking.
#[derive(Debug, Clone, PartialEq, Eq)]
// NOTE(invariant): Every pointer and ELF value belongs to `AbiType`, the graph edges passed bidirectional validation, and the module name owns its exact loader-provided bytes.
pub struct Module<AbiType>
where
    AbiType: Abi,
{
    /// Canonical foreign address of this link-map node.
    map: MapPointer<AbiType>,

    /// Module relocation base with ELF width preserved.
    load_bias: ElfAddress<AbiType>,

    /// Foreign pointer used to acquire the retained name.
    name_pointer: NamePointer<AbiType>,

    /// Foreign pointer to the module dynamic table.
    dynamic: DynamicPointer<AbiType>,

    /// Validated forward link-map edge.
    next: MapPointer<AbiType>,

    /// Validated reverse link-map edge.
    previous: MapPointer<AbiType>,

    /// Exact owned module path bytes.
    name: BytePath,
}

impl<AbiType> Module<AbiType>
where
    AbiType: Abi,
{
    /// Promote a stabilized link-map node after neighboring graph relationships were validated.
    #[inline]
    pub(crate) const fn new(
        target_map: MapPointer<AbiType>,
        target_load_bias: ElfAddress<AbiType>,
        target_name_pointer: NamePointer<AbiType>,
        target_dynamic: DynamicPointer<AbiType>,
        target_next: MapPointer<AbiType>,
        target_previous: MapPointer<AbiType>,
        target_name: BytePath,
    ) -> Self {
        Self {
            map: target_map,
            load_bias: target_load_bias,
            name_pointer: target_name_pointer,
            dynamic: target_dynamic,
            next: target_next,
            previous: target_previous,
            name: target_name,
        }
    }

    /// Return the target-width identity of the foreign link-map node represented here.
    #[inline]
    #[must_use]
    pub const fn map(&self) -> MapPointer<AbiType> {
        let Self { map, .. } = self;

        *map
    }

    /// Return the target ELF relocation base without widening it.
    #[inline]
    #[must_use]
    pub const fn bias(&self) -> ElfAddress<AbiType> {
        let Self { load_bias, .. } = self;

        *load_bias
    }

    /// Return the foreign pointer from which the retained exact module name was acquired.
    #[inline]
    #[must_use]
    pub const fn nameptr(&self) -> NamePointer<AbiType> {
        let Self { name_pointer, .. } = self;

        *name_pointer
    }

    /// Return the target-width dynamic-table pointer used as the module image anchor.
    #[inline]
    #[must_use]
    pub const fn dynamic(&self) -> DynamicPointer<AbiType> {
        let Self { dynamic, .. } = self;

        *dynamic
    }

    /// Return the forward edge that passed namespace graph validation.
    #[inline]
    #[must_use]
    pub const fn next(&self) -> MapPointer<AbiType> {
        let Self { next, .. } = self;

        *next
    }

    /// Return the reverse edge that passed namespace graph validation.
    #[inline]
    #[must_use]
    pub const fn previous(&self) -> MapPointer<AbiType> {
        let Self { previous, .. } = self;

        *previous
    }

    /// Borrow the exact loader-provided name bytes retained during acquisition.
    #[inline]
    #[must_use]
    pub const fn name(&self) -> &BytePath {
        let Self { name, .. } = self;

        name
    }

    /// Borrow the final byte path component without decoding the retained name as text.
    #[inline]
    #[must_use]
    pub fn basename(&self) -> &[u8] {
        let Self { name, .. } = self;

        name.basename()
    }
}

impl<AbiType> Module<AbiType>
where
    AbiType: Abi,
{
    /// Normalize this stable loader module through its dynamic-table process anchor.
    ///
    /// # Errors
    ///
    /// Returns an error when the dynamic-table anchor is absent from the process snapshot.
    #[inline]
    pub fn normalize(
        &self,
        target_snapshot: &ganymede_process::process::Snapshot,
    ) -> Result<ganymede_module::Module, ganymede_module::NormalizeError> {
        let anchor = ViAddr::new(self.dynamic().address().into());

        ganymede_module::Module::from_anchor(target_snapshot, self.name().clone(), anchor)
    }

    /// Discover class-matching ELF dynamic symbols for this stable GNU loader module.
    ///
    /// The loader-provided bias and dynamic pointer retain their selected target width until the ELF
    /// layer performs checked translation into process addresses.
    ///
    /// # Errors
    ///
    /// Returns an error when dynamic symbol metadata violates validated loaded-image geometry.
    #[inline]
    pub fn symbols(
        &self,
        target_process: &ganymede_process::process::Process,
    ) -> Result<DynamicSymbols<AbiType::Elf>, DynamicSymbolsError>
    where
        Dynamic<AbiType::Elf>: catalejo::prelude::Lift<
                Value = <AbiType::Elf as Class>::Dynamic,
                Context = (),
                Error = ElfError,
            >,
        Symbol<AbiType::Elf>: catalejo::prelude::Lift<
                Value = <AbiType::Elf as Class>::Symbol,
                Context = (),
                Error = ElfError,
            >,
    {
        let load_bias = LoadBias::<AbiType::Elf>::new(self.bias());
        let dynamic = ViAddr::new(self.dynamic().address().into());

        let image = LoadedImage::<AbiType::Elf>::read(target_process, load_bias)?;

        DynamicSymbols::read_loaded(&image, dynamic)
    }
}

/// Stable rendezvous identity and contents for one GNU loader namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// NOTE(invariant): The base rendezvous, optional extended identity, and next edge all belong to one `AbiType` and were admitted only after stable observations.
pub struct Rendezvous<AbiType>
where
    AbiType: Abi,
{
    /// Foreign base rendezvous pointer.
    debug: DebugPointer<AbiType>,

    /// Foreign extended rendezvous identity when present.
    extended: Option<ExtendedPointer<AbiType>>,

    /// Stable base rendezvous contents.
    base: DebugRecord<AbiType>,

    /// Foreign pointer to the next extended namespace.
    next: ExtendedPointer<AbiType>,
}

impl<AbiType> Rendezvous<AbiType>
where
    AbiType: Abi,
{
    /// Retain a rendezvous only after its ABI observation has stabilized.
    #[inline]
    pub(crate) const fn new(
        target_debug: DebugPointer<AbiType>,
        target_extended: Option<ExtendedPointer<AbiType>>,
        target_base: DebugRecord<AbiType>,
        target_next: ExtendedPointer<AbiType>,
    ) -> Self {
        Self {
            debug: target_debug,
            extended: target_extended,
            base: target_base,
            next: target_next,
        }
    }

    /// Return the canonical target-width pointer used to identify this namespace rendezvous.
    #[inline]
    #[must_use]
    pub const fn debug(&self) -> DebugPointer<AbiType> {
        let Self { debug, .. } = self;

        *debug
    }

    /// Return the extended-record identity when this namespace came from extended metadata.
    #[inline]
    #[must_use]
    pub const fn extended(&self) -> Option<ExtendedPointer<AbiType>> {
        let Self { extended, .. } = self;

        *extended
    }

    /// Return the stable base `r_debug` observation used for module traversal.
    #[inline]
    #[must_use]
    pub const fn base(&self) -> DebugRecord<AbiType> {
        let Self { base, .. } = self;

        *base
    }

    /// Return the validated edge used to continue extended namespace traversal.
    #[inline]
    #[must_use]
    pub const fn next(&self) -> ExtendedPointer<AbiType> {
        let Self { next, .. } = self;

        *next
    }
}

/// Coherent GNU namespace whose complete link-map chain passed forward and reverse validation.
#[derive(Debug, Clone, PartialEq, Eq)]
// NOTE(invariant): The rendezvous remained stable while every retained `AbiType` module passed complete forward and reverse graph validation.
pub struct Namespace<AbiType>
where
    AbiType: Abi,
{
    /// Stable namespace rendezvous.
    rendezvous: Rendezvous<AbiType>,

    /// Modules in validated forward link-map order.
    modules: Box<[Module<AbiType>]>,
}

impl<AbiType> Namespace<AbiType>
where
    AbiType: Abi,
{
    /// Promote one rendezvous and module sequence after complete graph validation.
    #[inline]
    pub(crate) const fn new(
        target_rendezvous: Rendezvous<AbiType>,
        target_modules: Box<[Module<AbiType>]>,
    ) -> Self {
        Self {
            rendezvous: target_rendezvous,
            modules: target_modules,
        }
    }

    /// Borrow the stable rendezvous that rooted acquisition of this namespace.
    #[inline]
    #[must_use]
    pub const fn rendezvous(&self) -> &Rendezvous<AbiType> {
        let Self { rendezvous, .. } = self;

        rendezvous
    }

    /// Borrow modules in validated forward link-map order.
    #[inline]
    #[must_use]
    pub fn modules(&self) -> &[Module<AbiType>] {
        let Self { modules, .. } = self;

        modules
    }
}

/// Complete coherent GNU loader observation rooted in one validated process image.
#[derive(Debug, Clone, PartialEq, Eq)]
// NOTE(invariant): The main ELF image uses the class selected by `AbiType`, the interpreter proves that GNU profile, and every namespace passed stable complete graph validation.
pub struct Snapshot<AbiType>
where
    AbiType: Abi,
{
    /// Proven main-image ELF load bias.
    main_load_bias: LoadBias<AbiType::Elf>,

    /// Exact validated interpreter path.
    interpreter: BytePath,

    /// Canonical primary target rendezvous pointer.
    debug: DebugPointer<AbiType>,

    /// Stable namespaces retained in traversal order.
    namespaces: Box<[Namespace<AbiType>]>,
}

impl<AbiType> Snapshot<AbiType>
where
    AbiType: Abi,
{
    /// Assemble the final snapshot after every namespace satisfied the acquisition protocol.
    #[inline]
    pub(crate) const fn new(
        target_main_load_bias: LoadBias<AbiType::Elf>,
        target_interpreter: BytePath,
        target_debug: DebugPointer<AbiType>,
        target_namespaces: Box<[Namespace<AbiType>]>,
    ) -> Self {
        Self {
            main_load_bias: target_main_load_bias,
            interpreter: target_interpreter,
            debug: target_debug,
            namespaces: target_namespaces,
        }
    }

    /// Borrow the main-image load bias proven by the matching ELF image reader.
    #[inline]
    #[must_use]
    pub const fn bias(&self) -> &LoadBias<AbiType::Elf> {
        let Self { main_load_bias, .. } = self;

        main_load_bias
    }

    /// Borrow the exact interpreter path that proved the selected GNU loader profile.
    #[inline]
    #[must_use]
    pub const fn interpreter(&self) -> &BytePath {
        let Self { interpreter, .. } = self;

        interpreter
    }

    /// Return the target-width primary rendezvous identity discovered through `DT_DEBUG`.
    #[inline]
    #[must_use]
    pub const fn debug(&self) -> DebugPointer<AbiType> {
        let Self { debug, .. } = self;

        *debug
    }

    /// Borrow all coherent namespaces in extended-rendezvous traversal order.
    #[inline]
    #[must_use]
    pub fn namespaces(&self) -> &[Namespace<AbiType>] {
        let Self { namespaces, .. } = self;

        namespaces
    }
}

impl<AbiType> Snapshot<AbiType>
where
    AbiType: Abi,
{
    /// Normalize every stable GNU module against one process snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error when a module anchor is absent or normalized mapping ownership is ambiguous.
    #[inline]
    pub fn normalize(
        &self,
        target_snapshot: &ganymede_process::process::Snapshot,
    ) -> Result<ganymede_module::Modules, ganymede_module::NormalizeError> {
        let modules = self
            .namespaces()
            .iter()
            .flat_map(Namespace::modules)
            .map(|target_module| target_module.normalize(target_snapshot))
            .collect::<Result<alloc::vec::Vec<_>, _>>()?;

        ganymede_module::Modules::new(modules)
    }
}

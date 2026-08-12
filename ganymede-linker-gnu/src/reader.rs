//! Coherent GNU runtime-linker snapshot acquisition shared by supported ABIs.
//!
//! One sealed GNU ABI family selects target-width records and pointers. The acquisition protocol,
//! bounded stabilization, namespace traversal, graph validation, and retry behavior are implemented
//! once. Conversion to process-wide addresses occurs only at explicit foreign-memory boundaries.

extern crate alloc;

use catalejo::{
    address::ViAddr,
    peephole::Coherent,
    prelude::{StabilizeError, Unassociated},
};
use ganymede_elf::{
    class::Class,
    lift::{Dynamic as ElfDynamic, ElfError},
    process::{Observation as ElfObservation, ProcessImage as ElfProcessImage},
};
use ganymede_process::process::{AccessError, Process, Snapshot};

use crate::{
    STABLE_READ_LIFTS,
    abi::{Abi, ElfAddress},
    acquire::{Interpreter, Target},
    error::{AddressOperation, BusyReason, LinkerError, StructureKind},
    failure::SnapshotError,
    model::{DebugRecord, ExtendedRecord, LinkMapRecord},
    snapshot::{SnapshotLimits, model::Snapshot as ModuleSnapshot},
};

mod dynamic;

mod module;

mod namespace;

mod retry;

use dynamic::Table;
use namespace::Namespaces;
use retry::{AttemptError, Retry};

/// Generated base rendezvous selected by one GNU ABI.
type RawDebug<AbiType> = <AbiType as Abi>::RawDebug;

/// Generated extended rendezvous selected by one GNU ABI.
type RawExtended<AbiType> = <AbiType as Abi>::RawExtended;

/// Generated link-map node selected by one GNU ABI.
type RawMap<AbiType> = <AbiType as Abi>::RawMap;

/// Generated ELF dynamic entry selected through the GNU ABI's ELF family.
type RawDynamic<AbiType> = <<AbiType as Abi>::Elf as Class>::Dynamic;

/// Stable GNU base rendezvous record selected by one ABI family.
type GnuDebug<AbiType> = DebugRecord<AbiType>;

/// Stable GNU extended rendezvous record selected by one ABI family.
type GnuDebugExtended<AbiType> = ExtendedRecord<AbiType>;

/// Stable GNU link-map record selected by one ABI family.
type GnuLinkMap<AbiType> = LinkMapRecord<AbiType>;

/// ELF dynamic-segment width selected by one GNU ABI family.
type DynamicSize<AbiType> = ElfAddress<AbiType>;

impl<AbiType> ModuleSnapshot<AbiType>
where
    AbiType: Abi,
    ElfDynamic<AbiType::Elf>:
        catalejo::prelude::Lift<Value = RawDynamic<AbiType>, Context = (), Error = ElfError>,
    GnuDebug<AbiType>: Coherent<Value = RawDebug<AbiType>, Context = (), Error = LinkerError>,
    GnuDebugExtended<AbiType>:
        Coherent<Value = RawExtended<AbiType>, Context = (), Error = LinkerError>,
    GnuLinkMap<AbiType>: Coherent<Value = RawMap<AbiType>, Context = (), Error = LinkerError>,
{
    /// Capture one coherent GNU loader observation with the ABI profile defaults.
    ///
    /// # Errors
    ///
    /// Returns [`SnapshotError`] for malformed image or GNU metadata, foreign-access failure, or
    /// retry exhaustion after repeated mutation or graph inconsistency.
    #[inline]
    pub fn capture(
        target_process: &Process,
        target_snapshot: &Snapshot,
    ) -> Result<Self, SnapshotError<AbiType>> {
        Self::bounded(target_process, target_snapshot, AbiType::DEFAULT_LIMITS)
    }

    /// Capture one coherent GNU loader observation under caller-selected finite bounds.
    ///
    /// # Errors
    ///
    /// Returns the same failure categories as [`Self::capture`] and reports policy exhaustion when
    /// valid target structures exceed the selected finite bounds.
    #[inline]
    pub fn bounded(
        target_process: &Process,
        target_snapshot: &Snapshot,
        target_limits: SnapshotLimits,
    ) -> Result<Self, SnapshotError<AbiType>> {
        let target = Target::new(target_process, target_snapshot, target_limits);
        let attempt = Attempt::new(target);

        Retry::new(target_limits.attempts()).run(|| attempt.run::<AbiType>())
    }

    /// Capture one coherent GNU loader observation from a process-bound matching ELF image.
    ///
    /// # Errors
    ///
    /// Returns GNU protocol, foreign-access, mutation, and graph-consistency failures. The validated
    /// ELF image is reused and is not read again.
    #[inline]
    pub fn prepared(
        target_observation: &ElfObservation<'_, AbiType::Elf>,
        target_limits: SnapshotLimits,
    ) -> Result<Self, SnapshotError<AbiType>> {
        let target = Target::new(
            target_observation.process(),
            target_observation.snapshot(),
            target_limits,
        );
        let attempt = Attempt::new(target);
        let image = target_observation.image();

        Retry::new(target_limits.attempts()).run(|| attempt.finish::<AbiType>(image))
    }
}

/// Capability for repeated coherent lifts from one attached process.
#[derive(Debug, Clone, Copy)]
// NOTE(invariant): Every lift uses the same process handle retained for this complete acquisition attempt.
pub struct Stable<'target>(
    /// Process used for all stable foreign observations.
    &'target Process,
);

impl<'target> Stable<'target> {
    /// Bind all later stable lifts to one process handle.
    #[inline]
    #[must_use]
    pub const fn new(target_process: &'target Process) -> Self {
        Self(target_process)
    }

    /// Return the exact process handle carried by this stability capability.
    #[inline]
    #[must_use]
    pub const fn process(self) -> &'target Process {
        let Self(process) = self;

        process
    }

    /// Stabilize and lift one typed foreign structure under the configured repetition bound.
    #[inline]
    pub fn lift<AbiType, ForeignType, LiftedType>(
        self,
        target_address: ViAddr,
        target_structure: StructureKind,
    ) -> Result<LiftedType, AttemptError<AbiType>>
    where
        AbiType: Abi,
        ForeignType: Unassociated,
        LiftedType: Coherent<Value = ForeignType, Error = LinkerError>,
        LiftedType::Context: Default,
    {
        let Self(process) = self;
        let foreign =
            Process::open::<ForeignType>(process, target_address).map_err(|target_error| {
                match target_error {
                    AccessError::Io(target_error) => SnapshotError::from(target_error),
                    AccessError::Unavailable(..) => SnapshotError::ForeignAccess {
                        structure: target_structure,
                        address: target_address,
                    },
                }
            })?;

        match foreign.stabilize::<LiftedType, { STABLE_READ_LIFTS }>() {
            Ok(target_value) => Ok(target_value),
            Err(StabilizeError::Lift(source)) => Err(SnapshotError::LinkerLift {
                address: target_address,
                source,
            }
            .into()),
            Err(StabilizeError::Unstable(..)) => {
                Err(AttemptError::Busy(BusyReason::UnstableStructure {
                    structure: target_structure,
                    address: target_address,
                }))
            }
        }
    }
}

/// Fixed target used for one all-or-nothing coherent acquisition attempt.
#[derive(Debug, Clone, Copy)]
// NOTE(invariant): `target` fixes one process observation and one finite policy for every operation in this attempt.
struct Attempt<'target>(
    /// Selected process observation.
    Target<'target>,
);

impl<'target> Attempt<'target> {
    /// Bind one target observation to an attempt.
    #[inline]
    const fn new(target: Target<'target>) -> Self {
        Self(target)
    }

    /// Execute image validation and complete GNU acquisition once.
    fn run<AbiType>(&self) -> Result<ModuleSnapshot<AbiType>, AttemptError<AbiType>>
    where
        AbiType: Abi,
        ElfDynamic<AbiType::Elf>:
            catalejo::prelude::Lift<Value = RawDynamic<AbiType>, Context = (), Error = ElfError>,
        GnuDebug<AbiType>: Coherent<Value = RawDebug<AbiType>, Context = (), Error = LinkerError>,
        GnuDebugExtended<AbiType>:
            Coherent<Value = RawExtended<AbiType>, Context = (), Error = LinkerError>,
        GnuLinkMap<AbiType>: Coherent<Value = RawMap<AbiType>, Context = (), Error = LinkerError>,
    {
        let Self(target) = self;
        let process = target.process();
        let snapshot = target.snapshot();
        let limits = target.limits();
        let image = ElfProcessImage::<AbiType::Elf>::read(
            process,
            snapshot,
            limits.phdrs(),
            limits.interpreter(),
        )
        .map_err(SnapshotError::ElfImage)?;

        self.finish::<AbiType>(&image)
    }

    /// Acquire mutable GNU state from one already validated main ELF image.
    fn finish<AbiType>(
        &self,
        image: &ElfProcessImage<AbiType::Elf>,
    ) -> Result<ModuleSnapshot<AbiType>, AttemptError<AbiType>>
    where
        AbiType: Abi,
        ElfDynamic<AbiType::Elf>:
            catalejo::prelude::Lift<Value = RawDynamic<AbiType>, Context = (), Error = ElfError>,
        GnuDebug<AbiType>: Coherent<Value = RawDebug<AbiType>, Context = (), Error = LinkerError>,
        GnuDebugExtended<AbiType>:
            Coherent<Value = RawExtended<AbiType>, Context = (), Error = LinkerError>,
        GnuLinkMap<AbiType>: Coherent<Value = RawMap<AbiType>, Context = (), Error = LinkerError>,
    {
        let Self(target) = self;
        let process = target.process();
        let limits = target.limits();
        let stable = Stable::new(process);
        let interpreter =
            Interpreter::new(image.interpreter().clone(), AbiType::INTERPRETER_BASENAME)
                .map_err(SnapshotError::UnsupportedInterpreter)?;
        let dynamic = image.dynamic();
        let debug =
            Table::<AbiType>::new(process, dynamic.address(), dynamic.size(), limits)?.debug()?;
        let namespaces = Namespaces::new(stable, limits)
            .read::<AbiType>(debug)?
            .into_boxed_slice();
        let main_load_bias = *image.load_bias();
        let interpreter = interpreter.finish();

        Ok(ModuleSnapshot::new(
            main_load_bias,
            interpreter,
            debug,
            namespaces,
        ))
    }
}

#[cfg(test)]
mod tests {
    //! Regression coverage for both GNU interpreter profiles and shared module-name semantics.

    use ganymede_text::BytePath;

    use super::*;
    use crate::{
        abi::{DynamicPointer, Gnu32, Gnu64, MapPointer, NamePointer},
        snapshot::model::Module,
    };

    fn fixture<AbiType>(
        target_map_address: ElfAddress<AbiType>,
        target_name: &[u8],
    ) -> Module<AbiType>
    where
        AbiType: Abi,
    {
        let map = MapPointer::<AbiType>::new(target_map_address);
        let load_bias = ElfAddress::<AbiType>::default();
        let name_pointer = NamePointer::<AbiType>::new(ElfAddress::<AbiType>::default());
        let dynamic = DynamicPointer::<AbiType>::new(ElfAddress::<AbiType>::default());
        let next = MapPointer::<AbiType>::new(ElfAddress::<AbiType>::default());
        let previous = MapPointer::<AbiType>::new(ElfAddress::<AbiType>::default());
        let name = BytePath::new(target_name);

        Module::new(map, load_bias, name_pointer, dynamic, next, previous, name)
    }

    #[test]
    fn basename_matching_is_shared_and_preserves_non_utf8_bytes() {
        let module32 = fixture::<Gnu32>(1, b"/tmp/lib\xffsample.so");
        let module64 = fixture::<Gnu64>(1, b"/one/libsame.so");

        assert_eq!(module32.basename(), b"lib\xffsample.so");
        assert_eq!(module32.name().as_ref(), b"/tmp/lib\xffsample.so");
        assert_eq!(module64.basename(), b"libsame.so");
    }

    #[test]
    fn interpreter_profiles_remain_abi_specific() {
        let i386 = BytePath::new(b"/lib32/ld-linux.so.2");
        let amd64 = BytePath::new(b"/lib64/ld-linux-x86-64.so.2");
        let other = BytePath::new(b"/lib/not-gnu.so");

        assert!(Interpreter::new(i386, Gnu32::INTERPRETER_BASENAME).is_ok());
        assert!(Interpreter::new(amd64, Gnu64::INTERPRETER_BASENAME).is_ok());
        assert!(Interpreter::new(other, Gnu64::INTERPRETER_BASENAME).is_err());
    }
}

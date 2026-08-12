//! GNU rendezvous and namespace traversal shared by supported ABIs.
//!
//! A consistent rendezvous proof prevents graph inspection while the loader reports mutation.
//! Namespace capture owns one complete forward and reverse module validation interval independent of
//! target pointer width.

extern crate alloc;

use alloc::{collections::BTreeSet, vec, vec::Vec};
use catalejo::peephole::Coherent;

use super::{
    Abi, AttemptError, BusyReason, GnuDebug, GnuDebugExtended, LinkerError, RawDebug, RawExtended,
    SnapshotLimits, Stable, StructureKind, ViAddr, module::Modules,
};
use crate::{
    abi::{DebugPointer, ElfAddress, ExtendedPointer},
    error::InconsistentReason,
    snapshot::{
        GNU_EXTENDED_PROTOCOL_VERSION,
        model::{Namespace, Rendezvous},
    },
};

/// GNU rendezvous proven consistent at one stable observation.
#[derive(Debug, Clone, Copy)]
// NOTE(invariant): `value` was stably lifted for `debug`, both belong to `AbiType`, and the generated state equals `AbiType::CONSISTENT`.
struct Consistent<AbiType>
where
    AbiType: Abi,
{
    /// Foreign base rendezvous pointer.
    debug: DebugPointer<AbiType>,

    /// Stable consistent rendezvous contents.
    value: GnuDebug<AbiType>,
}

impl<AbiType> Consistent<AbiType>
where
    AbiType: Abi,
    GnuDebug<AbiType>: Coherent<Value = RawDebug<AbiType>, Context = (), Error = LinkerError>,
{
    /// Validate one stable rendezvous value.
    #[inline]
    fn new(
        target_debug: DebugPointer<AbiType>,
        target_value: GnuDebug<AbiType>,
    ) -> Result<Self, AttemptError<AbiType>> {
        let state = target_value.state();
        let is_consistent = state == AbiType::CONSISTENT;

        if !is_consistent {
            return Err(AttemptError::Busy(BusyReason::LinkerState {
                debug: target_debug,
                state,
            }));
        }

        Ok(Self {
            debug: target_debug,
            value: target_value,
        })
    }

    /// Lift and validate one base rendezvous.
    #[inline]
    fn read(
        target_stable: Stable<'_>,
        target_debug: DebugPointer<AbiType>,
    ) -> Result<Self, AttemptError<AbiType>> {
        let address = ViAddr::new(target_debug.address().into());

        target_stable
            .lift::<AbiType, RawDebug<AbiType>, GnuDebug<AbiType>>(address, StructureKind::Debug)
            .and_then(|target_value| Self::new(target_debug, target_value))
    }

    /// Return the consistent rendezvous value.
    #[inline]
    const fn value(&self) -> GnuDebug<AbiType> {
        let Self { value, .. } = self;

        *value
    }

    /// Return the bound rendezvous pointer.
    #[inline]
    const fn debug(&self) -> DebugPointer<AbiType> {
        let Self { debug, .. } = self;

        *debug
    }
}

/// Complete namespace-chain reader for one attempt.
#[derive(Debug, Clone, Copy)]
pub struct Namespaces<'target> {
    /// Stable foreign access.
    stable: Stable<'target>,

    /// Finite namespace policy.
    limits: SnapshotLimits,
}

impl<'target> Namespaces<'target> {
    /// Bind namespace traversal to stable access and finite limits.
    #[inline]
    #[must_use]
    pub const fn new(target_stable: Stable<'target>, target_limits: SnapshotLimits) -> Self {
        Self {
            stable: target_stable,
            limits: target_limits,
        }
    }

    /// Read every supported namespace from the primary rendezvous.
    #[inline]
    pub fn read<AbiType>(
        self,
        target_debug: DebugPointer<AbiType>,
    ) -> Result<Vec<Namespace<AbiType>>, AttemptError<AbiType>>
    where
        AbiType: Abi,
        GnuDebug<AbiType>: Coherent<Value = RawDebug<AbiType>, Context = (), Error = LinkerError>,
        GnuDebugExtended<AbiType>:
            Coherent<Value = RawExtended<AbiType>, Context = (), Error = LinkerError>,
        super::GnuLinkMap<AbiType>:
            Coherent<Value = super::RawMap<AbiType>, Context = (), Error = LinkerError>,
    {
        let Self { stable, limits } = self;
        let initial = Consistent::<AbiType>::read(stable, target_debug)?;
        let capture = Capture::new(stable, limits);
        let is_extended = initial.value().version() >= GNU_EXTENDED_PROTOCOL_VERSION;

        if !is_extended {
            let next = ExtendedPointer::<AbiType>::new(ElfAddress::<AbiType>::default());
            let rendezvous = Rendezvous::new(target_debug, None, initial.value(), next);

            return capture
                .read::<AbiType>(rendezvous)
                .map(|target_namespace| vec![target_namespace]);
        }

        let mut cursor = ExtendedPointer::<AbiType>::new(target_debug.address());
        let mut seen = BTreeSet::new();
        let mut namespaces = Vec::new();

        while cursor.nonnull() {
            if namespaces.len() >= limits.namespaces().get() {
                return Err(AttemptError::Inconsistent(
                    InconsistentReason::NamespaceBound,
                ));
            }

            if !seen.insert(cursor.address()) {
                return Err(AttemptError::Inconsistent(
                    InconsistentReason::NamespaceCycle(cursor),
                ));
            }

            let extended = cursor;
            let debug = DebugPointer::<AbiType>::new(extended.address());
            let address = ViAddr::new(extended.address().into());
            let value = stable.lift::<AbiType, RawExtended<AbiType>, GnuDebugExtended<AbiType>>(
                address,
                StructureKind::ExtendedDebug,
            )?;
            let base = Consistent::<AbiType>::new(debug, value.base())?;
            let version = base.value().version();
            let is_supported = version >= GNU_EXTENDED_PROTOCOL_VERSION;

            if !is_supported {
                return Err(AttemptError::Inconsistent(
                    InconsistentReason::NamespaceProtocol { debug, version },
                ));
            }

            let next = value.next();
            let rendezvous = Rendezvous::new(base.debug(), Some(extended), base.value(), next);

            namespaces.push(capture.read::<AbiType>(rendezvous)?);
            cursor = next;
        }

        Ok(namespaces)
    }
}

/// One namespace capture interval.
#[derive(Debug, Clone, Copy)]
// NOTE(invariant): `stable` and `limits` remain fixed while one namespace rendezvous is read before and after complete module validation.
struct Capture<'target> {
    /// Stable foreign access.
    stable: Stable<'target>,

    /// Finite module policy.
    limits: SnapshotLimits,
}

impl<'target> Capture<'target> {
    /// Construct one namespace capture interval.
    #[inline]
    const fn new(target_stable: Stable<'target>, target_limits: SnapshotLimits) -> Self {
        Self {
            stable: target_stable,
            limits: target_limits,
        }
    }

    /// Capture one namespace while proving rendezvous stability.
    fn read<AbiType>(
        self,
        target_before: Rendezvous<AbiType>,
    ) -> Result<Namespace<AbiType>, AttemptError<AbiType>>
    where
        AbiType: Abi,
        GnuDebug<AbiType>: Coherent<Value = RawDebug<AbiType>, Context = (), Error = LinkerError>,
        GnuDebugExtended<AbiType>:
            Coherent<Value = RawExtended<AbiType>, Context = (), Error = LinkerError>,
        super::GnuLinkMap<AbiType>:
            Coherent<Value = super::RawMap<AbiType>, Context = (), Error = LinkerError>,
    {
        let Self { stable, limits } = self;
        let debug = target_before.debug();
        let base = Consistent::<AbiType>::new(debug, target_before.base())?;
        let walk = Modules::new(stable, limits).read::<AbiType>(debug, base.value().map())?;
        let after = Probe::new(stable).read::<AbiType>(target_before)?;
        let _consistent = Consistent::<AbiType>::new(debug, after.base())?;
        let structure = target_before
            .extended()
            .map_or(StructureKind::Debug, |_| StructureKind::ExtendedDebug);
        let is_stable = target_before == after;

        if !is_stable {
            return Err(AttemptError::Busy(BusyReason::StructureChanged {
                structure,
                address: ViAddr::new(debug.address().into()),
            }));
        }

        Ok(Namespace::new(after, walk.finish()))
    }
}

/// Rereader for one namespace rendezvous identity.
#[derive(Debug, Clone, Copy)]
struct Probe<'target>(Stable<'target>);

impl<'target> Probe<'target> {
    /// Bind rereads to stable foreign access.
    #[inline]
    const fn new(target_stable: Stable<'target>) -> Self {
        Self(target_stable)
    }

    /// Reread one rendezvous through the same foreign identity.
    fn read<AbiType>(
        self,
        target_before: Rendezvous<AbiType>,
    ) -> Result<Rendezvous<AbiType>, AttemptError<AbiType>>
    where
        AbiType: Abi,
        GnuDebug<AbiType>: Coherent<Value = RawDebug<AbiType>, Context = (), Error = LinkerError>,
        GnuDebugExtended<AbiType>:
            Coherent<Value = RawExtended<AbiType>, Context = (), Error = LinkerError>,
    {
        let Self(stable) = self;
        let debug = target_before.debug();

        target_before.extended().map_or_else(
            || {
                let address = ViAddr::new(debug.address().into());
                let next = ExtendedPointer::<AbiType>::new(ElfAddress::<AbiType>::default());

                stable
                    .lift::<AbiType, RawDebug<AbiType>, GnuDebug<AbiType>>(
                        address,
                        StructureKind::Debug,
                    )
                    .map(|target_base| Rendezvous::new(debug, None, target_base, next))
            },
            |target_extended| {
                let address = ViAddr::new(target_extended.address().into());

                stable
                    .lift::<AbiType, RawExtended<AbiType>, GnuDebugExtended<AbiType>>(
                        address,
                        StructureKind::ExtendedDebug,
                    )
                    .map(|target_value| {
                        Rendezvous::new(
                            debug,
                            Some(target_extended),
                            target_value.base(),
                            target_value.next(),
                        )
                    })
            },
        )
    }
}

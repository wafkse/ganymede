//! GNU link-map traversal and bidirectional validation shared by supported ABIs.
//!
//! Forward traversal owns cursor, cycle, and predecessor state. Stable node observations prove one
//! lifted record at one target-width pointer. Reverse traversal validates the retained graph
//! independently through the same ABI family.

extern crate alloc;

use alloc::{collections::BTreeSet, vec::Vec};
use catalejo::peephole::Coherent;
use ganymede_text::BytePath;

use super::{
    Abi, AttemptError, BusyReason, GnuLinkMap, LinkerError, Process, RawMap, SnapshotError,
    SnapshotLimits, Stable, StructureKind, ViAddr,
};
use crate::{
    abi::{ElfAddress, MapPointer},
    acquire::Walk,
    error::InconsistentReason,
    snapshot::model::Module,
};

/// One validated forward-walk position pairing its public module with the stable ABI node.
type Step<AbiType> = (Module<AbiType>, GnuLinkMap<AbiType>);

/// Module-chain reader bound to one stability capability and finite policy.
#[derive(Debug, Clone, Copy)]
pub struct Modules<'target> {
    /// Stable foreign access for this attempt.
    stable: Stable<'target>,

    /// Finite traversal policy.
    limits: SnapshotLimits,
}

impl<'target> Modules<'target> {
    /// Bind module traversal to stable access and finite limits.
    #[inline]
    #[must_use]
    pub const fn new(target_stable: Stable<'target>, target_limits: SnapshotLimits) -> Self {
        Self {
            stable: target_stable,
            limits: target_limits,
        }
    }

    /// Read the forward chain and validate its reverse edges.
    #[inline]
    pub fn read<AbiType>(
        self,
        target_debug: crate::abi::DebugPointer<AbiType>,
        target_head: MapPointer<AbiType>,
    ) -> Result<Walk<AbiType>, AttemptError<AbiType>>
    where
        AbiType: Abi,
        GnuLinkMap<AbiType>: Coherent<Value = RawMap<AbiType>, Context = (), Error = LinkerError>,
    {
        let Self { stable, limits } = self;
        let walk = Forward::<AbiType>::new(stable, limits, target_debug, target_head)
            .collect::<Result<Vec<_>, _>>()
            .map(Walk::new)?;

        Reverse::<AbiType>::new(stable, &walk).run()?;

        Ok(walk)
    }
}

/// Stable observation of one link-map pointer and node.
#[derive(Debug, Clone, Copy)]
// NOTE(invariant): `node` was stably lifted from exactly `map` at `address` during the current attempt and every value belongs to `AbiType`.
struct StableMap<AbiType>
where
    AbiType: Abi,
{
    /// Canonical foreign link-map pointer.
    map: MapPointer<AbiType>,

    /// Process-space address corresponding to `map`.
    address: ViAddr,

    /// Stable lifted link-map contents.
    node: GnuLinkMap<AbiType>,
}

impl<AbiType> StableMap<AbiType>
where
    AbiType: Abi,
    GnuLinkMap<AbiType>: Coherent<Value = RawMap<AbiType>, Context = (), Error = LinkerError>,
{
    /// Lift one link-map pointer into a stable observation.
    fn read(
        target_stable: Stable<'_>,
        target_map: MapPointer<AbiType>,
    ) -> Result<Self, AttemptError<AbiType>> {
        let address = ViAddr::new(target_map.address().into());
        let node = target_stable.lift::<AbiType, RawMap<AbiType>, GnuLinkMap<AbiType>>(
            address,
            StructureKind::LinkMap,
        )?;

        Ok(Self {
            map: target_map,
            address,
            node,
        })
    }

    /// Require the expected reverse edge.
    fn previous(self, target_expected: MapPointer<AbiType>) -> Result<Self, AttemptError<AbiType>> {
        let Self { map, node, .. } = self;
        let observed = node.previous();
        let is_expected = observed == target_expected;

        if !is_expected {
            return Err(AttemptError::Inconsistent(
                InconsistentReason::PreviousMismatch {
                    map,
                    expected: target_expected,
                    observed,
                },
            ));
        }

        Ok(self)
    }

    /// Read the exact name and prove the link-map node remained unchanged.
    fn module(
        self,
        target_stable: Stable<'_>,
        target_limits: SnapshotLimits,
    ) -> Result<(Module<AbiType>, GnuLinkMap<AbiType>), AttemptError<AbiType>> {
        let Self { map, address, node } = self;
        let name_address = ViAddr::new(node.name().address().into());
        let name = Process::read_c_string_bytes(
            target_stable.process(),
            name_address,
            target_limits.names(),
        )
        .map_err(SnapshotError::from)?;
        let after = target_stable.lift::<AbiType, RawMap<AbiType>, GnuLinkMap<AbiType>>(
            address,
            StructureKind::LinkMap,
        )?;
        let is_stable = node == after;

        if !is_stable {
            return Err(AttemptError::Busy(BusyReason::StructureChanged {
                structure: StructureKind::LinkMap,
                address,
            }));
        }

        let load_bias = after.address();
        let name_pointer = after.name();
        let dynamic = after.dynamic();
        let next = after.next();
        let previous = after.previous();
        let name = BytePath::new(&name);
        let module = Module::new(map, load_bias, name_pointer, dynamic, next, previous, name);

        Ok((module, after))
    }
}

/// Stateful forward link-map iterator.
#[derive(Debug)]
// NOTE(invariant): `previous` is the last successfully yielded map, `current` is its validated next edge, and `seen` contains exactly yielded target-width map addresses.
struct Forward<'target, AbiType>
where
    AbiType: Abi,
{
    /// Stable foreign access.
    stable: Stable<'target>,

    /// Finite traversal policy.
    limits: SnapshotLimits,

    /// Owning namespace rendezvous.
    debug: crate::abi::DebugPointer<AbiType>,

    /// Previously yielded link-map addresses.
    seen: BTreeSet<ElfAddress<AbiType>>,

    /// Next link-map pointer to inspect.
    current: MapPointer<AbiType>,

    /// Required reverse edge for `current`.
    previous: MapPointer<AbiType>,
}

impl<'target, AbiType> Forward<'target, AbiType>
where
    AbiType: Abi,
    GnuLinkMap<AbiType>: Coherent<Value = RawMap<AbiType>, Context = (), Error = LinkerError>,
{
    /// Construct a forward iterator at one namespace head.
    fn new(
        target_stable: Stable<'target>,
        target_limits: SnapshotLimits,
        target_debug: crate::abi::DebugPointer<AbiType>,
        target_head: MapPointer<AbiType>,
    ) -> Self {
        let previous = MapPointer::<AbiType>::new(ElfAddress::<AbiType>::default());

        Self {
            stable: target_stable,
            limits: target_limits,
            debug: target_debug,
            seen: BTreeSet::new(),
            current: target_head,
            previous,
        }
    }

    /// Read one forward position.
    fn step(&mut self) -> Result<Option<Step<AbiType>>, AttemptError<AbiType>> {
        let Self {
            stable,
            limits,
            debug,
            seen,
            current,
            previous,
        } = self;

        if current.null() {
            return Ok(None);
        }

        if seen.len() >= limits.modules().get() {
            return Err(AttemptError::Inconsistent(InconsistentReason::ModuleBound(
                *debug,
            )));
        }

        if !seen.insert(current.address()) {
            return Err(AttemptError::Inconsistent(InconsistentReason::ModuleCycle(
                *current,
            )));
        }

        let map = *current;
        let observation = StableMap::read(*stable, map)?.previous(*previous)?;
        let (module, node) = observation.module(*stable, *limits)?;
        let next = node.next();

        *previous = map;
        *current = next;

        Ok(Some((module, node)))
    }
}

impl<AbiType> Iterator for Forward<'_, AbiType>
where
    AbiType: Abi,
    GnuLinkMap<AbiType>: Coherent<Value = RawMap<AbiType>, Context = (), Error = LinkerError>,
{
    type Item = Result<Step<AbiType>, AttemptError<AbiType>>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.step().transpose()
    }
}

/// Reverse validation state for one completed forward walk.
#[derive(Debug)]
// NOTE(invariant): `current` and `next` are the reverse cursor edges required by the already validated suffix of `walk` and all pointers retain `AbiType` identity.
struct Reverse<'walk, 'target, AbiType>
where
    AbiType: Abi,
{
    /// Stable foreign access.
    stable: Stable<'target>,

    /// Forward proof being checked in reverse.
    walk: &'walk Walk<AbiType>,

    /// Current reverse pointer.
    current: MapPointer<AbiType>,

    /// Required forward edge from `current`.
    next: MapPointer<AbiType>,
}

impl<'walk, 'target, AbiType> Reverse<'walk, 'target, AbiType>
where
    AbiType: Abi,
    GnuLinkMap<AbiType>: Coherent<Value = RawMap<AbiType>, Context = (), Error = LinkerError>,
{
    /// Construct reverse validation at the final forward module.
    fn new(target_stable: Stable<'target>, target_walk: &'walk Walk<AbiType>) -> Self {
        let null = ElfAddress::<AbiType>::default();
        let current = target_walk.iter().next_back().map_or_else(
            || MapPointer::<AbiType>::new(null),
            |(target_module, _)| target_module.map(),
        );
        let next = MapPointer::<AbiType>::new(null);

        Self {
            stable: target_stable,
            walk: target_walk,
            current,
            next,
        }
    }

    /// Validate the complete reverse traversal.
    fn run(mut self) -> Result<(), AttemptError<AbiType>> {
        let Self {
            stable,
            walk,
            current,
            next,
        } = &mut self;

        for (target_module, target_forward) in walk.iter().rev() {
            let expected = target_module.map();

            if *current != expected {
                return Err(AttemptError::Inconsistent(
                    InconsistentReason::ReverseMapMismatch {
                        expected,
                        observed: *current,
                    },
                ));
            }

            let observed = StableMap::read(*stable, *current)?;

            if observed.node != *target_forward {
                return Err(AttemptError::Busy(BusyReason::StructureChanged {
                    structure: StructureKind::LinkMap,
                    address: observed.address,
                }));
            }

            let observed_next = observed.node.next();

            if observed_next != *next {
                return Err(AttemptError::Inconsistent(
                    InconsistentReason::NextMismatch {
                        map: *current,
                        expected: *next,
                        observed: observed_next,
                    },
                ));
            }

            *next = *current;
            *current = observed.node.previous();
        }

        if current.nonnull() {
            return Err(AttemptError::Inconsistent(
                InconsistentReason::ReverseDidNotTerminate(*current),
            ));
        }

        Ok(())
    }
}

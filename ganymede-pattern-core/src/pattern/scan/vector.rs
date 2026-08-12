//! Safe SIMD capability used by masked pattern scanning.
//!
//! [`Vector`] binds one `fearless_simd` implementation to vector operations used during a search.
//! The type keeps dispatch state explicit and gives verification, probe filtering, and scalar tail
//! handling one owner. Architecture-specific feature detection and unsafe intrinsics remain inside
//! `fearless_simd`.

use fearless_simd::{Simd, prelude::*};

use super::super::{Pattern, Probe};

/// Bound SIMD implementation for one dispatched scanner operation.
///
/// The value does not own pattern or haystack data. It carries only the selected vector capability,
/// so all slice access remains ordinary safe Rust and every load is checked before it reaches the
/// SIMD abstraction.
#[derive(Debug, Clone, Copy)]
// NOTE(invariant): The stored SIMD value is the capability selected for the complete operation, so vector width and comparison semantics remain consistent across every probe and verification step.
pub struct Vector<SimdType: Simd>(SimdType);

impl<SimdType: Simd> Vector<SimdType> {
    /// Bind one dispatched SIMD implementation to the scanner kernels.
    #[inline]
    #[must_use]
    pub const fn new(target_simd: SimdType) -> Self {
        Self(target_simd)
    }

    /// Verify every constrained bit of one same-width candidate.
    ///
    /// Complete native-width chunks use vector comparisons. The final incomplete chunk uses scalar
    /// iteration over the already bounded slices. The method assumes only that `target_candidate`
    /// has the same width as `target_pattern`, which the scanner proves before calling it.
    #[inline]
    #[must_use]
    pub fn verify(self, target_pattern: Pattern<'_>, target_candidate: &[u8]) -> bool {
        let Self(simd) = self;
        let bytes = target_pattern.bytes();
        let masks = target_pattern.masks();
        let lanes = SimdType::u8s::N;
        let mut candidate_chunks = target_candidate.chunks_exact(lanes);
        let mut pattern_chunks = bytes.chunks_exact(lanes);
        let mut mask_chunks = masks.chunks_exact(lanes);
        let zero = SimdType::u8s::splat(simd, 0);
        let vectors_match = candidate_chunks
            .by_ref()
            .zip(pattern_chunks.by_ref())
            .zip(mask_chunks.by_ref())
            .all(
                |((target_candidate_chunk, target_pattern_chunk), target_mask_chunk)| {
                    let candidate = SimdType::u8s::from_slice(simd, target_candidate_chunk);
                    let pattern = SimdType::u8s::from_slice(simd, target_pattern_chunk);
                    let mask = SimdType::u8s::from_slice(simd, target_mask_chunk);
                    let difference = (candidate ^ pattern) & mask;

                    difference.simd_eq(zero).all_true()
                },
            );
        let remainder_matches = candidate_chunks
            .remainder()
            .iter()
            .zip(pattern_chunks.remainder())
            .zip(mask_chunks.remainder())
            .all(|((&target_byte, &pattern_byte), &mask)| {
                ((target_byte ^ pattern_byte) & mask) == 0
            });

        vectors_match && remainder_matches
    }

    /// Return candidate lanes that satisfy one or two selective pattern probes.
    ///
    /// A complete native vector is filtered in parallel. A shorter final group stays scalar so no
    /// padded load or unchecked tail access is required. Set bits in the returned mask correspond to
    /// candidate starts relative to `target_base`.
    #[inline]
    #[must_use]
    pub fn mask(
        self,
        target_haystack: &[u8],
        target_base: usize,
        target_first: Probe,
        target_second: Option<Probe>,
        target_count: usize,
    ) -> u64 {
        let Self(simd) = self;
        let lanes = SimdType::u8s::N;
        let is_full_vector = target_count == lanes;

        if is_full_vector {
            let first = Self::probe(simd, target_haystack, target_base, target_first, lanes);
            let second = target_second.map_or(u64::MAX, |target_probe| {
                Self::probe(simd, target_haystack, target_base, target_probe, lanes)
            });

            first & second
        } else {
            Self::scalar(
                target_haystack,
                target_base,
                target_first,
                target_second,
                target_count,
            )
        }
    }

    /// Compare one masked probe across a complete native vector of candidate starts.
    #[inline]
    fn probe(
        target_simd: SimdType,
        target_haystack: &[u8],
        target_base: usize,
        target_probe: Probe,
        target_lanes: usize,
    ) -> u64 {
        let start = target_base + target_probe.offset;
        let end = start + target_lanes;
        let source_bytes = target_haystack
            .get(start..end)
            .expect("validated candidate span must contain one complete SIMD probe window");
        let source = SimdType::u8s::from_slice(target_simd, source_bytes);
        let value = SimdType::u8s::splat(target_simd, target_probe.value);
        let mask = SimdType::u8s::splat(target_simd, target_probe.mask);
        let zero = SimdType::u8s::splat(target_simd, 0);
        let difference = (source ^ value) & mask;

        difference.simd_eq(zero).to_bitmask()
    }

    /// Filter the final incomplete candidate group without constructing a partial vector.
    #[inline]
    fn scalar(
        target_haystack: &[u8],
        target_base: usize,
        target_first: Probe,
        target_second: Option<Probe>,
        target_count: usize,
    ) -> u64 {
        (0..target_count).fold(0u64, |target_mask, target_lane| {
            let first_position = target_base + target_lane + target_first.offset;
            let first_byte = target_haystack
                .get(first_position)
                .expect("validated candidate span must contain the first scalar probe byte");
            let is_first_match = ((*first_byte ^ target_first.value) & target_first.mask) == 0;
            let is_second_match = target_second.is_none_or(|target_probe| {
                let second_position = target_base + target_lane + target_probe.offset;
                let second_byte = target_haystack
                    .get(second_position)
                    .expect("validated candidate span must contain the second scalar probe byte");

                ((*second_byte ^ target_probe.value) & target_probe.mask) == 0
            });

            if is_first_match && is_second_match {
                target_mask | (1 << target_lane)
            } else {
                target_mask
            }
        })
    }
}

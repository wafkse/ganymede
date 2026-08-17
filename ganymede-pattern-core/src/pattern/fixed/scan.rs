//! Private fixed-width search engine for unified patterns.
//!
//! Construction preprocesses literal search anchors and records the available SIMD level once. A
//! search then selects among literal substring search, anchored verification, masked probe filtering,
//! and the unconstrained wildcard case without reparsing or reallocating the pattern.
//!

use fearless_simd::{Level, Simd, dispatch, prelude::SimdBase};
use memchr::memmem::Finder;

use super::{Fixed, Probe, SearchPlan};

mod vector;

use vector::Vector;

/// Smallest native byte vector exposed by `fearless_simd`.
const MINIMUM_VECTOR_BYTES: usize = 16;

/// Preprocessed fixed projection used by the unified scanner.
///
/// Literal and anchored plans retain a `memmem` finder built from the exact borrowed anchor. The SIMD
/// level is detected during construction and reused by every later search. Neither operation changes
/// the semantic pattern or copies its byte representation.
#[derive(Debug)]
// NOTE(invariant): `finder` is present exactly for plans with an exact-byte anchor and was built from the same borrowed pattern retained here.
pub struct Scanner<'pattern> {
    /// Validated pattern being searched.
    pattern: Fixed<'pattern>,

    /// Preprocessed substring finder for literal or anchored plans.
    finder: Option<Finder<'pattern>>,

    /// SIMD feature level detected once for repeated scanning.
    level: Level,
}

impl<'pattern> Scanner<'pattern> {
    /// Prepare anchor search and SIMD dispatch state for repeated scans.
    ///
    /// Construction does not inspect a haystack and performs no pattern parsing. A `memmem` finder is
    /// created only when the compiled search plan contains an exact literal run.
    #[inline]
    pub fn new(target_pattern: Fixed<'pattern>) -> Self {
        let anchor = target_pattern.anchor();
        let finder = anchor.map(Finder::new);
        let level = Level::new();

        Self {
            pattern: target_pattern,
            finder,
            level,
        }
    }

    /// Find the earliest matching start offset in one haystack.
    ///
    /// The returned offset is relative to the beginning of `target_haystack`. A haystack shorter than
    /// the fixed pattern width cannot match and returns `None`.
    #[inline]
    #[must_use]
    pub fn find_in(
        &self,
        target_haystack: &[u8],
        target_start: usize,
        target_end: usize,
    ) -> Option<usize> {
        self.find_from(target_haystack, target_start, target_end)
    }

    /// Search at or after one byte offset using only plans that benefit from SIMD dispatch.
    fn find_from(
        &self,
        target_haystack: &[u8],
        target_start: usize,
        target_end: usize,
    ) -> Option<usize> {
        let Self {
            pattern,
            finder,
            level,
        } = self;
        let width = pattern.len();
        let available = target_haystack.len().checked_sub(width);
        let requested_last = target_end.checked_sub(1);
        let last_start = available
            .zip(requested_last)
            .map(|(target_available, target_requested)| target_available.min(target_requested))
            .filter(|target_last| target_start <= *target_last);
        let vector_width_available = width >= MINIMUM_VECTOR_BYTES;

        match (pattern.plan(), finder, last_start, vector_width_available) {
            (_, _, None, _) => None,
            (SearchPlan::Wildcard, _, Some(_), _) => Some(target_start),
            (SearchPlan::Literal, Some(target_finder), Some(target_last), _) => {
                let target_search_end = target_last + width;

                target_finder
                    .find(&target_haystack[target_start..target_search_end])
                    .map(|target_offset| target_start + target_offset)
            }
            (
                SearchPlan::Anchor { offset, length: _ },
                Some(target_finder),
                Some(target_last),
                false,
            ) => Self::find_anchor(
                *pattern,
                target_finder,
                offset,
                target_haystack,
                target_start,
                target_last,
                |target_pattern, target_candidate| target_pattern.matches(target_candidate),
            ),
            (
                SearchPlan::Anchor { offset, length: _ },
                Some(target_finder),
                Some(target_last),
                true,
            ) => dispatch!(*level, simd => Self::find_anchor(
                *pattern,
                target_finder,
                offset,
                target_haystack,
                target_start,
                target_last,
                |target_pattern, target_candidate| Vector::new(simd).verify(target_pattern, target_candidate),
            )),
            (SearchPlan::Probes { first, second }, None, Some(target_last), _) => {
                dispatch!(*level, simd => Self::find_probes(
                    *pattern,
                    simd,
                    first,
                    second,
                    target_haystack,
                    target_start,
                    target_last,
                ))
            }
            _ => unreachable!("scanner representation keeps finder presence coherent with plan"),
        }
    }

    /// Discover candidates through a preprocessed exact substring anchor.
    #[inline]
    fn find_anchor<Verifier>(
        target_pattern: Fixed<'_>,
        target_finder: &Finder<'_>,
        target_anchor_offset: usize,
        target_haystack: &[u8],
        target_start: usize,
        target_last: usize,
        mut target_verify: Verifier,
    ) -> Option<usize>
    where
        Verifier: FnMut(Fixed<'_>, &[u8]) -> bool,
    {
        let anchor_search_start = target_start + target_anchor_offset;
        let anchor_search_end = target_last + target_anchor_offset + target_finder.needle().len();
        let anchor_haystack = target_haystack
            .get(anchor_search_start..anchor_search_end)
            .expect("validated anchor search span must remain within the haystack");
        let mut search_offset = 0usize;
        let mut result = None;

        while result.is_none() && search_offset <= anchor_haystack.len() {
            let search_bytes = anchor_haystack
                .get(search_offset..)
                .expect("anchor search offset must remain within the validated span");
            let found = target_finder.find(search_bytes);

            match found {
                Some(target_relative) => {
                    let anchor_offset = anchor_search_start + search_offset + target_relative;
                    let candidate = anchor_offset - target_anchor_offset;
                    let candidate_end = candidate + target_pattern.len();
                    let candidate_bytes = target_haystack
                        .get(candidate..candidate_end)
                        .expect("anchor candidate must remain within the validated haystack span");
                    let is_valid_candidate = target_verify(target_pattern, candidate_bytes);

                    if is_valid_candidate {
                        result = Some(candidate);
                    } else {
                        search_offset += target_relative + 1;
                    }
                }
                None => search_offset = anchor_haystack.len() + 1,
            }
        }

        result
    }

    /// Discover candidates through one or two masked SIMD probes.
    #[inline]
    fn find_probes<SimdType: Simd>(
        target_pattern: Fixed<'_>,
        target_simd: SimdType,
        target_first: Probe,
        target_second: Option<Probe>,
        target_haystack: &[u8],
        target_start: usize,
        target_last: usize,
    ) -> Option<usize> {
        let lanes = SimdType::u8s::N;
        let mut base = target_start;
        let mut result = None;

        while result.is_none() && base <= target_last {
            let remaining = target_last - base + 1;
            let candidate_count = remaining.min(lanes);
            let mut candidate_mask = Vector::new(target_simd).mask(
                target_haystack,
                base,
                target_first,
                target_second,
                candidate_count,
            );

            while candidate_mask != 0 && result.is_none() {
                let lane = candidate_mask.trailing_zeros() as usize;
                let candidate = base + lane;
                let candidate_end = candidate + target_pattern.len();
                let candidate_bytes = target_haystack
                    .get(candidate..candidate_end)
                    .expect("probe candidate must remain within the validated haystack span");
                let is_valid_candidate =
                    Vector::new(target_simd).verify(target_pattern, candidate_bytes);

                if is_valid_candidate {
                    result = Some(candidate);
                } else {
                    candidate_mask &= candidate_mask - 1;
                }
            }

            base = base.saturating_add(candidate_count);
        }

        result
    }
}

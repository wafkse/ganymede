//! Reusable scanners over validated fixed-width patterns.
//!
//! Construction preprocesses literal search anchors and records the available SIMD level once. A
//! search then selects among literal substring search, anchored verification, masked probe filtering,
//! and the unconstrained wildcard case without reparsing or reallocating the pattern.
//!
//! Match iteration advances one byte after each match start rather than one pattern width. This
//! intentionally preserves overlapping matches.

use fearless_simd::{Level, Simd, dispatch, prelude::SimdBase};
use memchr::memmem::Finder;

use super::{Pattern, Probe, SearchPlan};

mod vector;

use vector::Vector;

/// Smallest native byte vector exposed by `fearless_simd`.
const MINIMUM_VECTOR_BYTES: usize = 16;

/// Preprocessed search context for repeated scans with one pattern.
///
/// Literal and anchored plans retain a `memmem` finder built from the exact borrowed anchor. The SIMD
/// level is detected during construction and reused by every later search. Neither operation changes
/// the semantic pattern or copies its byte representation.
#[derive(Debug)]
// NOTE(invariant): `finder` is present exactly for plans with an exact-byte anchor and was built from the same borrowed pattern retained here.
pub struct Scanner<'pattern> {
    /// Validated pattern being searched.
    pattern: Pattern<'pattern>,

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
    pub fn new(target_pattern: Pattern<'pattern>) -> Self {
        let anchor = target_pattern.anchor();
        let finder = anchor.map(Finder::new);
        let level = Level::new();

        Self {
            pattern: target_pattern,
            finder,
            level,
        }
    }

    /// Return the fixed pattern width.
    #[inline]
    #[must_use]
    pub const fn pattern_len(&self) -> usize {
        let Self { pattern, .. } = self;

        pattern.len()
    }

    /// Find the earliest matching start offset in one haystack.
    ///
    /// The returned offset is relative to the beginning of `target_haystack`. A haystack shorter than
    /// the fixed pattern width cannot match and returns `None`.
    #[inline]
    #[must_use]
    pub fn find(&self, target_haystack: &[u8]) -> Option<usize> {
        self.find_from(target_haystack, 0)
    }

    /// Iterate matching start offsets in ascending order while preserving overlap.
    ///
    /// The iterator borrows both this scanner and the haystack. It performs no allocation and resumes
    /// each search one byte after the previously yielded start.
    #[inline]
    #[must_use]
    pub const fn find_iter<'scanner, 'haystack>(
        &'scanner self,
        target_haystack: &'haystack [u8],
    ) -> Matches<'scanner, 'haystack, 'pattern> {
        Matches {
            scanner: self,
            haystack: target_haystack,
            next_offset: 0,
        }
    }

    /// Search at or after one byte offset using only plans that benefit from SIMD dispatch.
    fn find_from(&self, target_haystack: &[u8], target_start: usize) -> Option<usize> {
        let Self {
            pattern,
            finder,
            level,
        } = self;
        let width = pattern.len();
        let available = target_haystack.len().checked_sub(width);
        let last_start = available.filter(|target_last| target_start <= *target_last);
        let vector_width_available = width >= MINIMUM_VECTOR_BYTES;

        match (pattern.plan(), finder, last_start, vector_width_available) {
            (_, _, None, _) => None,
            (SearchPlan::Wildcard, _, Some(_), _) => Some(target_start),
            (SearchPlan::Literal, Some(target_finder), Some(_), _) => target_finder
                .find(&target_haystack[target_start..])
                .map(|target_offset| target_start + target_offset),
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
        target_pattern: Pattern<'_>,
        target_finder: &Finder<'_>,
        target_anchor_offset: usize,
        target_haystack: &[u8],
        target_start: usize,
        target_last: usize,
        mut target_verify: Verifier,
    ) -> Option<usize>
    where
        Verifier: FnMut(Pattern<'_>, &[u8]) -> bool,
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
        target_pattern: Pattern<'_>,
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

/// Allocation-free iterator over ordered and potentially overlapping matches.
///
/// The iterator stores only the next candidate start. It delegates each search step to the retained
/// [`Scanner`], so finder preprocessing and SIMD feature detection are reused for the full iteration.
#[derive(Debug)]
// NOTE(invariant): `next_offset` is either zero or one byte past the previously yielded match start, so overlapping matches remain observable and progress is guaranteed.
pub struct Matches<'scanner, 'haystack, 'pattern> {
    /// Preprocessed scanner reused for each search step.
    scanner: &'scanner Scanner<'pattern>,

    /// Haystack retained for the iterator lifetime.
    haystack: &'haystack [u8],

    /// Earliest candidate start for the next search.
    next_offset: usize,
}

pub mod prelude {
    //! Convenience imports for preprocessed pattern scanning.
    //!
    //! This prelude exposes the reusable scanner and overlapping match iterator while leaving
    //! vector dispatch and candidate planning private.

    pub use super::{Matches, Scanner};
}

impl Iterator for Matches<'_, '_, '_> {
    type Item = usize;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        let Self {
            scanner,
            haystack,
            next_offset,
        } = self;
        let result = scanner.find_from(haystack, *next_offset);

        if let Some(target_match) = result {
            *next_offset = target_match.saturating_add(1);
        }

        result
    }
}

#[cfg(test)]
mod tests {
    //! Regression coverage for every search-plan family and overlapping iteration.

    use super::*;
    use crate::PatternBuf;

    /// Parse a static test pattern without unwrap-family shortcuts.
    fn parse_test(target_source: &str) -> PatternBuf {
        PatternBuf::parse(target_source).expect("test pattern should parse")
    }

    #[test]
    fn literal_and_anchor_plans_find_expected_offsets() {
        let literal = parse_test("DE AD BE EF");
        let anchored = parse_test("?? DE AD ??");
        let literal_haystack = [0, 0xde, 0xad, 0xbe, 0xef, 1];
        let anchored_haystack = [0, 1, 2, 3, 4, 5, 0x00, 0xde, 0xad, 2];

        assert_eq!(
            Scanner::new(literal.as_pattern()).find(&literal_haystack),
            Some(1)
        );
        assert_eq!(
            Scanner::new(anchored.as_pattern()).find(&anchored_haystack),
            Some(6)
        );
    }

    #[test]
    fn masked_probe_plan_finds_nibble_pattern() {
        let pattern = parse_test("4? ?? ?F");
        let haystack = [0x41, 0xaa, 0xbf, 0x52, 0x00, 0x0f];

        assert_eq!(Scanner::new(pattern.as_pattern()).find(&haystack), Some(0));
    }

    #[test]
    fn wildcard_plan_and_iterator_preserve_overlap() {
        let wildcard = parse_test("[2]");
        let literal = parse_test("41 41");
        let wildcard_scanner = Scanner::new(wildcard.as_pattern());
        let literal_scanner = Scanner::new(literal.as_pattern());

        assert_eq!(wildcard_scanner.find(&[1, 2, 3]), Some(0));
        assert_eq!(
            literal_scanner.find_iter(b"AAA").collect::<Vec<_>>(),
            vec![0, 1]
        );
    }
}

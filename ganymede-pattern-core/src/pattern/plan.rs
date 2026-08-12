//! Candidate-discovery planning for validated fixed-width patterns.
//!
//! Planning is const-evaluated from bytes and masks. It chooses exact substring search when
//! possible and otherwise retains selective masked probes for vector candidate filtering.

use super::Probe;

/// Minimum exact-byte run that is worth using as a substring-search anchor.
const MINIMUM_ANCHOR_BYTES: usize = 2;

/// Precomputed strategy used to discover candidate pattern starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// NOTE(invariant): Every stored range and probe was derived from the same validated byte and mask slices retained by `Pattern`.
pub enum SearchPlan {
    /// Every pattern bit is constrained and the whole pattern is a substring needle.
    Literal,

    /// A contiguous run of exact bytes is used as a substring-search anchor.
    Anchor {
        /// Offset of the exact run from the pattern start.
        offset: usize,

        /// Number of exact bytes in the run.
        length: usize,
    },

    /// One or two masked positions are searched in parallel before complete verification.
    Probes {
        /// Most selective available masked position.
        first: Probe,

        /// Second masked position when the pattern constrains another byte.
        second: Option<Probe>,
    },

    /// No bits are constrained and every in-bounds position matches.
    Wildcard,
}

impl SearchPlan {
    /// Derive one immutable search strategy from equal-length pattern byte and mask slices.
    #[inline]
    pub const fn compile(target_bytes: &[u8], target_masks: &[u8]) -> Self {
        let mut index = 0;
        let mut exact_count = 0;
        let mut constrained_count = 0;
        let mut current_start = 0;
        let mut current_length = 0;
        let mut best_start = 0;
        let mut best_length = 0;

        while index < target_masks.len() {
            let mask = target_masks[index];
            let is_exact = mask == u8::MAX;
            let is_constrained = mask != 0;

            if is_exact {
                exact_count += 1;

                let is_first_in_run = current_length == 0;
                if is_first_in_run {
                    current_start = index;
                }

                current_length += 1;

                let is_longest_run = current_length > best_length;
                if is_longest_run {
                    best_start = current_start;
                    best_length = current_length;
                }
            } else {
                current_length = 0;
            }

            if is_constrained {
                constrained_count += 1;
            }

            index += 1;
        }

        let literal = exact_count == target_masks.len();
        let anchor = best_length >= MINIMUM_ANCHOR_BYTES;

        match (literal, anchor, constrained_count) {
            (true, _, _) => Self::Literal,
            (false, true, _) => Self::Anchor {
                offset: best_start,
                length: best_length,
            },
            (false, false, 0) => Self::Wildcard,
            (false, false, _) => {
                let (first, second) = Self::select_probes(target_bytes, target_masks);

                Self::Probes { first, second }
            }
        }
    }

    /// Select the most constrained byte and a distant secondary byte when available.
    const fn select_probes(target_bytes: &[u8], target_masks: &[u8]) -> (Probe, Option<Probe>) {
        let mut index = 0;
        let mut first_offset = 0;
        let mut first_bits = 0;

        while index < target_masks.len() {
            let bits = target_masks[index].count_ones();
            let is_more_selective = bits > first_bits;

            if is_more_selective {
                first_offset = index;
                first_bits = bits;
            }

            index += 1;
        }

        let first_mask = target_masks[first_offset];
        let first = Probe {
            offset: first_offset,
            value: target_bytes[first_offset] & first_mask,
            mask: first_mask,
        };

        index = 0;
        let mut second_offset = 0;
        let mut second_score = 0;
        let mut second_present = false;

        while index < target_masks.len() {
            let mask = target_masks[index];
            let bits = mask.count_ones() as usize;
            let is_different_position = index != first_offset;
            let is_constrained = bits != 0;
            let distance = index.abs_diff(first_offset);
            let score = bits * target_masks.len() + distance;
            let is_better_secondary = score > second_score;

            if is_different_position && is_constrained && is_better_secondary {
                second_offset = index;
                second_score = score;
                second_present = true;
            }

            index += 1;
        }

        let second = if second_present {
            let mask = target_masks[second_offset];
            let probe = Probe {
                offset: second_offset,
                value: target_bytes[second_offset] & mask,
                mask,
            };

            Some(probe)
        } else {
            None
        };

        (first, second)
    }
}

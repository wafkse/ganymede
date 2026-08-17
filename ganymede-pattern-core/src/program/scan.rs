//! Pelite-style interpreter and candidate search for flat executable patterns.
//!
//! Execution uses a program counter over one borrowed atom stream. Recursive execution is confined
//! to control atoms that require backtracking or cursor restoration. The interpreter keeps no heap
//! owned branch stack. Candidate ranges constrain only match starts while followed references may
//! inspect any address represented by the supplied byte image.

use core::ops::Range;

use memchr::{memchr, memmem};

use super::{Atom, PointerWidth, Program};

/// Maximum exact prefix bytes retained on the stack for candidate filtering.
const PREFIX_BYTES: usize = 16;

/// One executable branch state.
#[derive(Debug, Clone, Copy)]
// NOTE(invariant): `pc` is either within `program.atoms()` or one checked position past it, and `cursor` is converted to a byte-image access only through checked helpers.
struct Exec<'program> {
    /// Validated executable program borrowed by this branch.
    program: Program<'program>,

    /// Current byte-image cursor.
    cursor: usize,

    /// Next atom program counter.
    pc: usize,
}

/// Reusable scanner for one flat executable pattern.
#[derive(Debug, Clone, Copy)]
// NOTE(invariant): `program` retains a nonempty atom stream, `pointer_width` fixes target pointer decoding, and `base` is applied through checked arithmetic before offsets become virtual capture addresses.
pub struct Scanner<'program> {
    /// Executable pattern interpreted at candidate starts.
    program: Program<'program>,

    /// Width used by absolute pointer operations and zero-width push or skip atoms.
    pointer_width: PointerWidth,

    /// Virtual address corresponding to byte-image offset zero.
    base: u64,
}

impl<'program> Scanner<'program> {
    /// Prepare one executable pattern with a zero virtual base.
    #[inline]
    #[must_use]
    pub const fn new(
        target_program: Program<'program>,
        target_pointer_width: PointerWidth,
    ) -> Self {
        Self::with_base(target_program, target_pointer_width, 0)
    }

    /// Prepare one executable pattern with an explicit virtual base address.
    #[inline]
    #[must_use]
    pub const fn with_base(
        target_program: Program<'program>,
        target_pointer_width: PointerWidth,
        target_base: u64,
    ) -> Self {
        Self {
            program: target_program,
            pointer_width: target_pointer_width,
            base: target_base,
        }
    }

    /// Return the capture-array width required by this executable program.
    #[inline]
    #[must_use]
    pub const fn save_len(&self) -> usize {
        let Self { program, .. } = self;

        program.save_len()
    }

    /// Return the executable program interpreted by this scanner.
    #[inline]
    #[must_use]
    pub const fn program(&self) -> Program<'program> {
        let Self { program, .. } = self;

        *program
    }

    /// Execute the pattern at one exact byte-image offset.
    ///
    /// Out-of-bounds capture stores are ignored. Failed branches may leave temporary values in the
    /// supplied save array, matching Pelite's interpreter contract. Callers that need transactional
    /// captures should execute with temporary storage and copy it only after success.
    #[inline]
    pub fn exec(
        &self,
        target_haystack: &[u8],
        target_start: usize,
        target_saves: &mut [u64],
    ) -> bool {
        if target_start > target_haystack.len() {
            return false;
        }

        let Self { program, .. } = self;
        let mut target_exec = Exec {
            program: *program,
            cursor: target_start,
            pc: 0,
        };

        self.run(target_haystack, &mut target_exec, target_saves)
    }

    /// Find the earliest matching candidate start.
    #[inline]
    #[must_use]
    pub fn find(&self, target_haystack: &[u8]) -> Option<usize> {
        let mut ignored = [];

        self.find_from(target_haystack, 0, target_haystack.len(), &mut ignored)
    }

    /// Find the earliest match and retain captures available in the supplied save slice.
    ///
    /// Failed candidate executions may leave temporary values in `target_saves` before a later
    /// candidate succeeds or the search is exhausted.
    #[inline]
    pub fn find_with(&self, target_haystack: &[u8], target_saves: &mut [u64]) -> Option<usize> {
        self.find_from(target_haystack, 0, target_haystack.len(), target_saves)
    }

    /// Determine whether exactly one candidate start matches.
    ///
    /// The second uniqueness probe uses an empty save slice so first-match captures remain intact.
    #[inline]
    pub fn finds(&self, target_haystack: &[u8], target_saves: &mut [u64]) -> bool {
        let Some(target_first) = self.find_with(target_haystack, target_saves) else {
            return false;
        };
        let mut ignored = [];

        self.find_from(
            target_haystack,
            target_first.saturating_add(1),
            target_haystack.len(),
            &mut ignored,
        )
        .is_none()
    }

    /// Find the earliest matching candidate start inside one explicit range.
    ///
    /// The range limits only candidate starts. Successful execution may consume bytes or follow
    /// references outside that range while remaining inside `target_haystack`.
    #[inline]
    #[must_use]
    pub fn find_in(&self, target_haystack: &[u8], target_range: Range<usize>) -> Option<usize> {
        let mut ignored = [];

        self.find_from(
            target_haystack,
            target_range.start,
            target_range.end.min(target_haystack.len()),
            &mut ignored,
        )
    }

    /// Find the earliest ranged match and retain supplied capture slots.
    #[inline]
    pub fn find_with_in(
        &self,
        target_haystack: &[u8],
        target_range: Range<usize>,
        target_saves: &mut [u64],
    ) -> Option<usize> {
        self.find_from(
            target_haystack,
            target_range.start,
            target_range.end.min(target_haystack.len()),
            target_saves,
        )
    }

    /// Determine whether exactly one candidate start inside one explicit range matches.
    #[inline]
    pub fn finds_in(
        &self,
        target_haystack: &[u8],
        target_range: Range<usize>,
        target_saves: &mut [u64],
    ) -> bool {
        let target_end = target_range.end.min(target_haystack.len());
        let Some(target_first) = self.find_from(
            target_haystack,
            target_range.start,
            target_end,
            target_saves,
        ) else {
            return false;
        };
        let mut ignored = [];

        self.find_from(
            target_haystack,
            target_first.saturating_add(1),
            target_end,
            &mut ignored,
        )
        .is_none()
    }

    /// Iterate matching candidate starts in ascending order while preserving overlap.
    #[inline]
    #[must_use]
    pub const fn matches<'scanner, 'haystack>(
        &'scanner self,
        target_haystack: &'haystack [u8],
    ) -> Matches<'scanner, 'haystack, 'program> {
        Matches {
            scanner: self,
            haystack: target_haystack,
            next_offset: 0,
            end_offset: target_haystack.len(),
        }
    }

    /// Iterate matching candidate starts inside one explicit range.
    #[inline]
    #[must_use]
    pub fn matches_in<'scanner, 'haystack>(
        &'scanner self,
        target_haystack: &'haystack [u8],
        target_range: Range<usize>,
    ) -> Matches<'scanner, 'haystack, 'program> {
        let end_offset = target_range.end.min(target_haystack.len());

        Matches {
            scanner: self,
            haystack: target_haystack,
            next_offset: target_range.start,
            end_offset,
        }
    }

    /// Compatibility spelling matching the fixed-width scanner iterator.
    #[inline]
    #[must_use]
    pub const fn find_iter<'scanner, 'haystack>(
        &'scanner self,
        target_haystack: &'haystack [u8],
    ) -> Matches<'scanner, 'haystack, 'program> {
        self.matches(target_haystack)
    }

    /// Search one candidate-start interval using an exact leading prefix when available.
    fn find_from(
        &self,
        target_haystack: &[u8],
        target_start: usize,
        target_end: usize,
        target_saves: &mut [u64],
    ) -> Option<usize> {
        if target_start >= target_end {
            return None;
        }

        let mut prefix = [0u8; PREFIX_BYTES];
        let prefix_len = self.prefix(&mut prefix);

        match prefix_len {
            0 => self.find_bruteforce(target_haystack, target_start, target_end, target_saves),
            1 => self.find_byte(
                target_haystack,
                target_start,
                target_end,
                prefix[0],
                target_saves,
            ),
            target_len => self.find_prefix(
                target_haystack,
                target_start,
                target_end,
                &prefix[..target_len],
                target_saves,
            ),
        }
    }

    /// Extract the deterministic exact-byte prefix used only for candidate filtering.
    fn prefix(&self, target_prefix: &mut [u8; PREFIX_BYTES]) -> usize {
        let Self { program, .. } = self;
        let mut length = 0usize;

        for target_atom in program.atoms() {
            match *target_atom {
                Atom::Byte(target_byte) if length < target_prefix.len() => {
                    target_prefix[length] = target_byte;
                    length += 1;
                }
                Atom::Save(..) | Atom::Aligned(..) | Atom::Nop => {}
                _ => break,
            }
        }

        length
    }

    /// Brute-force candidate starts when no exact leading byte is available.
    fn find_bruteforce(
        &self,
        target_haystack: &[u8],
        target_start: usize,
        target_end: usize,
        target_saves: &mut [u64],
    ) -> Option<usize> {
        (target_start..target_end)
            .find(|&target_candidate| self.exec(target_haystack, target_candidate, target_saves))
    }

    /// Filter candidate starts through one leading exact byte.
    fn find_byte(
        &self,
        target_haystack: &[u8],
        target_start: usize,
        target_end: usize,
        target_byte: u8,
        target_saves: &mut [u64],
    ) -> Option<usize> {
        let mut next = target_start;

        while next < target_end {
            let target_slice = target_haystack.get(next..target_end)?;
            let target_relative = memchr(target_byte, target_slice)?;
            let target_candidate = next.checked_add(target_relative)?;

            if self.exec(target_haystack, target_candidate, target_saves) {
                return Some(target_candidate);
            }

            next = target_candidate.saturating_add(1);
        }

        None
    }

    /// Filter candidate starts through a multi-byte exact prefix.
    fn find_prefix(
        &self,
        target_haystack: &[u8],
        target_start: usize,
        target_end: usize,
        target_prefix: &[u8],
        target_saves: &mut [u64],
    ) -> Option<usize> {
        let extension = target_prefix.len().saturating_sub(1);
        let search_end = target_end
            .saturating_add(extension)
            .min(target_haystack.len());
        let mut next = target_start;

        while next < target_end {
            let target_slice = target_haystack.get(next..search_end)?;
            let target_relative = memmem::find(target_slice, target_prefix)?;
            let target_candidate = next.checked_add(target_relative)?;

            if target_candidate >= target_end {
                return None;
            }

            if self.exec(target_haystack, target_candidate, target_saves) {
                return Some(target_candidate);
            }

            next = target_candidate.saturating_add(1);
        }

        None
    }

    /// Execute one branch until success or mismatch.
    fn run(
        &self,
        target_haystack: &[u8],
        target_exec: &mut Exec<'program>,
        target_saves: &mut [u64],
    ) -> bool {
        let mut mask = u8::MAX;

        loop {
            let Some(target_atom) = Self::next(target_exec) else {
                return true;
            };

            let valid = match target_atom {
                Atom::Byte(..) | Atom::Fuzzy(..) => {
                    Self::match_byte(target_haystack, target_exec, target_atom, &mut mask)
                }
                Atom::Save(..)
                | Atom::Check(..)
                | Atom::Aligned(..)
                | Atom::ReadI8(..)
                | Atom::ReadU8(..)
                | Atom::ReadI16(..)
                | Atom::ReadU16(..)
                | Atom::ReadI32(..)
                | Atom::ReadU32(..)
                | Atom::Zero(..) => {
                    self.capture(target_haystack, target_exec, target_saves, target_atom)
                }
                Atom::Push(target_skip) => {
                    let valid = self.push(target_haystack, target_exec, target_saves, target_skip);
                    mask = u8::MAX;

                    valid
                }
                Atom::Pop => return true,
                Atom::Skip(..) | Atom::Back(..) => {
                    self.move_cursor(target_haystack.len(), target_exec, target_atom)
                }
                Atom::Many(target_limit) => {
                    return self.many(target_haystack, target_exec, target_saves, target_limit);
                }
                Atom::Jump1 | Atom::Jump4 | Atom::Pointer | Atom::Pir(..) => {
                    self.follow(target_haystack, target_exec, target_saves, target_atom)
                }
                Atom::Case(target_next) => {
                    self.case(target_haystack, target_exec, target_saves, target_next)
                }
                Atom::Break(target_next) => return Self::break_branch(target_exec, target_next),
                Atom::Nop => true,
            };

            if !valid {
                return false;
            }
        }
    }

    /// Apply one exact or fuzzy byte operation.
    fn match_byte(
        target_haystack: &[u8],
        target_exec: &mut Exec<'program>,
        target_atom: Atom,
        target_mask: &mut u8,
    ) -> bool {
        match target_atom {
            Atom::Byte(target_pattern) => {
                let Exec { cursor, .. } = target_exec;
                let Some(&target_byte) = target_haystack.get(*cursor) else {
                    return false;
                };

                if target_byte & *target_mask != target_pattern & *target_mask {
                    return false;
                }

                *target_mask = u8::MAX;
                let Some(target_cursor) = cursor.checked_add(1) else {
                    return false;
                };
                *cursor = target_cursor;

                true
            }
            Atom::Fuzzy(target_next_mask) => {
                *target_mask = target_next_mask;

                true
            }
            _ => false,
        }
    }

    /// Execute one followed subpattern and restore its caller cursor.
    fn push(
        &self,
        target_haystack: &[u8],
        target_exec: &mut Exec<'program>,
        target_saves: &mut [u64],
        target_skip: usize,
    ) -> bool {
        let cursor = {
            let Exec { cursor, .. } = target_exec;

            *cursor
        };
        let target_skip = self.movement(target_skip);
        let Some(target_resume) = cursor.checked_add(target_skip) else {
            return false;
        };
        let mut target_nested = *target_exec;

        if !self.run(target_haystack, &mut target_nested, target_saves) {
            return false;
        }

        let Exec { pc, cursor, .. } = target_exec;
        let Exec { pc: nested_pc, .. } = target_nested;
        *pc = nested_pc;
        *cursor = target_resume;

        true
    }

    /// Apply one fixed forward or backward cursor movement.
    const fn move_cursor(
        &self,
        target_length: usize,
        target_exec: &mut Exec<'program>,
        target_atom: Atom,
    ) -> bool {
        let Exec { cursor, .. } = target_exec;
        let target_cursor = match target_atom {
            Atom::Skip(target_skip) => {
                let target_skip = self.movement(target_skip);

                cursor.checked_add(target_skip)
            }
            Atom::Back(target_back) => {
                let target_back = self.movement(target_back);

                cursor.checked_sub(target_back)
            }
            _ => None,
        };
        let Some(target_cursor) = target_cursor else {
            return false;
        };

        if target_cursor > target_length {
            return false;
        }

        *cursor = target_cursor;

        true
    }

    /// Follow one relative, absolute, or saved-base reference.
    fn follow(
        &self,
        target_haystack: &[u8],
        target_exec: &mut Exec<'program>,
        target_saves: &[u64],
        target_atom: Atom,
    ) -> bool {
        let Exec { cursor, .. } = target_exec;
        let target_cursor = match target_atom {
            Atom::Jump1 => target_haystack.get(*cursor).and_then(|target_byte| {
                let target_displacement = i64::from(target_byte.cast_signed());
                let target_resume = cursor.checked_add(1)?;

                Self::relative(target_resume, target_displacement)
            }),
            Atom::Jump4 => {
                Self::read_i32(target_haystack, *cursor).and_then(|target_displacement| {
                    let target_resume = cursor.checked_add(4)?;

                    Self::relative(target_resume, target_displacement)
                })
            }
            Atom::Pointer => self
                .read_pointer(target_haystack, *cursor)
                .and_then(|target_pointer| self.offset(target_pointer, target_haystack.len())),
            Atom::Pir(target_slot) => {
                let target_displacement = Self::read_i32(target_haystack, *cursor);
                let target_current = self.absolute(*cursor);

                target_displacement
                    .zip(target_current)
                    .and_then(|(target_displacement, target_current)| {
                        let target_anchor = target_saves
                            .get(usize::from(target_slot))
                            .copied()
                            .unwrap_or(target_current);

                        Self::relative_u64(target_anchor, target_displacement)
                    })
                    .and_then(|target_absolute| self.offset(target_absolute, target_haystack.len()))
            }
            _ => None,
        };
        let Some(target_cursor) = target_cursor else {
            return false;
        };

        if target_cursor > target_haystack.len() {
            return false;
        }

        *cursor = target_cursor;

        true
    }

    /// Apply one capture, equality, alignment, or integer-read operation.
    fn capture(
        &self,
        target_haystack: &[u8],
        target_exec: &mut Exec<'program>,
        target_saves: &mut [u64],
        target_atom: Atom,
    ) -> bool {
        let Exec { cursor, .. } = target_exec;

        match target_atom {
            Atom::Save(target_slot) => {
                let Some(target_value) = self.absolute(*cursor) else {
                    return false;
                };
                Self::write(target_saves, target_slot, target_value);
            }
            Atom::Check(target_slot) => {
                if let Some(target_saved) = target_saves.get(usize::from(target_slot)) {
                    let Some(target_current) = self.absolute(*cursor) else {
                        return false;
                    };

                    if *target_saved != target_current {
                        return false;
                    }
                }
            }
            Atom::Aligned(target_exponent) => {
                let Some(target_alignment) = 1u64.checked_shl(u32::from(target_exponent)) else {
                    return false;
                };
                let Some(target_current) = self.absolute(*cursor) else {
                    return false;
                };

                if target_current % target_alignment != 0 {
                    return false;
                }
            }
            Atom::ReadI8(target_slot) => {
                let Some(&target_byte) = target_haystack.get(*cursor) else {
                    return false;
                };
                let target_value = i64::from(target_byte.cast_signed()).cast_unsigned();
                Self::write(target_saves, target_slot, target_value);

                let Some(target_cursor) = cursor.checked_add(1) else {
                    return false;
                };
                *cursor = target_cursor;
            }
            Atom::ReadU8(target_slot) => {
                let Some(&target_byte) = target_haystack.get(*cursor) else {
                    return false;
                };
                Self::write(target_saves, target_slot, u64::from(target_byte));

                let Some(target_cursor) = cursor.checked_add(1) else {
                    return false;
                };
                *cursor = target_cursor;
            }
            Atom::ReadI16(target_slot) => {
                let Some(target_value) = Self::read_i16(target_haystack, *cursor) else {
                    return false;
                };
                Self::write(target_saves, target_slot, target_value.cast_unsigned());

                let Some(target_cursor) = cursor.checked_add(2) else {
                    return false;
                };
                *cursor = target_cursor;
            }
            Atom::ReadU16(target_slot) => {
                let Some(target_value) = Self::read_u16(target_haystack, *cursor) else {
                    return false;
                };
                Self::write(target_saves, target_slot, u64::from(target_value));

                let Some(target_cursor) = cursor.checked_add(2) else {
                    return false;
                };
                *cursor = target_cursor;
            }
            Atom::ReadI32(target_slot) => {
                let Some(target_value) = Self::read_i32(target_haystack, *cursor) else {
                    return false;
                };
                Self::write(target_saves, target_slot, target_value.cast_unsigned());

                let Some(target_cursor) = cursor.checked_add(4) else {
                    return false;
                };
                *cursor = target_cursor;
            }
            Atom::ReadU32(target_slot) => {
                let Some(target_value) = Self::read_u32(target_haystack, *cursor) else {
                    return false;
                };
                Self::write(target_saves, target_slot, u64::from(target_value));

                let Some(target_cursor) = cursor.checked_add(4) else {
                    return false;
                };
                *cursor = target_cursor;
            }
            Atom::Zero(target_slot) => Self::write(target_saves, target_slot, 0),
            _ => return false,
        }

        true
    }

    /// Execute or skip one alternative branch.
    fn case(
        &self,
        target_haystack: &[u8],
        target_exec: &mut Exec<'program>,
        target_saves: &mut [u64],
        target_next: usize,
    ) -> bool {
        let (program, cursor, pc) = {
            let Exec {
                program,
                cursor,
                pc,
            } = target_exec;

            (*program, *cursor, *pc)
        };
        let mut target_branch = *target_exec;

        if self.run(target_haystack, &mut target_branch, target_saves) {
            *target_exec = target_branch;

            return true;
        }

        let Some(target_next_pc) = pc.checked_add(target_next) else {
            return false;
        };

        if target_next_pc > program.atoms().len() {
            return false;
        }

        let Exec {
            cursor: current,
            pc,
            ..
        } = target_exec;
        *pc = target_next_pc;
        *current = cursor;

        true
    }

    /// Finish the current alternative and advance past its sibling branches.
    const fn break_branch(target_exec: &mut Exec<'program>, target_next: usize) -> bool {
        let Exec { program, pc, .. } = target_exec;
        let Some(target_next_pc) = pc.checked_add(target_next) else {
            return false;
        };

        if target_next_pc > program.atoms().len() {
            return false;
        }

        *pc = target_next_pc;

        true
    }

    /// Retry the remaining program at increasing cursor offsets.
    fn many(
        &self,
        target_haystack: &[u8],
        target_exec: &mut Exec<'program>,
        target_saves: &mut [u64],
        target_limit: usize,
    ) -> bool {
        let available = target_haystack.len().saturating_sub(target_exec.cursor);
        let extent = if target_limit == 0 {
            available
        } else {
            target_limit.min(available)
        };

        for target_skip in 0..extent {
            let Some(target_cursor) = target_exec.cursor.checked_add(target_skip) else {
                return false;
            };
            let mut target_branch = *target_exec;
            target_branch.cursor = target_cursor;

            if self.run(target_haystack, &mut target_branch, target_saves) {
                *target_exec = target_branch;

                return true;
            }
        }

        false
    }

    /// Fetch and advance one atom from the current program counter.
    #[inline]
    fn next(target_exec: &mut Exec<'program>) -> Option<Atom> {
        let Exec { program, pc, .. } = target_exec;
        let target_atom = program.atoms().get(*pc).copied()?;
        *pc += 1;

        Some(target_atom)
    }

    /// Resolve zero movement to target pointer width, matching Pelite push and skip semantics.
    #[inline]
    const fn movement(&self, target_movement: usize) -> usize {
        let Self { pointer_width, .. } = self;

        if target_movement == 0 {
            pointer_width.bytes()
        } else {
            target_movement
        }
    }

    /// Convert one byte-image offset into its checked virtual address.
    #[inline]
    fn absolute(&self, target_offset: usize) -> Option<u64> {
        let Self { base, .. } = self;
        let target_offset = u64::try_from(target_offset).ok()?;

        base.checked_add(target_offset)
    }

    /// Convert one virtual address into a checked byte-image offset.
    #[inline]
    fn offset(&self, target_address: u64, target_length: usize) -> Option<usize> {
        let Self { base, .. } = self;
        let target_offset = target_address.checked_sub(*base)?;
        let target_offset = usize::try_from(target_offset).ok()?;

        (target_offset <= target_length).then_some(target_offset)
    }

    /// Decode one target-width little-endian absolute pointer.
    fn read_pointer(&self, target_haystack: &[u8], target_cursor: usize) -> Option<u64> {
        let Self { pointer_width, .. } = self;
        let target_end = target_cursor.checked_add(pointer_width.bytes())?;
        let target_bytes = target_haystack.get(target_cursor..target_end)?;

        match pointer_width {
            PointerWidth::U32 => Some(u64::from(u32::from_le_bytes(target_bytes.try_into().ok()?))),
            PointerWidth::U64 => Some(u64::from_le_bytes(target_bytes.try_into().ok()?)),
        }
    }

    /// Add one signed displacement to a byte-image offset.
    #[inline]
    fn relative(target_base: usize, target_displacement: i64) -> Option<usize> {
        if target_displacement >= 0 {
            target_base.checked_add(usize::try_from(target_displacement).ok()?)
        } else {
            target_base.checked_sub(usize::try_from(target_displacement.unsigned_abs()).ok()?)
        }
    }

    /// Add one signed displacement to a virtual address.
    #[inline]
    fn relative_u64(target_base: u64, target_displacement: i64) -> Option<u64> {
        if target_displacement >= 0 {
            target_base.checked_add(u64::try_from(target_displacement).ok()?)
        } else {
            target_base.checked_sub(target_displacement.unsigned_abs())
        }
    }

    /// Write one capture slot when the caller supplied it.
    #[inline]
    fn write(target_saves: &mut [u64], target_slot: u8, target_value: u64) {
        if let Some(target_save) = target_saves.get_mut(usize::from(target_slot)) {
            *target_save = target_value;
        }
    }

    /// Decode one signed little-endian word.
    #[inline]
    fn read_i16(target_haystack: &[u8], target_cursor: usize) -> Option<i64> {
        let target_end = target_cursor.checked_add(2)?;
        let target_bytes = target_haystack.get(target_cursor..target_end)?;

        Some(i64::from(i16::from_le_bytes(target_bytes.try_into().ok()?)))
    }

    /// Decode one unsigned little-endian word.
    #[inline]
    fn read_u16(target_haystack: &[u8], target_cursor: usize) -> Option<u16> {
        let target_end = target_cursor.checked_add(2)?;
        let target_bytes = target_haystack.get(target_cursor..target_end)?;

        Some(u16::from_le_bytes(target_bytes.try_into().ok()?))
    }

    /// Decode one signed little-endian dword.
    #[inline]
    fn read_i32(target_haystack: &[u8], target_cursor: usize) -> Option<i64> {
        let target_end = target_cursor.checked_add(4)?;
        let target_bytes = target_haystack.get(target_cursor..target_end)?;

        Some(i64::from(i32::from_le_bytes(target_bytes.try_into().ok()?)))
    }

    /// Decode one unsigned little-endian dword.
    #[inline]
    fn read_u32(target_haystack: &[u8], target_cursor: usize) -> Option<u32> {
        let target_end = target_cursor.checked_add(4)?;
        let target_bytes = target_haystack.get(target_cursor..target_end)?;

        Some(u32::from_le_bytes(target_bytes.try_into().ok()?))
    }
}

/// Ordered iterator over executable-pattern match starts.
#[derive(Debug, Clone)]
// NOTE(invariant): `next_offset` is zero or one byte beyond the previously yielded candidate start and `end_offset` is the exclusive candidate boundary.
pub struct Matches<'scanner, 'haystack, 'program> {
    /// Scanner reused by every iterator step.
    scanner: &'scanner Scanner<'program>,

    /// Byte image searched by every iterator step.
    haystack: &'haystack [u8],

    /// Earliest candidate start for the next search.
    next_offset: usize,

    /// Exclusive candidate-start boundary retained from the requested range.
    end_offset: usize,
}

impl<'scanner, 'program> Matches<'scanner, '_, 'program> {
    /// Return the scanner reused by every iteration step.
    #[inline]
    #[must_use]
    pub const fn scanner(&self) -> &'scanner Scanner<'program> {
        let Self { scanner, .. } = self;

        scanner
    }

    /// Return the executable program interpreted by this match iterator.
    #[inline]
    #[must_use]
    pub const fn program(&self) -> Program<'program> {
        let Self { scanner, .. } = self;

        scanner.program()
    }

    /// Return the remaining candidate-start range.
    #[inline]
    #[must_use]
    pub const fn range(&self) -> Range<usize> {
        let Self {
            next_offset,
            end_offset,
            ..
        } = self;

        *next_offset..*end_offset
    }

    /// Find the next match and retain captures available in the supplied save slice.
    ///
    /// Failed candidate executions may leave temporary values in `target_saves`. A successful
    /// result advances the iterator by one byte from the matched candidate start so overlap remains
    /// observable.
    #[inline]
    pub fn next_with(&mut self, target_saves: &mut [u64]) -> Option<usize> {
        let Self {
            scanner,
            haystack,
            next_offset,
            end_offset,
        } = self;
        let target_match = scanner.find_from(haystack, *next_offset, *end_offset, target_saves)?;
        *next_offset = target_match.saturating_add(1);

        Some(target_match)
    }
}

impl Iterator for Matches<'_, '_, '_> {
    type Item = usize;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        let mut ignored = [];

        self.next_with(&mut ignored)
    }
}

#[cfg(test)]
mod tests {
    //! Regression coverage for Pelite cursor control, captures, alternatives, ranges, and uniqueness.

    use super::*;
    use crate::program::ProgramBuf;

    fn scanner(target_source: &str) -> Scanner<'static> {
        let target_program = Box::leak(Box::new(
            ProgramBuf::parse(target_source).expect("test pattern should parse"),
        ));

        Scanner::new(target_program.as_program(), PointerWidth::U64)
    }

    #[test]
    fn pelite_documented_fixed_capture_and_range_examples_execute() {
        let capture = scanner("B9 ' 37 13 00 00");
        let mut capture_saves = [0_u64; 2];
        let ranged = scanner("B8 [16] 50 [13-42] ' FF");
        let mut range_saves = [0_u64; 2];
        let mut ranged_bytes = [0u8; 64];
        ranged_bytes[0] = 0xb8;
        ranged_bytes[17] = 0x50;
        ranged_bytes[41] = 0xff;

        assert!(capture.exec(&[0xb9, 0x37, 0x13, 0, 0], 0, &mut capture_saves));
        assert_eq!(capture_saves[1], 1);
        assert!(ranged.exec(&ranged_bytes, 0, &mut range_saves));
        assert_eq!(range_saves[1], 41);
    }

    #[test]
    fn relative_follow_and_restoring_subpattern_match_pelite_semantics() {
        let short = scanner("31 C0 74 % ' C0");
        let mut short_saves = [0_u64; 2];
        let nested = scanner("E8 $ { ' } 83 F0 5C C3");
        let mut nested_saves = [0_u64; 2];
        let nested_bytes = [0xe8, 10, 0, 0, 0, 0x83, 0xf0, 0x5c, 0xc3, 5, 6, 7, 8, 9, 10];

        assert!(short.exec(
            &[0x31, 0xc0, 0x74, (-3i8).cast_unsigned()],
            0,
            &mut short_saves
        ));
        assert_eq!(short_saves[1], 1);
        assert!(nested.exec(&nested_bytes, 0, &mut nested_saves));
        assert_eq!(nested_saves[1], 15);
    }

    #[test]
    fn alternatives_and_integer_reads_execute_flat_case_control_flow() {
        let alternatives = scanner("83 C0 2A ( 6A ? | 68 ???? ) E8");
        let reads = scanner("E8 i1 A0 u4");
        let mut read_saves = [0_u64; 3];

        assert!(alternatives.exec(&[0x83, 0xc0, 0x2a, 0x6a, 0, 0xe8], 0, &mut []));
        assert!(alternatives.exec(&[0x83, 0xc0, 0x2a, 0x68, 0, 0, 0, 0x10, 0xe8], 0, &mut []));
        assert!(reads.exec(
            &[0xe8, 0xff, 0xa0, 0x78, 0x56, 0x34, 0x12],
            0,
            &mut read_saves
        ));
        assert_eq!(read_saves[1], (-1_i64).cast_unsigned());
        assert_eq!(read_saves[2], 0x1234_5678);
    }

    #[test]
    fn programmatic_back_pir_and_check_atoms_preserve_flat_cursor_semantics() {
        let control_atoms = [
            Atom::Save(0),
            Atom::Byte(0x41),
            Atom::Skip(1),
            Atom::Back(1),
            Atom::Byte(0x42),
            Atom::Back(2),
            Atom::Check(0),
        ];
        let control_program =
            Program::from_atoms(&control_atoms).expect("control atom program should be valid");
        let control = Scanner::with_base(control_program, PointerWidth::U64, 0x1000);
        let mut control_saves = [0_u64; 1];
        let pir_atoms = [Atom::Save(0), Atom::Pir(0), Atom::Byte(0x42)];
        let pir_program =
            Program::from_atoms(&pir_atoms).expect("PIR atom program should be valid");
        let pir = Scanner::with_base(pir_program, PointerWidth::U64, 0x2000);
        let mut pir_saves = [0_u64; 1];

        assert!(control.exec(b"AB", 0, &mut control_saves));
        assert_eq!(control_saves[0], 0x1000);
        assert!(pir.exec(&[4, 0, 0, 0, 0x42], 0, &mut pir_saves));
        assert_eq!(pir_saves[0], 0x2000);
    }

    #[test]
    fn followed_pointer_subpattern_uses_target_pointer_width_for_resume() {
        let target_program = Box::leak(Box::new(
            ProgramBuf::parse("* { 42 } 43").expect("pointer subpattern should parse"),
        ));
        let target_scanner =
            Scanner::with_base(target_program.as_program(), PointerWidth::U32, 0x1000);
        let haystack = [0x08, 0x10, 0, 0, 0x43, 0, 0, 0, 0x42];

        assert_eq!(target_scanner.find(&haystack), Some(0));
    }

    #[test]
    fn absolute_pointer_follow_uses_explicit_target_width_and_virtual_base() {
        let target_program = Box::leak(Box::new(
            ProgramBuf::parse("* 42").expect("pointer pattern should parse"),
        ));
        let target_32 = Scanner::with_base(target_program.as_program(), PointerWidth::U32, 0x1000);
        let target_64 = Scanner::with_base(target_program.as_program(), PointerWidth::U64, 0x1000);
        let haystack = [0x08, 0x10, 0, 0, 0xff, 0xff, 0xff, 0xff, 0x42];

        assert_eq!(target_32.find(&haystack), Some(0));
        assert_eq!(target_64.find(&haystack), None);
    }

    #[test]
    fn fuzzy_nibble_atoms_match_without_changing_exact_prefix_rules() {
        let target_scanner = scanner("4? ?F 42");

        assert_eq!(target_scanner.find(&[0x4a, 0xbf, 0x42]), Some(0));
        assert_eq!(target_scanner.find(&[0x5a, 0xbf, 0x42]), None);
    }

    #[test]
    fn explicit_range_limits_only_candidate_starts() {
        let target_scanner = scanner("E8 $ { 42 } 43");
        let haystack = [0xe8, 2, 0, 0, 0, 0x43, 0, 0x42, 0xe8, 0, 0, 0, 0x43];

        assert_eq!(target_scanner.find_in(&haystack, 0..1), Some(0));
        assert_eq!(target_scanner.find_in(&haystack, 1..8), None);
    }

    #[test]
    fn followed_relative_target_must_remain_inside_the_memory_image() {
        let target_scanner = scanner("%");

        assert_eq!(target_scanner.find(&[0x7f]), None);
        assert_eq!(target_scanner.find(&[0x00]), Some(0));
    }

    #[test]
    fn candidate_prefix_filtering_preserves_match_set() {
        let sources = [
            "41 ?? 42",
            "41 [1-4] 42",
            "41 u1 42",
            "@0 41 42",
            "(41|42)43",
        ];
        let haystacks: &[&[u8]] = &[
            b"",
            b"A",
            b"AB",
            b"AqB",
            b"AqqB",
            b"xAqBy",
            b"ABCABC",
            &[0x41, 0x11, 0x42],
            &[0x42, 0x43],
        ];

        for target_source in sources {
            let target_program = Box::leak(Box::new(
                ProgramBuf::parse(target_source).expect("test pattern should parse"),
            ));
            let target_scanner = Scanner::new(target_program.as_program(), PointerWidth::U64);

            for target_haystack in haystacks {
                let filtered = target_scanner.matches(target_haystack).collect::<Vec<_>>();
                let direct = (0..target_haystack.len())
                    .filter(|&target_start| {
                        target_scanner.exec(target_haystack, target_start, &mut [])
                    })
                    .collect::<Vec<_>>();

                assert_eq!(
                    filtered, direct,
                    "candidate filtering changed matches for {target_source:?} in {target_haystack:?}"
                );
            }
        }
    }

    #[test]
    fn match_iteration_can_retain_captures_for_each_match() {
        let target_scanner = scanner("' 41");
        let mut matches = target_scanner.matches(b"xAxA");
        let mut saves = [0_u64; 2];

        assert_eq!(matches.next_with(&mut saves), Some(1));
        assert_eq!(saves, [1, 1]);
        assert_eq!(matches.next_with(&mut saves), Some(3));
        assert_eq!(saves, [3, 3]);
        assert_eq!(matches.next_with(&mut saves), None);
    }

    #[test]
    fn finds_requires_one_unique_match_without_disturbing_first_captures() {
        let target_scanner = scanner("' 41 42");
        let mut saves = [0_u64; 2];

        assert!(target_scanner.finds(b"xABy", &mut saves));
        assert_eq!(saves[1], 1);
        assert!(!target_scanner.finds(b"ABxxAB", &mut saves));
        assert_eq!(saves[1], 0);
    }
}

//! Checked translation between ELF image addresses and runtime process addresses.
//!
//! Load bias is parameterized by one sealed ELF class. Arithmetic remains in the selected foreign
//! word width until a successfully translated address crosses into Ganymede's process-wide
//! [`ViAddr`] representation.

use core::ops::{Deref, DerefMut};

use catalejo::{
    address::{ViAddr, ViRange},
    ffi,
};
use num_traits::CheckedAdd;

use crate::class::{Class, Elf32, Elf64};

/// Load bias for one selected ELF class.
///
/// The wrapped word is never widened before checked address arithmetic. This keeps ELF32 overflow
/// behavior distinct from ELF64 while sharing the translation algorithm.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
// NOTE(invariant): The retained word has the selected ELF class width and every image-address translation uses checked arithmetic in that width before widening to `ViAddr`.
pub struct LoadBias<ClassType>(
    /// Proven image load bias in the selected ELF word width.
    ClassType::Word,
)
where
    ClassType: Class;

impl<ClassType> LoadBias<ClassType>
where
    ClassType: Class,
{
    /// Wrap a proven load bias without changing its ELF width.
    #[inline]
    #[must_use]
    pub const fn new(target_address: ClassType::Word) -> Self {
        Self(target_address)
    }

    /// Translate one image virtual address into a process virtual address.
    ///
    /// `None` means addition overflowed the selected ELF class before any host-side widening.
    #[inline]
    #[must_use]
    pub fn address(&self, target_virtual_address: ClassType::Word) -> Option<ViAddr> {
        let Self(load_bias) = self;

        load_bias
            .checked_add(&target_virtual_address)
            .map(Into::<ffi::binding::virtual_address_t>::into)
            .map(ViAddr::new)
    }

    /// Translate one image virtual range into a checked process range.
    ///
    /// Both the base translation and extent addition are performed in the selected ELF word width.
    #[inline]
    #[must_use]
    pub fn range(
        &self,
        target_virtual_address: ClassType::Word,
        target_memory_size: ClassType::Word,
    ) -> Option<ViRange> {
        let Self(load_bias) = self;
        let start = load_bias.checked_add(&target_virtual_address)?;
        let end = start.checked_add(&target_memory_size)?;
        let start = ViAddr::new(start.into());
        let end = ViAddr::new(end.into());

        Some(ViRange::new(start, end))
    }
}

impl<ClassType> Deref for LoadBias<ClassType>
where
    ClassType: Class,
{
    type Target = ClassType::Word;

    #[inline]
    fn deref(&self) -> &Self::Target {
        let Self(load_bias) = self;

        load_bias
    }
}

impl<ClassType> DerefMut for LoadBias<ClassType>
where
    ClassType: Class,
{
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        let Self(load_bias) = self;

        load_bias
    }
}

/// ELF32 load bias with checked 32-bit translation semantics.
pub type Elf32LoadBias = LoadBias<Elf32>;

/// ELF64 load bias with checked 64-bit translation semantics.
pub type Elf64LoadBias = LoadBias<Elf64>;

#[cfg(test)]
mod tests {
    //! Regression coverage for class-width overflow before process-address widening.

    use super::*;

    #[test]
    fn elf32_translation_rejects_width_overflow() {
        let bias = Elf32LoadBias::new(u32::MAX - 1);

        assert_eq!(bias.address(1), Some(ViAddr::new(u64::from(u32::MAX))));
        assert_eq!(bias.address(2), None);
    }

    #[test]
    fn elf64_translation_rejects_width_overflow() {
        let bias = Elf64LoadBias::new(u64::MAX - 1);

        assert_eq!(bias.address(1), Some(ViAddr::new(u64::MAX)));
        assert_eq!(bias.address(2), None);
    }
}

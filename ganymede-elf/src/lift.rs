//! ABI-preserving lifting for ELF records that need semantic projection.
//!
//! Complete plain records can be copied directly through Catalejo. This module exists for generated
//! ELF unions whose raw representation must be projected before shared interpretation can consume a
//! stable semantic value.

use catalejo::prelude::{Foreign, Lift};

use crate::{
    binding,
    class::{Class, Elf32, Elf64},
};

/// Failure while lifting an ELF value from foreign memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, fack::prelude::Error)]
pub enum ElfError {
    /// A protected foreign copy or field read faulted.
    #[error("foreign ELF read faulted")]
    Faulted,

    /// A generated union could not be projected to the required value type.
    #[error("generated ELF union has an invalid projection")]
    InvalidUnion,
}

/// Semantic dynamic-table entry with the selected ELF word width retained.
///
/// The signed tag is normalized to `i64` because tags are semantic identifiers rather than target
/// addresses. The dynamic value remains class-sized because it can represent a target address,
/// extent, stride, or other ABI-width datum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// NOTE(invariant): `value` retains the selected ELF class width and `tag` is the sign-preserving interpretation of the matching generated `d_tag` field.
pub struct Dynamic<ClassType>
where
    ClassType: Class,
{
    /// Sign-preserving dynamic-table tag.
    tag: i64,

    /// Raw dynamic value in the selected ELF word width.
    value: ClassType::Word,
}

impl<ClassType> Dynamic<ClassType>
where
    ClassType: Class,
{
    /// Return the semantic dynamic-table tag.
    #[inline]
    #[must_use]
    pub const fn tag(&self) -> i64 {
        let Self { tag, .. } = self;

        *tag
    }

    /// Return the raw class-sized dynamic value.
    #[inline]
    #[must_use]
    pub const fn value(&self) -> ClassType::Word {
        let Self { value, .. } = self;

        *value
    }
}

impl Lift for Dynamic<Elf32> {
    type Value = binding::Elf32_Dyn;
    type Context = ();
    type Error = ElfError;

    #[inline]
    fn construct_with(
        target_handle: Foreign<Self::Value>,
        _target_context: &Self::Context,
    ) -> Result<Self, Self::Error> {
        let tag = target_handle
            .project(binding::Elf32_Dyn::d_tag)
            .read()
            .ok_or(ElfError::Faulted)?;
        let value = target_handle
            .project(binding::Elf32_Dyn::d_un)
            .cast::<binding::Elf32_Word>()
            .ok_or(ElfError::InvalidUnion)?
            .read()
            .ok_or(ElfError::Faulted)?;
        let tag = i64::from(tag);

        Ok(Self { tag, value })
    }
}

impl Lift for Dynamic<Elf64> {
    type Value = binding::Elf64_Dyn;
    type Context = ();
    type Error = ElfError;

    #[inline]
    fn construct_with(
        target_handle: Foreign<Self::Value>,
        _target_context: &Self::Context,
    ) -> Result<Self, Self::Error> {
        let tag = target_handle
            .project(binding::Elf64_Dyn::d_tag)
            .read()
            .ok_or(ElfError::Faulted)?;
        let value = target_handle
            .project(binding::Elf64_Dyn::d_un)
            .cast::<binding::Elf64_Xword>()
            .ok_or(ElfError::InvalidUnion)?
            .read()
            .ok_or(ElfError::Faulted)?;

        Ok(Self { tag, value })
    }
}

/// Semantic ELF32 dynamic-table entry.
pub type Elf32Dynamic = Dynamic<Elf32>;

/// Semantic ELF64 dynamic-table entry.
pub type Elf64Dynamic = Dynamic<Elf64>;

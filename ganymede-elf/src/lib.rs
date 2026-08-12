//! ELF interpretation over format-neutral process memory.
//!
//! This crate owns ELF-specific ABI knowledge, image-class selection, checked runtime address
//! translation, foreign record lifting, and validation of running images. Process access stays
//! below this boundary and runtime-linker protocol interpretation stays above it.
#![deny(clippy::all, clippy::perf, clippy::nursery, clippy::pedantic)]
#![forbid(clippy::unwrap_used, clippy::panic, rustdoc::all)]
#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]

pub mod binding {
    //! Platform ELF ABI declarations used by the interpretation layer.
    //!
    //! This module isolates externally defined names and layouts from authored Rust abstractions.
    //! The declarations remain raw so ABI provenance is visible at every conversion boundary.

    #![allow(
        nonstandard_style,
        missing_docs,
        clippy::pub_underscore_fields,
        clippy::unreadable_literal,
        clippy::use_self,
        reason = "bindgen generated declarations preserve external ELF names, recursive type spelling, and literal values"
    )]

    include!(concat!(env!("OUT_DIR"), "/ganymede-elf.rs"));
}

pub mod class;

pub mod dynamic;

pub mod image;

pub mod lift;

pub mod process;

pub mod symbol;

pub mod prelude {
    //! Convenience imports for ELF interpretation.
    //!
    //! The prelude exposes runtime class proof, compile-time class families, validated process
    //! images, symbol semantics, and bounded dynamic lookup without erasing target-width identity.

    pub use crate::{
        class::{Class, Elf32, Elf64, ElfClass, ElfClassError, ProgramHeader, Word},
        dynamic::{
            DynamicField, DynamicSymbols, DynamicSymbolsError, Elf32DynamicSymbols,
            Elf32DynamicSymbolsError, Elf32SymbolLimits, Elf64DynamicSymbols,
            Elf64DynamicSymbolsError, Elf64SymbolLimits, SymbolLimits,
        },
        image::{Elf32LoadBias, Elf64LoadBias, LoadBias},
        lift::{Dynamic, Elf32Dynamic, Elf64Dynamic, ElfError},
        process::{
            AddressOperation, DynamicSegment, Elf32DynamicSegment, Elf32Observation,
            Elf32ProcessImage, Elf32ProcessImageError, Elf64DynamicSegment, Elf64Observation,
            Elf64ProcessImage, Elf64ProcessImageError, Observation, ProcessImage,
            ProcessImageError,
        },
        symbol::{
            DynamicSymbol, Elf32DynamicSymbol, Elf32Export, Elf32Symbol, Elf32SymbolError,
            Elf32SymbolLocation, Elf64DynamicSymbol, Elf64Export, Elf64Symbol, Elf64SymbolError,
            Elf64SymbolLocation, ElfSymbolBinding, ElfSymbolType, ElfSymbolVisibility, Export,
            Symbol, SymbolError, SymbolLocation,
        },
    };
}

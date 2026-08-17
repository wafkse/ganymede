//! Binary patterns compiled for fixed-width search and executable scanning.
//!
//! This crate owns fixed-width pattern representation, flat executable pattern programs, their
//! syntax, search planning, and byte-slice scanning. Architecture-specific vector selection is delegated to
//! `fearless_simd` so this crate contains no raw SIMD intrinsics or unsafe SIMD dispatch.
#![deny(clippy::all, clippy::perf, clippy::nursery, clippy::pedantic)]
#![forbid(clippy::unwrap_used, clippy::panic, rustdoc::all)]
#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]

pub mod pattern;

pub mod program;

pub use pattern::{Pattern, PatternBuf, PatternError, scan, syntax};
pub use program::scan::{Matches as ProgramMatches, Scanner as ProgramScanner};

pub mod prelude {
    //! Convenience imports for fixed-width and executable binary pattern scanning.
    //!
    //! The prelude exposes both scanner families without exposing internal vector implementation
    //! details.

    pub use crate::{
        Pattern, PatternBuf, PatternError, ProgramMatches, ProgramScanner,
        program::{
            Atom, PointerWidth, Program, ProgramBuf, ProgramError,
            syntax::{ParseError as ProgramParseError, ParseErrorKind as ProgramParseErrorKind},
        },
        scan::{Matches, Scanner},
        syntax::{MaskedByte, ParseError, ParseErrorKind, Parser, Token, parse},
    };
}

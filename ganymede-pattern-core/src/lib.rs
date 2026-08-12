//! Fixed-width binary patterns compiled for high-throughput byte scanning.
//!
//! This crate owns pattern representation, shared syntax, search planning, and byte-slice scanning.
//! Architecture-specific vector selection is delegated to `fearless_simd` so this crate contains no
//! raw SIMD intrinsics or unsafe SIMD dispatch.
#![deny(clippy::all, clippy::perf, clippy::nursery, clippy::pedantic)]
#![forbid(clippy::unwrap_used, clippy::panic, rustdoc::all)]
#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]

pub mod pattern;

pub use pattern::{Pattern, PatternBuf, PatternError, scan, syntax};

pub mod prelude {
    //! Convenience imports for fixed-width binary pattern scanning.
    //!
    //! The prelude exposes the stable pattern, parser, and scanner concepts without exposing
    //! internal search planning or vector implementation details.

    pub use crate::{
        Pattern, PatternBuf, PatternError,
        scan::{Matches, Scanner},
        syntax::{MaskedByte, ParseError, ParseErrorKind, Parser, Token, parse},
    };
}

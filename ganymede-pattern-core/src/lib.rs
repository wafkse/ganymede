//! Unified binary pattern parsing, compilation, and scanning.
//!
//! One Pelite-style language lowers to a flat atom stream. Patterns with fixed-width linear
//! semantics carry a private derived search plan that uses substring search and SIMD verification.
//! Dynamic patterns execute through the same public scanner with explicit target pointer width.
#![deny(clippy::all, clippy::perf, clippy::nursery, clippy::pedantic)]
#![forbid(clippy::unwrap_used, clippy::panic, rustdoc::all)]
#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]

pub mod pattern;

pub mod prelude {
    //! This is the `ganymede-pattern-core` prelude.
    //!
    //! It re-exports the pattern model, parser, and scanner concepts used together by consumers.

    pub use crate::pattern::{
        Atom, Pattern, PatternBuf, PatternError, PointerWidth,
        scan::{Matches, Scanner},
        syntax::{ParseError, ParseErrorKind, parse},
    };
}

//! Public binary-pattern facade combining runtime scanning and compile-time construction.
//!
//! Core parsing, planning, and scanning live in `ganymede-pattern-core`. The procedural macro uses
//! that same core parser, while this crate provides the single downstream dependency and import path.
#![deny(clippy::all, clippy::perf, clippy::nursery, clippy::pedantic)]
#![forbid(clippy::unwrap_used, clippy::panic, rustdoc::all)]
#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]

pub use ganymede_pattern_core::*;

#[doc(hidden)]
pub mod export {
    //! Implementation re-exports used by generated pattern macro expressions.
    //!
    //! Keeping these paths together prevents generated code from depending on the facade's ordinary
    //! public re-export layout. The module remains public because expansion occurs in downstream
    //! crates, but it is not a supported user-facing namespace.

    pub use ganymede_pattern_core::Pattern;
    pub use ganymede_pattern_macro::pattern;
}

pub use export::pattern;

pub mod prelude {
    //! Convenience imports for both runtime and compile-time binary patterns.
    //!
    //! The facade prelude adds [`pattern!`](crate::pattern!) to the core pattern and scanner concepts.

    pub use crate::scan::{Matches, Scanner};
    pub use crate::syntax::{MaskedByte, ParseError, ParseErrorKind, Parser, Token, parse};
    pub use crate::{Pattern, PatternBuf, PatternError, pattern};
}

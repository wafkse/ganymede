//! Public binary-pattern facade combining runtime scanning and compile-time construction.
//!
//! Core parsing, planning, fixed-width search, and flat executable scanning live in
//! `ganymede-pattern-core`. The procedural macros use the matching core parsers, while this crate
//! provides one downstream dependency and import path.
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

    pub use ganymede_pattern_core::{
        Pattern,
        program::{Atom, Program},
    };
    pub use ganymede_pattern_macro::{pattern, program};
}

pub use export::{pattern, program};

pub mod prelude {
    //! Convenience imports for runtime and compile-time binary patterns.
    //!
    //! The facade prelude adds both procedural macros to the core fixed-width and executable pattern
    //! concepts.

    pub use crate::{pattern, program};
    pub use ganymede_pattern_core::prelude::*;
}

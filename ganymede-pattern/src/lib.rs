//! Public facade for unified binary pattern compilation and scanning.
//!
//! One Pelite-style syntax lowers to a flat atom representation in `ganymede-pattern-core`.
//! Fixed-width linear patterns receive a private optimized search projection while dynamic patterns
//! execute through the same scanner and public API.
#![deny(clippy::all, clippy::perf, clippy::nursery, clippy::pedantic)]
#![forbid(clippy::unwrap_used, clippy::panic, rustdoc::all)]
#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]

pub use ganymede_pattern_core::*;

#[doc(hidden)]
pub mod export {
    //! Implementation re-exports used by generated pattern macro expressions.
    //!
    //! Expansion occurs in downstream crates, so these names must remain publicly reachable even
    //! though this namespace is not part of the supported user-facing API.

    pub use ganymede_pattern_core::{Atom, Pattern};
    pub use ganymede_pattern_macro::pattern;
}

pub use export::pattern;

pub mod prelude {
    //! Convenience imports for runtime and compile-time binary pattern scanning.

    pub use crate::pattern;
    pub use ganymede_pattern_core::prelude::*;
}

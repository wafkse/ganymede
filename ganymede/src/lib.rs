//! End-to-end process introspection facade for the Ganymede crate family.
//!
//! Lower-level crates retain ownership of process access, executable formats, runtime-linker
//! protocols, normalized modules, byte text, and pattern scanning. This facade composes those
//! capabilities without moving their representations into a common lowest-level crate.
#![deny(clippy::all, clippy::perf, clippy::nursery, clippy::pedantic)]
#![forbid(clippy::unwrap_used, clippy::panic, rustdoc::all)]
#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]

pub mod loader;

pub mod prelude {
    //! This is the `ganymede` prelude.
    //!
    //! It re-exports end-to-end inspection types while keeping process and linker snapshots distinct.

    pub use crate::loader::{
        CaptureError, Inspection, InspectionError, Loader, Snapshot, UnsupportedLoader,
    };
}

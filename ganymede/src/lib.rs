//! End-to-end process introspection facade for the Ganymede crate family.
//!
//! Lower-level crates retain ownership of process access, executable formats, runtime-linker
//! protocols, normalized modules, byte text, and pattern scanning. This facade composes those
//! capabilities without moving their representations into a common lowest-level crate.
#![deny(clippy::all, clippy::perf, clippy::nursery, clippy::pedantic)]
#![forbid(clippy::unwrap_used, clippy::panic, rustdoc::all)]
#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]

pub use ganymede_elf as elf;
pub use ganymede_linker_gnu as gnu;
pub use ganymede_module as module;
pub use ganymede_process as process;
pub use ganymede_text as text;

pub mod loader;

pub mod prelude {
    //! Convenience imports for end-to-end process and loader inspection.
    //!
    //! The prelude keeps the process snapshot distinct from the runtime-linker snapshot while
    //! exposing the GNU retry policy and normalized module collection used by the facade.

    pub use crate::loader::{
        CaptureError, Inspection, InspectionError, Loader, Snapshot, UnsupportedLoader,
    };
    pub use ganymede_linker_gnu::snapshot::RetryPolicy;
    pub use ganymede_module::{Module, Modules};
    pub use ganymede_process::process::{Process, ProcessId, Snapshot as ProcessSnapshot};
}

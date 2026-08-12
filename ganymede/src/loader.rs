//! Runtime-linker selection and end-to-end loaded-module acquisition.
//!
//! Selection first proves the ELF class and exact interpreter basename. Only the two GNU profiles
//! currently implemented by the workspace are accepted. Unknown ELF interpreters fail before GNU
//! rendezvous acquisition, so backend choice is explicit even while there is only one linker family.

use ganymede_elf::{
    class::{ElfClass, ElfClassError},
    process::{Elf32Observation, Elf64Observation, ProcessImageError},
};
use ganymede_linker_gnu::{snapshot, snapshot32};
use ganymede_module::{Modules, NormalizeError};
use ganymede_process::process::{Process, Snapshot as ProcessSnapshot};
use ganymede_text::BytePath;

/// Supported runtime-linker profile selected from ELF class and interpreter identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Loader {
    /// GNU runtime linker serving an ELF32 i386 process.
    Gnu32,

    /// GNU runtime linker serving an ELF64 x86-64 process.
    Gnu64,
}

impl Loader {
    /// Select a supported runtime-linker profile from exact ELF interpreter identity.
    ///
    /// The full path remains byte-preserving. Selection compares only its final slash-delimited
    /// component against the basename owned by the corresponding GNU backend.
    ///
    /// # Errors
    ///
    /// This returns [`UnsupportedLoader`] when the interpreter does not identify the GNU profile
    /// supported for the supplied ELF class.
    #[inline]
    pub fn select(
        target_class: ElfClass,
        target_interpreter: &BytePath,
    ) -> Result<Self, UnsupportedLoader> {
        let basename = target_interpreter.basename();
        let selected = match target_class {
            ElfClass::Elf32 => {
                let is_gnu = basename == snapshot32::GNU_I386_INTERPRETER_BASENAME;

                is_gnu.then_some(Self::Gnu32)
            }
            ElfClass::Elf64 => {
                let is_gnu = basename == snapshot::GNU_X86_64_INTERPRETER_BASENAME;

                is_gnu.then_some(Self::Gnu64)
            }
        };

        selected.ok_or_else(|| UnsupportedLoader::new(target_class, target_interpreter.clone()))
    }
}

/// Exact unsupported interpreter observation retained by loader selection failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unsupported {class:?} ELF interpreter {interpreter:?}")]
pub struct UnsupportedLoader {
    /// ELF class proven from process metadata.
    class: ElfClass,

    /// Exact interpreter path bytes without lossy text conversion.
    interpreter: BytePath,
}

impl UnsupportedLoader {
    /// Retain one unsupported class and interpreter pair.
    #[inline]
    #[must_use]
    pub const fn new(target_class: ElfClass, target_interpreter: BytePath) -> Self {
        Self {
            class: target_class,
            interpreter: target_interpreter,
        }
    }

    /// Return the ELF class that lacked a supported loader backend.
    #[inline]
    #[must_use]
    pub const fn class(&self) -> ElfClass {
        let Self { class, .. } = self;

        *class
    }

    /// Borrow the exact unsupported interpreter path.
    #[inline]
    #[must_use]
    pub const fn interpreter(&self) -> &BytePath {
        let Self { interpreter, .. } = self;

        interpreter
    }
}

/// Width-preserving coherent runtime-linker snapshot selected for one process.
#[derive(Debug)]
pub enum Snapshot {
    /// Coherent GNU i386 snapshot retaining 32-bit foreign pointer identity.
    Gnu32(snapshot32::ModuleSnapshot),

    /// Coherent GNU x86-64 snapshot retaining 64-bit foreign pointer identity.
    Gnu64(snapshot::ModuleSnapshot),
}

impl Snapshot {
    /// Capture a supported runtime-linker snapshot under the selected architecture defaults.
    ///
    /// # Errors
    ///
    /// This returns [`CaptureError`] when ELF class or image validation fails, the exact interpreter
    /// is unsupported, or the selected GNU backend cannot produce a coherent bounded snapshot.
    #[inline]
    pub fn capture(
        target_process: &Process,
        target_snapshot: &ProcessSnapshot,
    ) -> Result<Self, CaptureError> {
        let class = ElfClass::from_snapshot(target_snapshot)?;
        let limits = match class {
            ElfClass::Elf32 => snapshot::SnapshotLimits::i386(),
            ElfClass::Elf64 => snapshot::SnapshotLimits::amd64(),
        };

        Self::read(target_process, target_snapshot, class, limits)
    }

    /// Capture a supported runtime-linker snapshot under caller-selected finite bounds.
    ///
    /// One policy shape is shared because both GNU backends expose the same bounded resource
    /// categories. Target-width identities remain inside the selected snapshot variant.
    ///
    /// # Errors
    ///
    /// This returns the same failure categories as [`Self::capture`] and reports policy exhaustion
    /// when valid target structures exceed the supplied finite bounds.
    #[inline]
    pub fn bounded(
        target_process: &Process,
        target_snapshot: &ProcessSnapshot,
        target_limits: snapshot::SnapshotLimits,
    ) -> Result<Self, CaptureError> {
        let class = ElfClass::from_snapshot(target_snapshot)?;

        Self::read(target_process, target_snapshot, class, target_limits)
    }

    /// Return the runtime-linker profile represented by this snapshot.
    #[inline]
    #[must_use]
    pub const fn loader(&self) -> Loader {
        match self {
            Self::Gnu32(..) => Loader::Gnu32,
            Self::Gnu64(..) => Loader::Gnu64,
        }
    }

    /// Read one class-specific ELF observation and enter only its validated GNU backend.
    fn read(
        target_process: &Process,
        target_snapshot: &ProcessSnapshot,
        target_class: ElfClass,
        target_limits: snapshot::SnapshotLimits,
    ) -> Result<Self, CaptureError> {
        match target_class {
            ElfClass::Elf32 => {
                let observation = Elf32Observation::read(
                    target_process,
                    target_snapshot,
                    target_limits.phdrs(),
                    target_limits.interpreter(),
                )?;
                Loader::select(target_class, observation.image().interpreter())?;

                snapshot32::ModuleSnapshot::prepared(&observation, target_limits)
                    .map(Self::Gnu32)
                    .map_err(CaptureError::Gnu32)
            }
            ElfClass::Elf64 => {
                let observation = Elf64Observation::read(
                    target_process,
                    target_snapshot,
                    target_limits.phdrs(),
                    target_limits.interpreter(),
                )?;
                Loader::select(target_class, observation.image().interpreter())?;

                snapshot::ModuleSnapshot::prepared(&observation, target_limits)
                    .map(Self::Gnu64)
                    .map_err(CaptureError::Gnu64)
            }
        }
    }

    /// Normalize all modules using the same process snapshot supplied to facade acquisition.
    fn normalize(&self, target_snapshot: &ProcessSnapshot) -> Result<Modules, NormalizeError> {
        match self {
            Self::Gnu32(target_snapshot32) => target_snapshot32.normalize(target_snapshot),
            Self::Gnu64(target_snapshot64) => target_snapshot64.normalize(target_snapshot),
        }
    }
}

/// Complete loader and normalized-module observation for one process snapshot.
#[derive(Debug)]
// NOTE(invariant): `modules` was normalized from `snapshot` against the same caller-supplied process snapshot during construction, so facade users cannot pair these values from unrelated observations.
pub struct Inspection {
    /// Width-preserving runtime-linker snapshot.
    snapshot: Snapshot,

    /// Format-neutral modules normalized from that snapshot.
    modules: Modules,
}

impl Inspection {
    /// Capture loader state and normalize its modules under architecture defaults.
    ///
    /// # Errors
    ///
    /// This returns [`InspectionError`] when loader capture fails or normalized mapping ownership
    /// cannot be proven from the same process snapshot.
    #[inline]
    pub fn capture(
        target_process: &Process,
        target_snapshot: &ProcessSnapshot,
    ) -> Result<Self, InspectionError> {
        let snapshot = Snapshot::capture(target_process, target_snapshot)?;

        Self::finish(snapshot, target_snapshot)
    }

    /// Capture loader state and normalize its modules under caller-selected finite bounds.
    ///
    /// # Errors
    ///
    /// This returns the same failure categories as [`Self::capture`] with the supplied bounds used
    /// for ELF image and GNU graph acquisition.
    #[inline]
    pub fn bounded(
        target_process: &Process,
        target_snapshot: &ProcessSnapshot,
        target_limits: snapshot::SnapshotLimits,
    ) -> Result<Self, InspectionError> {
        let snapshot = Snapshot::bounded(target_process, target_snapshot, target_limits)?;

        Self::finish(snapshot, target_snapshot)
    }

    /// Borrow the width-preserving coherent runtime-linker snapshot.
    #[inline]
    #[must_use]
    pub const fn snapshot(&self) -> &Snapshot {
        let Self { snapshot, .. } = self;

        snapshot
    }

    /// Borrow the normalized module collection derived from this snapshot.
    #[inline]
    #[must_use]
    pub const fn modules(&self) -> &Modules {
        let Self { modules, .. } = self;

        modules
    }

    /// Return the selected runtime-linker profile.
    #[inline]
    #[must_use]
    pub const fn loader(&self) -> Loader {
        let Self { snapshot, .. } = self;

        snapshot.loader()
    }

    /// Bind normalized modules to the exact loader snapshot that produced them.
    fn finish(
        snapshot: Snapshot,
        target_snapshot: &ProcessSnapshot,
    ) -> Result<Self, InspectionError> {
        let modules = snapshot.normalize(target_snapshot)?;

        Ok(Self { snapshot, modules })
    }
}

/// Failure while selecting and capturing one coherent runtime-linker snapshot.
#[derive(Debug, thiserror::Error)]
pub enum CaptureError {
    /// ELF class proof from process auxiliary metadata failed.
    #[error(transparent)]
    Class(#[from] ElfClassError),

    /// Main ELF process-image validation failed.
    #[error(transparent)]
    Image(#[from] ProcessImageError),

    /// No supported runtime-linker backend matches the exact interpreter.
    #[error(transparent)]
    Unsupported(#[from] UnsupportedLoader),

    /// GNU i386 coherent acquisition failed after loader selection.
    #[error("GNU i386 snapshot acquisition failed")]
    Gnu32(#[source] snapshot32::SnapshotError),

    /// GNU x86-64 coherent acquisition failed after loader selection.
    #[error("GNU x86-64 snapshot acquisition failed")]
    Gnu64(#[source] snapshot::SnapshotError),
}

/// Failure while completing end-to-end loader and module inspection.
#[derive(Debug, thiserror::Error)]
pub enum InspectionError {
    /// Runtime-linker selection or coherent capture failed.
    #[error(transparent)]
    Capture(#[from] CaptureError),

    /// Module normalization could not prove unambiguous mapping ownership.
    #[error(transparent)]
    Normalize(#[from] NormalizeError),
}

#[cfg(test)]
mod tests {
    //! Regression coverage for explicit runtime-linker selection.

    use super::*;

    #[test]
    fn selects_gnu_profile_for_each_matching_elf_class() {
        let path32 = BytePath::new(b"/lib/ld-linux.so.2");
        let path64 = BytePath::new(b"/lib64/ld-linux-x86-64.so.2");

        assert_eq!(Loader::select(ElfClass::Elf32, &path32), Ok(Loader::Gnu32));
        assert_eq!(Loader::select(ElfClass::Elf64, &path64), Ok(Loader::Gnu64));
    }

    #[test]
    fn rejects_unknown_and_cross_class_interpreters() {
        let unknown = BytePath::new(b"/lib/ld-musl-x86_64.so.1");
        let gnu64 = BytePath::new(b"/lib64/ld-linux-x86-64.so.2");

        assert!(Loader::select(ElfClass::Elf64, &unknown).is_err());
        assert!(Loader::select(ElfClass::Elf32, &gnu64).is_err());
    }

    #[test]
    fn unsupported_loader_retains_exact_non_utf8_path() {
        let path = BytePath::new(b"/tmp/ld-\xff.so");
        let error = Loader::select(ElfClass::Elf64, &path)
            .expect_err("non-GNU interpreter should be rejected");

        assert_eq!(error.class(), ElfClass::Elf64);
        assert_eq!(&**error.interpreter(), b"/tmp/ld-\xff.so");
    }
}

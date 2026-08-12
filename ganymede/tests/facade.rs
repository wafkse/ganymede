//! Public facade integration coverage.

#[cfg(test)]
mod tests {
    //! Pure loader-selection coverage plus an opt-in live self-process path.

    use catalejo::prelude::Subsystem;
    use ganymede::{
        elf::class::ElfClass,
        prelude::{Inspection, Loader, Process, ProcessId, SnapshotLimits},
        text::BytePath,
    };

    #[test]
    fn prelude_and_subcrate_paths_compose_for_gnu_selection() {
        let interpreter = BytePath::new(b"/lib64/ld-linux-x86-64.so.2");
        let loader = Loader::select(ElfClass::Elf64, &interpreter)
            .expect("known GNU x86-64 interpreter should select the backend");
        let limits = SnapshotLimits::amd64();

        assert_eq!(loader, Loader::Gnu64);
        assert_eq!(limits, ganymede::gnu::snapshot::SnapshotLimits::amd64());
    }

    #[test]
    fn facade_rejects_unimplemented_loader_families() {
        let interpreter = BytePath::new(b"/lib/ld-musl-i386.so.1");
        let error = Loader::select(ElfClass::Elf32, &interpreter)
            .expect_err("unimplemented runtime linker should be rejected explicitly");

        assert_eq!(error.class(), ElfClass::Elf32);
        assert_eq!(&**error.interpreter(), b"/lib/ld-musl-i386.so.1");
    }

    #[test]
    #[ignore = "requires an updated mirilla kernel module and exclusive Catalejo signal initialization"]
    fn self_process_reaches_normalized_modules() {
        // SAFETY: This opt-in test installs no competing SIGBUS, SIGSEGV, or SIGILL handlers. Its
        // ignore contract requires running it in an environment where Catalejo owns initialization.
        unsafe { Subsystem::initialize() }.expect("Catalejo fault subsystem should initialize");

        let process = Process::new(ProcessId(std::process::id()))
            .expect("self process should engage through Mirilla");
        let process_snapshot = process
            .snapshot()
            .expect("self process mapping snapshot should succeed");
        let inspection = Inspection::capture(&process, &process_snapshot)
            .expect("self process should produce a supported coherent loader observation");

        assert!(!inspection.modules().modules().is_empty());
    }
}

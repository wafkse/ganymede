//! Public facade integration coverage.

#[cfg(test)]
mod tests {
    //! Pure loader-selection coverage plus an opt-in live self-process path.

    use ganymede::prelude::{Inspection, Loader};
    use ganymede_elf::class::ElfClass;
    use ganymede_linker_gnu::snapshot::RetryPolicy;
    use ganymede_process::process::{Process, ProcessId};
    use ganymede_text::BytePath;

    #[test]
    fn prelude_and_subcrate_paths_compose_for_gnu_selection() {
        let interpreter = BytePath::new(b"/lib64/ld-linux-x86-64.so.2");
        let loader = Loader::select(ElfClass::Elf64, &interpreter)
            .expect("known GNU x86-64 interpreter should select the backend");
        let retry = RetryPolicy::standard();

        assert_eq!(loader, Loader::Gnu64);
        assert_eq!(retry, RetryPolicy::standard());
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
    #[ignore = "requires a loaded Mirilla kernel module"]
    fn self_process_reaches_normalized_modules() {
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

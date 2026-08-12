//! Facade coverage for runtime and compile-time pattern APIs through one dependency.
#![deny(clippy::all, clippy::perf, clippy::nursery, clippy::pedantic)]
#![forbid(clippy::unwrap_used, clippy::panic, rustdoc::all)]

#[cfg(test)]
mod tests {
    //! Integration coverage for the public facade re-exports.

    use ganymede_pattern::{Pattern, pattern};

    #[test]
    fn facade_reexports_core_and_macro() {
        const PATTERN: Pattern<'static> = pattern!(r#"48 8B ?? 4? [2] "ELF""#);

        assert_eq!(PATTERN.len(), 9);
        assert!(PATTERN.matches(&[0x48, 0x8b, 1, 0x4f, 2, 3, b'E', b'L', b'F']));
    }
}

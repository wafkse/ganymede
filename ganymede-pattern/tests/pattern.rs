//! Facade coverage for the unified runtime and compile-time pattern API.
#![deny(clippy::all, clippy::perf, clippy::nursery, clippy::pedantic)]
#![forbid(clippy::unwrap_used, clippy::panic, rustdoc::all)]

use ganymede_pattern::{Pattern, PatternBuf, PointerWidth, Scanner, pattern};

#[test]
fn macro_and_runtime_parser_emit_identical_unified_patterns() {
    let compiled = pattern!("E8 $ { ' 31 C0 } ( 41 | 42 ) [1-4] 90");
    let runtime = PatternBuf::parse("E8 $ { ' 31 C0 } ( 41 | 42 ) [1-4] 90")
        .expect("runtime pattern should parse");

    assert_eq!(compiled.atoms(), runtime.atoms());
    assert_eq!(compiled.save_len(), runtime.save_len());
}

#[test]
fn fixed_and_dynamic_patterns_use_the_same_scanner_type() {
    const FIXED: Pattern<'static> = pattern!("48 8B ? 4? [2] \"ELF\"");
    const DYNAMIC: Pattern<'static> = pattern!("41 [1-4] 42");
    let fixed = Scanner::new(FIXED, PointerWidth::U64);
    let dynamic = Scanner::new(DYNAMIC, PointerWidth::U64);

    assert_eq!(
        fixed.find(&[0x48, 0x8b, 1, 0x4f, 2, 3, b'E', b'L', b'F']),
        Some(0)
    );
    assert_eq!(dynamic.find(b"xAqqBy"), Some(1));
}

#[test]
fn prelude_exposes_one_pattern_macro_and_scanner() {
    use ganymede_pattern::prelude::{PointerWidth, Scanner, pattern};

    let compiled = pattern!("41 ? 42");
    let scanner = Scanner::new(compiled, PointerWidth::U64);

    assert_eq!(scanner.find(b"xAqBy"), Some(1));
}

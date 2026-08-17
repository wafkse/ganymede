//! Facade coverage for flat executable pattern parsing, scanning, and macro construction.

use ganymede_pattern::{
    program,
    program::{Atom, PointerWidth, ProgramBuf, scan::Scanner},
};

#[test]
fn executable_program_is_available_through_the_facade() {
    let program = ProgramBuf::parse("48 8B [1-4] 90").expect("executable pattern should parse");
    let scanner = Scanner::new(program.as_program(), PointerWidth::U64);

    assert_eq!(scanner.find(&[0x48, 0x8b, 0, 0x90]), Some(0));
    assert!(program.atoms().contains(&Atom::Many(3)));
}

#[test]
fn executable_scanner_aliases_are_available_from_the_facade_prelude() {
    use ganymede_pattern::prelude::{PointerWidth, ProgramBuf, ProgramScanner};

    let program = ProgramBuf::parse("4142").expect("executable pattern should parse");
    let scanner = ProgramScanner::new(program.as_program(), PointerWidth::U64);

    assert_eq!(scanner.find(b"xABy"), Some(1));
}

#[test]
fn executable_macro_and_runtime_parser_emit_identical_atoms() {
    let compiled = program!("E8 $ { ' 31 C0 } ( 41 | 42 ) [1-4] 90");
    let runtime = ProgramBuf::parse("E8 $ { ' 31 C0 } ( 41 | 42 ) [1-4] 90")
        .expect("runtime executable pattern should parse");

    assert_eq!(compiled.atoms(), runtime.atoms());
    assert_eq!(compiled.save_len(), runtime.save_len());
}

#[test]
fn executable_macro_is_available_from_the_facade_prelude() {
    use ganymede_pattern::prelude::{PointerWidth, ProgramScanner, program};

    let compiled = program!("41 ? 42");
    let scanner = ProgramScanner::new(compiled, PointerWidth::U64);

    assert_eq!(scanner.find(b"xAqBy"), Some(1));
}

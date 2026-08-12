#![deny(clippy::all, clippy::perf, clippy::nursery, clippy::pedantic)]
#![forbid(clippy::unwrap_used, clippy::panic, rustdoc::all)]

use std::env;
use std::error::Error;
use std::path::PathBuf;

use bindgen::MacroTypeVariation;
use bindgen::callbacks::ParseCallbacks;

/// The package relative common binding header.
const COMMON_BINDING_HEADER_RELATIVE_PATH: &str = "c/include/ganymede-elf.h";

/// The generated common binding output file.
const COMMON_BINDING_OUTPUT_FILE: &str = "ganymede-elf.rs";

fn main() -> Result<(), Box<dyn Error>> {
    let current_dir = env::current_dir()?.canonicalize()?;
    let common_binding_header = current_dir.join(COMMON_BINDING_HEADER_RELATIVE_PATH);
    let output = PathBuf::from(env::var("OUT_DIR")?);

    let bind_context = || {
        bindgen::Builder::default()
            .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
            .parse_callbacks(Box::new(DeriveCallbacks))
            .prepend_enum_name(false)
            .default_macro_constant_type(MacroTypeVariation::Signed)
            .clang_arg("-D__BINDGEN__")
            .use_core()
    };

    bind_context()
        .header(common_binding_header.to_string_lossy().into_owned())
        .generate()?
        .write_to_file(output.join(COMMON_BINDING_OUTPUT_FILE))?;

    Ok(())
}

/// Structure used for `derive` annotations in generated items via bindgen.
#[derive(Debug)]
struct DeriveCallbacks;

impl ParseCallbacks for DeriveCallbacks {
    fn add_derives(
        &self,
        bindgen::callbacks::DeriveInfo { name, .. }: &bindgen::callbacks::DeriveInfo<'_>,
    ) -> Vec<String> {
        let is_elf_struct = name.starts_with("Elf32_") | name.starts_with("Elf64_");

        if is_elf_struct {
            vec!["catalejo::prelude::Field".to_string()]
        } else {
            Vec::new()
        }
    }

    fn int_macro(&self, name: &str, _value: i64) -> Option<bindgen::callbacks::IntKind> {
        let is_auxiliary = name.starts_with("AT_");

        if is_auxiliary {
            Some(bindgen::callbacks::IntKind::U64)
        } else {
            None
        }
    }
}

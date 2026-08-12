#![deny(clippy::all, clippy::perf, clippy::nursery, clippy::pedantic)]
#![forbid(clippy::unwrap_used, clippy::panic, rustdoc::all)]

use std::env;
use std::error::Error;
use std::fs;
use std::path::PathBuf;

use bindgen::callbacks::ParseCallbacks;
use syn::visit_mut::{self, VisitMut};

/// The package relative GNU linker binding header.
const GNU_LINKER_BINDING_HEADER_RELATIVE_PATH: &str = "c/include/ganymede-linker-gnu.h";

/// The generated GNU i386 linker binding output file.
const GNU_LINKER_32_BINDING_OUTPUT_FILE: &str = "ganymede-linker-gnu-32.rs";

/// The generated GNU x86-64 linker binding output file.
const GNU_LINKER_64_BINDING_OUTPUT_FILE: &str = "ganymede-linker-gnu-64.rs";

/// Syntax visitor that wraps generated raw pointers with target-width Catalejo identities.
///
/// Bindgen remains responsible for every other generated declaration, attribute, and layout check.
#[derive(Debug)]
// NOTE(invariant): The pointer wrapper belongs to the same bindgen target width as every syntax node visited by this value.
struct GeneratedBindingVisitor(syn::Path);

impl VisitMut for GeneratedBindingVisitor {
    fn visit_type_mut(&mut self, target_type: &mut syn::Type) {
        match target_type {
            syn::Type::Ptr(..) => {
                let target_raw_pointer = target_type.clone();
                let Self(pointer) = self;
                let target_wrapper = &*pointer;

                *target_type = syn::parse_quote!(#target_wrapper<#target_raw_pointer>);
            }
            _ => visit_mut::visit_type_mut(self, target_type),
        }
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let current_dir = env::current_dir()?.canonicalize()?;
    let gnu_linker_binding_header = current_dir.join(GNU_LINKER_BINDING_HEADER_RELATIVE_PATH);
    let output = PathBuf::from(env::var("OUT_DIR")?);

    let bind_context = || {
        bindgen::Builder::default()
            .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
            .parse_callbacks(Box::new(DeriveCallbacks))
            .use_core()
    };

    for (pointer_width, target, output_file) in [
        (
            32,
            "i686-unknown-linux-gnu",
            GNU_LINKER_32_BINDING_OUTPUT_FILE,
        ),
        (
            64,
            "x86_64-unknown-linux-gnu",
            GNU_LINKER_64_BINDING_OUTPUT_FILE,
        ),
    ] {
        let output_path = output.join(output_file);

        bind_context()
            .header(gnu_linker_binding_header.to_string_lossy().into_owned())
            .clang_arg(format!("--target={target}"))
            .clang_arg(format!("-m{pointer_width}"))
            .clang_arg("-D_GNU_SOURCE")
            .allowlist_type(format!("r_debug_{pointer_width}"))
            .allowlist_type(format!("r_debug_extended_{pointer_width}"))
            .allowlist_type(format!("link_map_{pointer_width}"))
            .allowlist_recursively(false)
            .generate()?
            .write_to_file(&output_path)?;

        let generated_source = fs::read_to_string(&output_path)?;
        let mut generated_syntax = syn::parse_file(&generated_source)?;
        let pointer = syn::parse_str(&format!("::catalejo::pointer::Pointer{pointer_width}"))?;
        let mut target_visitor = GeneratedBindingVisitor(pointer);

        target_visitor.visit_file_mut(&mut generated_syntax);

        let generated_source = prettyplease::unparse(&generated_syntax);

        fs::write(output_path, generated_source)?;
    }

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
        let is_link_struct = name.starts_with("r_debug") || name.starts_with("link_map");

        if is_link_struct {
            vec![
                "catalejo::prelude::Field".to_string(),
                "Copy".to_string(),
                "Clone".to_string(),
            ]
        } else {
            Vec::new()
        }
    }
}

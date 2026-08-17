//! Compile-time construction of validated fixed-width and executable patterns.
//!
//! Both procedural macros delegate syntax to `ganymede-pattern-core`. The fixed-width macro emits
//! canonical byte and mask arrays. The executable macro emits the exact flat atom stream returned by
//! the runtime executable parser. Generated expressions therefore require no runtime parsing.
#![deny(clippy::all, clippy::perf, clippy::nursery, clippy::pedantic)]
#![forbid(clippy::unwrap_used, clippy::panic, rustdoc::all)]
#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]

use ganymede_pattern_core::program::Atom;
use proc_macro2::TokenStream;
use quote::quote;
use syn::LitStr;

/// Compile one string literal into a static `ganymede_pattern::Pattern`.
///
/// Expansion accepts exactly the syntax implemented by
/// [`ganymede_pattern_core::syntax::parse`]. Invalid syntax becomes a compiler error at the literal
/// span. Successful expansion performs no runtime parsing and allocates no pattern representation at
/// runtime.
#[proc_macro]
#[inline]
pub fn pattern(target_input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let target_literal = syn::parse_macro_input!(target_input as LitStr);

    match PatternExpansion::new(&target_literal).render() {
        Ok(target_tokens) => target_tokens,
        Err(target_error) => target_error.into_compile_error(),
    }
    .into()
}

/// Compile one string literal into a static executable `ganymede_pattern::Program`.
///
/// Expansion accepts exactly the syntax implemented by
/// [`ganymede_pattern_core::program::syntax::parse`]. The emitted flat atom stream is the same
/// representation consumed by runtime executable scanning.
#[proc_macro]
#[inline]
pub fn program(target_input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let target_literal = syn::parse_macro_input!(target_input as LitStr);

    match ProgramExpansion::new(&target_literal).render() {
        Ok(target_tokens) => target_tokens,
        Err(target_error) => target_error.into_compile_error(),
    }
    .into()
}

/// Borrowed fixed-pattern macro input and its code-generation operation.
struct PatternExpansion<'literal>(&'literal LitStr);

impl<'literal> PatternExpansion<'literal> {
    /// Bind one parsed Rust string literal to a fixed-pattern expansion.
    #[inline]
    const fn new(target_literal: &'literal LitStr) -> Self {
        Self(target_literal)
    }

    /// Parse fixed-width syntax and emit the canonical static representation.
    fn render(self) -> syn::Result<TokenStream> {
        let Self(target_literal) = self;
        let source = target_literal.value();
        let (bytes, masks) =
            ganymede_pattern_core::syntax::parse(&source).map_err(|target_error| {
                syn::Error::new(
                    target_literal.span(),
                    format!("invalid binary pattern {target_error}"),
                )
            })?;

        Ok(quote! {{
            const __GANYMEDE_PATTERN_BYTES: &[u8] = &[#(#bytes),*];
            const __GANYMEDE_PATTERN_MASKS: &[u8] = &[#(#masks),*];
            const __GANYMEDE_PATTERN: ::ganymede_pattern::export::Pattern<'static> =
                ::ganymede_pattern::export::Pattern::from_static_parts(
                    __GANYMEDE_PATTERN_BYTES,
                    __GANYMEDE_PATTERN_MASKS,
                );

            __GANYMEDE_PATTERN
        }})
    }
}

/// Borrowed executable-pattern macro input and its code-generation operation.
struct ProgramExpansion<'literal>(&'literal LitStr);

impl<'literal> ProgramExpansion<'literal> {
    /// Bind one parsed Rust string literal to an executable-pattern expansion.
    #[inline]
    const fn new(target_literal: &'literal LitStr) -> Self {
        Self(target_literal)
    }

    /// Parse executable syntax and emit the exact flat atom representation.
    fn render(self) -> syn::Result<TokenStream> {
        let Self(target_literal) = self;
        let source = target_literal.value();
        let atoms =
            ganymede_pattern_core::program::syntax::parse(&source).map_err(|target_error| {
                syn::Error::new(
                    target_literal.span(),
                    format!("invalid executable pattern {target_error}"),
                )
            })?;
        let atoms = atoms.into_iter().map(Self::atom);

        Ok(quote! {{
            const __GANYMEDE_PROGRAM_ATOMS: &[::ganymede_pattern::export::Atom] =
                &[#(#atoms),*];
            const __GANYMEDE_PROGRAM: ::ganymede_pattern::export::Program<'static> =
                ::ganymede_pattern::export::Program::from_static_atoms(
                    __GANYMEDE_PROGRAM_ATOMS,
                );

            __GANYMEDE_PROGRAM
        }})
    }

    /// Render one parsed executable atom through the facade's hidden export namespace.
    fn atom(target_atom: Atom) -> TokenStream {
        match target_atom {
            Atom::Byte(target_value) => {
                quote!(::ganymede_pattern::export::Atom::Byte(#target_value))
            }
            Atom::Save(target_slot) => quote!(::ganymede_pattern::export::Atom::Save(#target_slot)),
            Atom::Push(target_skip) => quote!(::ganymede_pattern::export::Atom::Push(#target_skip)),
            Atom::Pop => quote!(::ganymede_pattern::export::Atom::Pop),
            Atom::Fuzzy(target_mask) => {
                quote!(::ganymede_pattern::export::Atom::Fuzzy(#target_mask))
            }
            Atom::Skip(target_skip) => quote!(::ganymede_pattern::export::Atom::Skip(#target_skip)),
            Atom::Back(target_back) => quote!(::ganymede_pattern::export::Atom::Back(#target_back)),
            Atom::Many(target_limit) => {
                quote!(::ganymede_pattern::export::Atom::Many(#target_limit))
            }
            Atom::Jump1 => quote!(::ganymede_pattern::export::Atom::Jump1),
            Atom::Jump4 => quote!(::ganymede_pattern::export::Atom::Jump4),
            Atom::Pointer => quote!(::ganymede_pattern::export::Atom::Pointer),
            Atom::Pir(target_slot) => quote!(::ganymede_pattern::export::Atom::Pir(#target_slot)),
            Atom::Check(target_slot) => {
                quote!(::ganymede_pattern::export::Atom::Check(#target_slot))
            }
            Atom::Aligned(target_exponent) => {
                quote!(::ganymede_pattern::export::Atom::Aligned(#target_exponent))
            }
            Atom::ReadI8(target_slot) => {
                quote!(::ganymede_pattern::export::Atom::ReadI8(#target_slot))
            }
            Atom::ReadU8(target_slot) => {
                quote!(::ganymede_pattern::export::Atom::ReadU8(#target_slot))
            }
            Atom::ReadI16(target_slot) => {
                quote!(::ganymede_pattern::export::Atom::ReadI16(#target_slot))
            }
            Atom::ReadU16(target_slot) => {
                quote!(::ganymede_pattern::export::Atom::ReadU16(#target_slot))
            }
            Atom::ReadI32(target_slot) => {
                quote!(::ganymede_pattern::export::Atom::ReadI32(#target_slot))
            }
            Atom::ReadU32(target_slot) => {
                quote!(::ganymede_pattern::export::Atom::ReadU32(#target_slot))
            }
            Atom::Zero(target_slot) => quote!(::ganymede_pattern::export::Atom::Zero(#target_slot)),
            Atom::Case(target_next) => quote!(::ganymede_pattern::export::Atom::Case(#target_next)),
            Atom::Break(target_next) => {
                quote!(::ganymede_pattern::export::Atom::Break(#target_next))
            }
            Atom::Nop => quote!(::ganymede_pattern::export::Atom::Nop),
        }
    }
}

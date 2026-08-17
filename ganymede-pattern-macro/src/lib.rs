//! Compile-time construction for the unified binary pattern representation.
//!
//! The procedural macro delegates complete parsing and fixed-projection compilation to
//! `ganymede-pattern-core`. Expansion emits the same atom representation produced at runtime and
//! includes derived fixed byte and mask arrays only when the pattern is statically linear.
#![deny(clippy::all, clippy::perf, clippy::nursery, clippy::pedantic)]
#![forbid(clippy::unwrap_used, clippy::panic, rustdoc::all)]
#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]

use ganymede_pattern_core::{Atom, PatternBuf};
use proc_macro2::TokenStream;
use quote::quote;
use syn::LitStr;

/// Compile one string literal into a static `ganymede_pattern::Pattern`.
///
/// Expansion accepts the unified Pelite-style syntax implemented by
/// [`ganymede_pattern_core::PatternBuf::parse`]. Invalid syntax becomes a compiler error at the
/// literal span. Successful expansion performs no runtime parsing or allocation.
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

/// Borrowed pattern macro input and its code-generation operation.
struct PatternExpansion<'literal>(&'literal LitStr);

impl<'literal> PatternExpansion<'literal> {
    /// Bind one parsed Rust string literal to a pattern expansion.
    #[inline]
    const fn new(target_literal: &'literal LitStr) -> Self {
        Self(target_literal)
    }

    /// Parse unified syntax and emit atoms plus any derived fixed projection.
    fn render(self) -> syn::Result<TokenStream> {
        let Self(target_literal) = self;
        let source = target_literal.value();
        let pattern = PatternBuf::parse(&source).map_err(|target_error| {
            syn::Error::new(
                target_literal.span(),
                format!("invalid binary pattern {target_error}"),
            )
        })?;
        let atoms = pattern.atoms().iter().copied().map(Self::atom);
        let (fixed_bytes, fixed_masks) = pattern.fixed_parts().unwrap_or((&[], &[]));

        Ok(quote! {{
            const __GANYMEDE_PATTERN_ATOMS: &[::ganymede_pattern::export::Atom] = &[#(#atoms),*];
            const __GANYMEDE_PATTERN_FIXED_BYTES: &[u8] = &[#(#fixed_bytes),*];
            const __GANYMEDE_PATTERN_FIXED_MASKS: &[u8] = &[#(#fixed_masks),*];
            const __GANYMEDE_PATTERN: ::ganymede_pattern::export::Pattern<'static> =
                ::ganymede_pattern::export::Pattern::from_static_parts(
                    __GANYMEDE_PATTERN_ATOMS,
                    __GANYMEDE_PATTERN_FIXED_BYTES,
                    __GANYMEDE_PATTERN_FIXED_MASKS,
                );

            __GANYMEDE_PATTERN
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

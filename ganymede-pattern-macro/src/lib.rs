//! Compile-time construction of validated fixed-width patterns.
//!
//! The procedural macro uses the public syntax implementation from `ganymede-pattern-core`, then
//! emits static canonical byte and mask arrays. Search planning remains in the core crate and is
//! evaluated in the generated const expression, so macro and runtime construction share grammar and
//! representation rules without sharing procedural-macro internals.
#![deny(clippy::all, clippy::perf, clippy::nursery, clippy::pedantic)]
#![forbid(clippy::unwrap_used, clippy::panic, rustdoc::all)]
#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]

use proc_macro2::TokenStream;
use quote::quote;
use syn::LitStr;

/// Compile one string literal into a static `ganymede_pattern::Pattern`.
///
/// Expansion accepts exactly the syntax implemented by
/// [`ganymede_pattern_core::syntax::parse`]. Invalid syntax becomes a compiler error
/// at the literal span. Successful expansion performs no runtime parsing and allocates no pattern
/// representation at runtime.
///
/// This function is module-level because procedural macro entry points are required by Rust to be
/// exported functions carrying `#[proc_macro]`. Expansion behavior itself is owned by the private `Expansion` value.
#[proc_macro]
#[inline]
pub fn pattern(target_input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let target_literal = syn::parse_macro_input!(target_input as LitStr);

    match Expansion::new(&target_literal).render() {
        Ok(target_tokens) => target_tokens,
        Err(target_error) => target_error.into_compile_error(),
    }
    .into()
}

/// Borrowed macro input that owns syntax validation and code generation for one expansion.
struct Expansion<'literal>(&'literal LitStr);

impl<'literal> Expansion<'literal> {
    /// Bind one parsed Rust string literal to an expansion operation.
    #[inline]
    const fn new(target_literal: &'literal LitStr) -> Self {
        Self(target_literal)
    }

    /// Parse pattern syntax and emit the canonical static representation.
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

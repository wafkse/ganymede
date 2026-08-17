# Ganymede

Ganymede is a Linux process introspection toolkit built on [Catalejo].

The workspace keeps process access, ELF interpretation, GNU runtime-linker state, normalized modules, byte-preserving text, and binary pattern scanning in separate crates. The `ganymede` facade composes those capabilities without erasing their lower-level types.

## Crates

- `ganymede-process` owns format-neutral process access and mapping snapshots.
- `ganymede-text` preserves foreign path and text bytes without requiring UTF-8.
- `ganymede-elf` validates ELF32 and ELF64 process images and dynamic metadata.
- `ganymede-linker-gnu` captures coherent GNU i386 and x86-64 loader state.
- `ganymede-module` normalizes loader observations into format-neutral modules.
- `ganymede-pattern` provides fixed-width and Pelite-inspired executable scanning.
- `ganymede` selects supported loaders and exposes end-to-end inspection.

## Inspection

The facade proves the ELF class and exact interpreter path before entering a runtime-linker backend. Unsupported interpreter families return typed errors rather than falling through to GNU interpretation.

```rust
use ganymede::prelude::*;

fn modules(process: &Process) -> Result<Modules, Box<dyn std::error::Error>> {
    let process_snapshot = process.snapshot()?;
    let inspection = Inspection::capture(process, &process_snapshot)?;

    Ok(inspection.modules().clone())
}
```

## Pattern scanning

`ganymede-pattern` keeps the fixed-width scanner as a direct search path and adds a flat executable atom program inspired by Pelite. Runtime parsing and the `program!` procedural macro lower to the same representation.

Executable scanning keeps target pointer width and virtual base explicit. Its grammar supports exact bytes, wildcards, captures, fixed and ranged skips, followed relative and absolute pointers, alignment checks, integer reads, and alternatives.

## Development

The workspace pins Rust through `rust-toolchain.toml`. Clippy and rustfmt are installed with that toolchain. Bindgen also requires Clang and libclang.

Run the release validation set from the workspace root.

```sh
cargo fmt --all -- --check
cargo check --locked --workspace --all-targets
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo clippy --locked --workspace --all-targets -- -D warnings -D clippy::missing_const_for_fn
cargo clippy --locked --workspace --all-targets -- -D warnings -D clippy::missing_inline_in_public_items
cargo test --locked --workspace
RUSTDOCFLAGS='-D warnings' cargo doc --locked --workspace --no-deps
git diff --check
```

Two integration tests require the Mirilla kernel module and remain environment dependent.

[Catalejo]: https://github.com/wafkse/catalejo

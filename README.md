# Ganymede

Ganymede is a Rust workspace for inspecting Linux processes, ELF images, GNU runtime linker state, loaded modules, and binary patterns.

It is built on [Catalejo] for process memory access. The workspace keeps each layer separate so process access, executable parsing, loader state, normalized module identity, byte-preserving text, and pattern scanning can evolve without collapsing into one shared representation.

The project is currently focused on Linux ELF targets and GNU loaders on i386 and x86-64.

## What it provides

- Process attachment, typed foreign reads, and mapping snapshots through `ganymede-process`
- Byte-preserving text and path handling through `ganymede-text`
- ELF32 and ELF64 process image validation through `ganymede-elf`
- GNU runtime linker snapshot acquisition through `ganymede-linker-gnu`
- Format-neutral loaded module normalization through `ganymede-module`
- Fixed-width and Pelite-inspired executable pattern scanning through `ganymede-pattern`
- End-to-end loader inspection through the `ganymede` facade

## Inspection

The facade inspects the target ELF class and interpreter before selecting a loader backend. Unsupported interpreter families return typed errors instead of being interpreted as GNU state.

```rust
use ganymede::prelude::*;

fn modules(pid: u32) -> Result<Modules, Box<dyn std::error::Error>> {
    let process = Process::new(ProcessId(pid))?;
    let process_snapshot = process.snapshot()?;
    let inspection = Inspection::capture(&process, &process_snapshot)?;

    Ok(inspection.modules().clone())
}
```

`Inspection` keeps the validated loader snapshot and the normalized module view tied to the same process mapping snapshot used during capture.

## Pattern scanning

`ganymede-pattern` exposes one pattern language and one scanner. The syntax is inspired by Pelite and supports exact bytes, wildcards, captures, fixed and ranged skips, followed references, alignment checks, integer reads, and alternatives.

Patterns with linear fixed-width semantics are automatically compiled to an internal anchor and SIMD search plan. Patterns that need control flow, captures, reads, or followed references execute through the flat atom interpreter. Both paths preserve the same public `Pattern`, `Scanner`, and `Matches` API.

Runtime parsing and the `pattern!` procedural macro use the same compiler.

```rust
use ganymede_pattern::prelude::*;

let pattern = pattern!("48 8B [1-4] 90");
let scanner = Scanner::new(pattern, PointerWidth::U64);

assert_eq!(scanner.find(&[0x48, 0x8b, 0x00, 0x90]), Some(0));
```

Scans operate on byte images. Candidate ranges limit where matches may begin, while followed references may resolve elsewhere inside the supplied image.

## Workspace layout

The workspace is intentionally split by semantic responsibility rather than by one common internal representation.

| Crate | Responsibility |
| --- | --- |
| `ganymede` | End-to-end facade and loader selection |
| `ganymede-process` | Process access and mapping snapshots |
| `ganymede-text` | Byte-preserving text and paths |
| `ganymede-elf` | ELF validation and dynamic metadata |
| `ganymede-linker-gnu` | GNU runtime linker acquisition |
| `ganymede-module` | Normalized loaded modules |
| `ganymede-pattern-core` | Pattern representations, parsing, and scanning |
| `ganymede-pattern-macro` | Compile-time pattern construction |
| `ganymede-pattern` | Pattern facade |

## Development

The workspace pins Rust with `rust-toolchain.toml`. Clippy and rustfmt are included in the pinned toolchain. The ELF binding build also requires Clang and libclang.

Catalejo is currently consumed from its Git repository and pinned by `Cargo.lock` until a registry release is available.

Run the same validation set used by CI from the workspace root.

```sh
cargo fmt --all -- --check
cargo check --locked --workspace --all-targets
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo clippy --locked --workspace --all-targets -- -D warnings -D clippy::missing_const_for_fn
cargo clippy --locked --workspace --all-targets -- -D warnings -D clippy::missing_inline_in_public_items
cargo test --locked --workspace
RUSTDOCFLAGS='-D warnings' cargo doc --locked --workspace --no-deps
```

Two integration tests depend on the Mirilla kernel module and are ignored when that environment is unavailable.

## Project status

Ganymede is under active development. Public APIs are being shaped around explicit format, address-width, snapshot, and loader invariants. Expect changes while the crate family approaches its first stable release.

[Catalejo]: https://github.com/wafkse/catalejo

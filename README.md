# Ganymede

Ganymede is a Linux process introspection toolkit built on [Catalejo].

The workspace keeps process access, executable formats, runtime-linker protocols, normalized module identity, byte-preserving text, and binary pattern scanning in separate crates. The `ganymede` facade composes the process-to-module path without erasing the lower-level types.

## Crates

- `ganymede-process` provides format-neutral process attachment, foreign reads, and kernel mapping snapshots.
- `ganymede-text` preserves exact foreign path and text bytes without requiring UTF-8.
- `ganymede-elf` validates ELF32 and ELF64 process images and resolves dynamic symbols.
- `ganymede-linker-gnu` captures coherent GNU i386 and x86-64 runtime-linker state.
- `ganymede-module` normalizes loader observations into format-neutral loaded modules.
- `ganymede-pattern` provides runtime and compile-time binary pattern parsing and scanning.
- `ganymede` selects a supported loader explicitly and composes coherent loader capture with module normalization.

## Loader selection

The facade proves the ELF class and reads the exact interpreter path before entering a runtime-linker backend. GNU i386 is selected only for `ld-linux.so.2`. GNU x86-64 is selected only for `ld-linux-x86-64.so.2`. Other ELF interpreters return a typed unsupported-loader error.

This policy prevents an unknown ELF interpreter from silently falling through to GNU interpretation. Future runtime-linker crates can be added as sibling backends without placing a generic linker protocol into lower-level crates.

## End-to-end inspection

Given an already attached `Process`, the common path is

```rust
use ganymede::prelude::*;

fn modules(process: &Process) -> Result<Modules, Box<dyn std::error::Error>> {
    let process_snapshot = process.snapshot()?;
    let inspection = Inspection::capture(process, &process_snapshot)?;

    Ok(inspection.modules().clone())
}
```

`Inspection` retains a width-preserving GNU snapshot internally and normalizes modules against the same process mapping snapshot used during capture. Call `Inspection::snapshot` when architecture-specific GNU state is required and `Inspection::modules` for the format-neutral module view.

Pattern scanning remains a separate dependency through `ganymede-pattern`. This keeps its procedural macro expansion and runtime scanner usable without making them dependencies of process or loader inspection.

[Catalejo]: https://github.com/wafkse/catalejo

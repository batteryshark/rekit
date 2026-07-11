---
name: minimal-executable
description: "CONSTRUCT: generate a deterministic, conservative no-runtime executable that exits with a chosen status: Linux ELF (x86_64/i386), Windows PE (PE32+/PE32), or a static macOS arm64 Mach-O research artifact. Emits bytes, verifies its own header invariants, measures/hash-inspects the result, and labels proof honestly. Builds only; never runs the artifact."
---

# Minimal Executable Builder

Generate a small, deterministic executable without a compiler, linker, imports, or
language runtime. The runner writes the artifact and validates the fields it owns; it
never executes the result.

## Workflow

1. Choose `elf`, `pe`, or `macho` and a supported architecture.
2. Pick an exit status from 0 through 255.
3. Generate the artifact and inspect the JSON evidence.
4. If execution matters, test separately on the real target OS/CPU and record that
   evidence as `native-proven`.

```bash
rekit run minimal-executable elf --arch x86_64 --exit-code 42 --out tiny-elf --report json
rekit run minimal-executable pe --arch i386 --out tiny.exe --report json
rekit run minimal-executable macho --arch arm64 --out tiny-macho --report json
```

## Supported shapes

| Format | Architectures | Shape | Initial proof |
|---|---|---|---|
| ELF | `x86_64`, `i386` | ELF header + one RX `PT_LOAD` + direct Linux `exit` syscall | structurally validated |
| PE | `x86_64`, `i386` | DOS/COFF/optional headers + one RX `.text`, no imports | structurally validated |
| Mach-O | `arm64` | `__PAGEZERO` + RX `__TEXT` + `LC_UNIXTHREAD`, direct Darwin syscall | static research artifact |

The PE entry point returns the requested value to the Windows process-start thunk.
The arm64 Mach-O is intentionally labeled a **research artifact**: modern release
macOS normally requires dyld plus an ad-hoc signature and can reject static
`MH_EXECUTE` before entry. Parser acceptance does not change that claim.

## Evidence discipline

- `structural`: the runner re-parsed its own required headers and offsets.
- `tool-readable`: an available host `file` command recognized the artifact.
- `loader-accepted`: only claim after the target OS loader maps and starts it.
- `native-proven`: only claim after execution on the actual target OS and CPU.

The runner reports only the first two. Do not promote those results to loader or
native proof without a separate execution record.

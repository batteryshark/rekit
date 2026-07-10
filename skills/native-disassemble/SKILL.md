---
name: native-disassemble
description: "Disassemble PE, ELF, or Mach-O binaries to function-oriented assembly without executing them. Automatically uses llvm-objdump/objdump, then falls back to Rizin/radare2 analysis for stripped binaries. Writes the complete listing to disassembly.txt and reports instruction/function-line counts."
---

# Native Disassembler

Turn a PE, ELF, or Mach-O executable or library into a complete assembly listing
without running it. This is the lightweight read-side tool between structural triage
(`pe-analyze`, `elf-analyze`, `macho-analyze`) and C-like decompilation
(`native-decompile`).

## What it does

The runner validates the input container, selects the first available backend, and
writes `disassembly.txt` atomically:

1. `llvm-objdump -d -C`
2. `objdump -d -C`
3. `rizin -q -c "aaa; pdf @@F"`
4. `r2 -q -c "aaa; pdf @@F"`

Objdump is preferred because it is direct and fast. Rizin/radare2 is the fallback
when analyzed function recovery is more useful, especially on stripped binaries.
All backends are invoked with argument arrays, color is disabled, and execution is
timeout-bounded. The target is parsed and disassembled only; it is never loaded as a
process, emulated, or executed.

## Usage

```bash
rekit run native-disassemble ./sample.exe ./out
rekit run native-disassemble ./sample.elf ./out --format json
rekit run native-disassemble ./sample.elf ./out --tool rizin
rekit run native-disassemble ./sample.elf ./out --timeout 300
```

The JSON result is a compact summary containing the selected backend, detected file
format, output path, byte count, function-label count, and instruction-line count.
The potentially large assembly listing always stays in `out/disassembly.txt`.

## Prerequisites

- **Python 3.8+** for the pure-stdlib runner.
- One disassembler on `PATH`: `llvm-objdump`, `objdump`, `rizin`, or `r2`.

LLVM/GNU objdump is normally supplied by LLVM, Xcode Command Line Tools, or binutils.
Rizin and radare2 are optional heavier fallbacks; no Ghidra or Java runtime is needed.

## Boundaries

- PE, ELF, Mach-O, and universal/fat Mach-O containers are accepted.
- Raw shellcode has no container metadata and is intentionally rejected; use
  `emulate-code` or a future raw-code disassembler with an explicit architecture.
- The summary counts recognizable listing lines; `disassembly.txt` is the source of
  truth and is not truncated.

---
name: asm-assemble
description: "CONSTRUCT: assemble asm text (a file or --code) into machine-code bytes with the LLVM/clang integrated assembler — x64/x86/arm64/arm — emitted as hex, a C array, a raw blob, or JSON. Backed by clang (no fragile native python binding), so it works cross-arch anywhere clang does. The write-side partner of emulate-code: assemble a snippet, then run it on the virtual CPU. Transforms text→bytes; runs nothing."
---

# Assembler (LLVM/clang)

**🔨 Construct tier — produces bytes, runs nothing.**

## Role in the workflow

The write-side partner of `emulate-code`. Where that skill *runs* bytes on a virtual CPU,
this one *makes* them: assemble a snippet, then emulate it — a tight
**write-shellcode → observe-behavior** loop with no host execution at any point.

## What it does

Assembles asm text (a file or `--code "…"`) with the **LLVM/clang integrated assembler**
for `x64 / x86 / arm64 / arm`, then extracts the raw `.text` bytes, emitted as:

- `hex` (default) — a hex string
- `c` — a ready-to-paste `unsigned char shellcode[] = { … };` array (drop into a `cc-build` stub)
- `raw` — the raw bytes (to `--out`, or stdout)
- `json` — `{ok, arch, triple, length, hex, out?}`

x86/x64 default to **Intel syntax** (`--att` for AT&T/GAS); ARM uses GAS syntax.

## Toolchain choice

The LLVM assembler supports the target architectures anywhere clang runs.
`keystone-engine` has no arm64 macOS wheel, which would make that alternative
platform-dependent.

## Prerequisites

- **clang** — `xcode-select --install` (macOS) or install clang/LLVM (Linux).
- **A section extractor** — `otool` (ships with Xcode CLT) on macOS, or
  `objcopy`/`llvm-objcopy`/`objdump` on Linux. Checked flexibly; absent → honest hint.

## Usage — the shellcode loop

```bash
rekit run asm-assemble --code "mov rax, 0x1337; mov [rsp], rax" --out sc.bin
rekit run emulate-code sc.bin            # ← run what you just assembled, contained
rekit run asm-assemble --code "mov x0, #0x1337" --arch arm64 --format hex
rekit run asm-assemble --code "xor eax,eax; ret" --arch x86 --format c   # C array for a stub
```

---
name: cc-build
description: "CONSTRUCT: compile C/C++/ObjC source into a native artifact (exe / .o / .s / LLVM IR) with clang (falls back to cc/gcc). For building PoCs, test harnesses, stubs, and shared libs rekit needs. Cross-compiles via --target/--arch. Compiles only — does NOT run the result (feed the output to exec-observe/emulate-code yourself). BYO C compiler."
---

# C/C++ Compiler (clang)

**🔨 Construct tier — this skill *produces* an artifact, it doesn't read a sample.**

## Why this exists

rekit has been all *analyze* — read/observe a target. `cc-build` is the first *construct*
skill: it builds the things RE work needs — a PoC, a test harness, a stub to feed a
decompiler, a shared lib to inject. It compiles; it does **not** run the result. To run
what it builds, hand the artifact to the dynamic tier yourself (`exec-observe` for an
exe, `emulate-code` for shellcode/obj bytes).

## What it does

Thin, honest wrapper over `clang` (falls back to `cc`/`gcc`): picks a compiler, builds
the argv, runs it, and reports the artifact path/size plus the compiler diagnostics.

- `--emit exe|obj|asm|ir` — link an executable, a `.o`, assembly (`.s`), or LLVM IR
  (`.ll`, clang only). `asm`/`ir` are great for *seeing what the compiler generates*.
- Cross-compile with `--target <triple>` and/or `--arch`.
- `--std`, `--opt`, `--shared`, `--static`, and `--cflags "…"` for anything else.

## Prerequisites

- A **C compiler** — `clang` (macOS: `xcode-select --install`; Linux: install clang/LLVM)
  or `gcc`. Checked flexibly (`clang || cc || gcc`); absent → honest install hint.

## Safety

`executes_input: no` — the produced binary is never run. Caveat: compiling *untrusted*
source still invokes a compiler, so it's tier 1, not 0. The usual input is your own
trusted PoC source.

## Usage

```bash
rekit run cc-build poc.c --out poc                       # build an exe
rekit run cc-build shellcode_stub.c --emit obj           # → .o for emulate-code
rekit run cc-build foo.c --emit asm --opt 0              # see the codegen
rekit run cc-build mod.c --shared --target aarch64-linux-gnu   # cross-compiled .so
```

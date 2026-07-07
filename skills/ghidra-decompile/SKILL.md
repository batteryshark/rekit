# Ghidra Decompiler (headless)

Decompile a native binary (ELF/PE/Mach-O) with **full Ghidra** headless analysis.

## When to use

A hard native target where `native-decompile` (rizin's `pdg`) isn't enough — Ghidra's
auto-analysis (function/type/xref recovery) is heavier and often produces cleaner
output on complex or stripped binaries. Triage with `elf`/`pe`/`macho-analyze` first.

> `native-decompile` already gives you *Ghidra's decompiler* via rizin, without a JVM
> — use that for the common case. Reach for this when you want full Ghidra.

## What it does

Runs `analyzeHeadless` on the binary in a throwaway project, then executes the bundled
Ghidra script (`runtime/ghidra_decompile.py`, Jython) which decompiles **every**
function to `outdir/decompiled.c`. Static — Ghidra analyses and decompiles; it never
runs the target. The project dir is deleted afterward; analysis is timeout-bounded.

## Prerequisites

- **python3** (runner) and **Ghidra's `analyzeHeadless`** — Ghidra is a large JVM
  application (needs a JRE ≥ 17), so it is **not bundled**. Install Ghidra
  (<https://ghidra-sre.org>) and put `<ghidra>/support/analyzeHeadless` on PATH, or set
  `GHIDRA_HOME` (the runner will find `support/analyzeHeadless`). Until then `doctor`
  marks the skill not-ready and `run` reports the honest gap. (We *do* bundle the
  decompile script.)

## Usage

```bash
skillpack run ghidra-decompile ./suspicious.elf ./out
```

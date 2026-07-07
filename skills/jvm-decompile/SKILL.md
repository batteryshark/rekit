# JVM / Android Decompiler

Decompile Java/Android bytecode (`.apk` / `.dex` / `.jar` / `.class`) back to Java
source with [jadx](https://github.com/skylot/jadx).

## When to use

An Android app or Java archive you need to read. Extract nested archives with
`unpack` first if needed, then decompile the `.dex`/`.jar` and review the `.java`.

## What it does

Runs `jadx -d <outdir> <input>` (static — jadx reconstructs source from bytecode and
never executes it) and reports how many files were written.

## Prerequisites

- **python3** (runner) and **`jadx`** on PATH. jadx is a large JVM application that
  needs a JRE (java ≥ 11), so it is **not bundled** — install it and put it on PATH.
  Until then `rekit doctor` shows this skill as not-ready and `run` reports the
  honest blind spot with an install hint (nothing is silently skipped).

## Usage

```bash
rekit run jvm-decompile ./app.apk ./out
```

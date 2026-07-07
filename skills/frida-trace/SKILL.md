# Frida API Tracer

**⚡ Dynamic tier — Frida spawns and runs the target.** Run only where you don't mind
the risk.

## When to use

You want the **API/library view** of a running sample — which network/exec/file/crypto
functions it actually calls — even when the code is statically obfuscated. Complements
`syscall-trace` (kernel view) with instrumentation at the library boundary.

## What it does

Runs [`frida-trace`](https://frida.re) with a curated set of hooks (network, exec,
file, crypto globs — override with `--patterns`), spawns the target, and logs the
matched calls for a bounded duration, then summarizes call counts per function.

## Consent & prerequisites

- Dynamic: `rekit run --allow-dynamic frida-trace <target>` (or `--yes-i-consent` /
  `REKIT_ALLOW_DYNAMIC=1`).
- **`frida-trace`** on PATH — `pip install frida-tools` (pulls the Frida native core).
  Absent → `doctor` marks it not-ready.

## Usage

```bash
rekit run --allow-dynamic frida-trace ./sample --patterns "connect*,send*,open*"
rekit run --allow-dynamic frida-trace ./sample --format json
```

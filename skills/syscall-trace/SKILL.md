# Syscall Tracer

**⚡ Dynamic tier — runs the target.** Run only where you don't mind the risk.

## When to use

The core behavioral question: *what does this sample actually do to the system?*
`syscall-trace` runs it under a syscall tracer and tells you the files it touched, the
network it reached, the processes it spawned, and its syscall profile — the real
ground truth behind static findings.

## What it does

Runs the target under **`strace`** (Linux) or **`dtruss`** (macOS) with a timeout, then
summarizes: files opened, network (`connect`/`socket`), execs, and a syscall histogram.

## Consent & prerequisites

- Dynamic: `rekit run --allow-dynamic syscall-trace <target>` (or `--yes-i-consent` /
  `REKIT_ALLOW_DYNAMIC=1` for a direct call).
- **`strace`** (Linux) or **`dtruss`** (macOS) on PATH. On macOS, `dtruss` needs **root
  and a permissive SIP**; on Linux, `strace` needs ptrace permissions. Absent → `doctor`
  marks it not-ready with an install hint.

## Usage

```bash
rekit run --allow-dynamic syscall-trace ./sample --timeout 20
rekit run --allow-dynamic syscall-trace ./sample --format json | ...
```

Pipe the recovered files/IPs into `ioc-extract` for a report.

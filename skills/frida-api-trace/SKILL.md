---
name: frida-api-trace
description: "DYNAMIC: spawn an authorized target under Frida and trace selected exported APIs using signatures parsed from a user-supplied API Monitor XML tree. Reports typed argument names, safe string previews, return values, hook coverage, and bounded events. The proprietary definition corpus is never shipped and stays gitignored. EXECUTES the target; consent-gated. BYO frida-tools and legally obtained definitions."
---

# Signature-Aware Frida API Trace

Trace a bounded set of exported APIs while preserving their parameter names and
types. This complements `frida-trace`: use `frida-trace` for quick glob-based call
counts, and this skill when API signatures make the captured events materially more
readable.

## Safety and data boundary

**This skill spawns and executes the target.** Use an isolated, authorized analysis
environment and invoke it through `rekit run --allow-dynamic`.

API Monitor's XML definitions are user-supplied data with their own license. Rekit
does not redistribute them. Put your legally obtained tree at
`skills/frida-api-trace/assets/apimonitor/` (ignored by Git), or pass another location
with `--definitions`.

## Usage

```bash
rekit run --allow-dynamic frida-api-trace ./sample.exe \
  --apis "CreateFileW,WriteFile,RegSetValueExW,WinHttpSendRequest" \
  --format json

rekit run --allow-dynamic frida-api-trace ./sample.exe \
  --definitions /path/to/api-monitor-xml \
  --modules "Kernel32.dll,Advapi32.dll" \
  --apis "CreateProcess*,VirtualAlloc*,WriteProcessMemory"
```

The XML parser expands `BothCharset="True"` declarations into `A` and `W` exports,
prefers the richest duplicate signature, and caps wildcard expansion with
`--max-hooks`. The generated Frida script reads only bounded ANSI/UTF-16 string
arguments it can identify safely; other arguments remain pointer/scalar values.

The target is terminated after `--timeout` seconds if it has not already exited.
JSON reports selected signatures, installed/missing hooks, captured calls, truncation,
and XML parse warnings. A missing export remains visible instead of silently reducing
coverage.

## Prerequisites

- Python 3.8+
- `frida-tools` / Python `frida` bindings
- A local API Monitor XML definition tree that you are permitted to use

Direct invocation additionally requires `--yes-i-consent` or
`REKIT_ALLOW_DYNAMIC=1`.

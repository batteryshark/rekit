---
name: dotnet-analyze
description: "Static triage of .NET / CLR managed assemblies (.dll/.exe) with dnfile: runtime version, assembly + referenced assemblies, type/method counts, IL-only vs mixed-mode, strong-name signing, unmanaged module refs, and the P/Invoke (DllImport) native-API surface classified by capability. Emits DOTNET.* atoms. Parses CLR metadata only — never loads or runs the assembly."
---

# .NET Assembly Analyzer

Static triage of .NET / CLR managed assemblies (`.dll` / `.exe`) with
[dnfile](https://github.com/malwarefrank/dnfile). No .NET runtime required — it
parses CLR metadata directly.

## When to use

You have a Windows binary that turns out to be **managed .NET** (a PE with a CLR
header) rather than native code. `pe-analyze` sees only the tiny native stub; the
real behaviour lives in IL + metadata. This reads that metadata. If you're not sure
which it is, point this at it — a native PE is reported as such with a pointer to
`pe-analyze`.

## What it reports

- **Identity** — runtime version (e.g. `v4.0.30319`), assembly name, IL-only vs
  **mixed-mode** (native code → `DOTNET.MIXED_MODE`), strong-name signing
  (`DOTNET.NO_STRONGNAME`).
- **References** — referenced assemblies (name + version), and **unmanaged module
  refs** (`DOTNET.UNMANAGED_MODULE`).
- **P/Invoke surface** — every `DllImport` (managed method → native API in a native
  DLL), classified by capability (inject / exec / network / anti-debug / crypto) →
  `DOTNET.PINVOKE`. **This is the key signal**: pure-IL malware still has to reach
  the OS through P/Invoke.
- **Suspicious refs** — dynamic-code / process / WMI namespaces (`DOTNET.SUSPICIOUS_REF`).
- Counts of types and methods.

Strictly **static** — parses metadata tables via dnfile; never loads the assembly
into a CLR, JITs, or executes it. Safe on hostile files.

## Usage

```bash
rekit run dotnet-analyze ./payload.exe
rekit run dotnet-analyze ./managed.dll --format json
```

Native PE → `{"ok": true, "isDotNet": false, "note": "… use pe-analyze"}`.
Non-PE → honest failure.

## Prerequisites

- **python3 ≥ 3.8** — dnfile is vendored under `runtime/site` (pure-python). No .NET
  runtime, no network/install at analysis time.

## Rebuilding

`runtime/site` is populated from the pinned `runtime/requirements.txt` by
`scripts/build.sh` (`uv pip install --target`, build time only).

---
name: pyscylla
description: "Dump, realign, and rebuild Import Address Tables of Windows PE binaries via Python bindings to libscylla (the engine behind the classic Scylla GUI). The programmatic successor to Scylla for agent-driven memory-dump cleanup: process enumeration (arch-aware), live dump, IAT search/parse/fix, XML tree round-trip, and reference scanning. Windows-only (vendored libscylla-{x86,x64}.dll + matching-arch Python). DYNAMIC on a live process (ReadProcessMemory) but does not execute the target."
---

# pyscylla — IAT Rebuilder (libscylla bindings)

Python bindings for `libscylla` — dump, realign, and rebuild Import Address Tables
of Windows PE binaries. The programmatic successor to the classic
[Scylla](https://github.com/NtQuery/Scylla) GUI tool, designed for agent-driven
memory-dump cleanup workflows.

**Windows-only.** The vendored `libscylla-{x86,x64}.dll` is a native Windows DLL,
and the live-process operations use `OpenProcess` / `ReadProcessMemory`.

## ⚠️ The arch-match rule (read first)

**`sizeof(DWORD_PTR)` is baked at libscylla compile time.** A 64-bit libscylla only
correctly processes 64-bit targets; 32-bit only 32-bit. **Wrong arch = silently
corrupt output** (every IAT entry becomes its own import descriptor).

| Target arch | Required Python | Required DLL |
|---|---|---|
| x64 | 64-bit Python | `libscylla-x64.dll` |
| x86 | 32-bit Python | `libscylla-x86.dll` |

pyscylla selects the DLL by Python's arch at import time. **Run `arch` first** to
confirm the match before dump/fix.

## Usage

This skill is a clean passthrough to pyscylla's CLI — the first positional is the
operation (`op`), followed by that op's args. `--json` is forced for rekit.

```bash
# check libscylla version + the arch match for a target
rekit run pyscylla version
rekit run pyscylla arch --pid 1234

# list processes
rekit run pyscylla procs

# the headline pipeline: find IAT → dump → fix → rebuild
rekit run pyscylla iat-find --pid 1234 --start 0x401000
rekit run pyscylla fix --pid 1234 --addr 0x405000 --size 0x100 --dump game.dmp --out game_fixed.exe
rekit run pyscylla rebuild --file game_fixed.exe
```

## Op reference

| Op | Args | Does |
|---|---|---|
| `version` | — | print libscylla version |
| `arch` | `--pid` | print target arch + Python arch + match status (run this first) |
| `procs` | — | list processes with arch + image base |
| `dump` | `--pid\|--name` `--out` `[--file]` `[--entry-point]` | dump a live process to a file |
| `iat-find` | `--pid` `[--start]` `[--advanced]` | find the IAT region in a live process |
| `fix` | `--pid` `--addr` `--size` `--dump` `--out` | dump + fix IAT (auto mode) |
| `rebuild` | `--file` `[--backup]` `[--skip-checksum]` | realign + checksum a dumped PE |
| `tree` | `--load\|--save` `[--pid --addr --size --oep]` | Scylla XML tree load/save |
| `refs` | `--pid` `--iat-addr` `--iat-size` `[--patch]` | scan for IAT references (trace bad imports) |

The agent workflow this is built for: another skill finds the OEP → pyscylla does
`iat-find` → `dump` → `fix` → `rebuild`, producing a clean unpacked EXE.

## MCP server (for direct LLM-agent integration)

pyscylla also ships an MCP server (`runtime/pyscylla/mcp_server.py`) exposing
`server_info`, `list_processes`, `find_process`, `check_arch_match`,
`dump_process`, `iat_search`, `iat_parse_live`, `iat_fix_auto`, `rebuild_file`,
`tree_save`, `tree_load`, `reference_scan`. Run it directly:

```bash
python -m pyscylla.mcp_server
```

## In the dump-recovery pipeline

1. **OEP find** — separate skill (debugger / Frida trace).
2. **iat-find** ← this skill — locate the IAT region.
3. **dump** ← this skill — write the process memory.
4. **fix** ← this skill — rebuild imports from the live IAT.
5. **rebuild** ← this skill — realign + checksum.
6. **pe-unmap** skill — final realignment if needed (virtual→raw).

## Rebuild the native DLL

The vendored DLLs were built with `scripts/build-native.ps1` (needs VS 2022 v143 +
diStorm + tinyxml; ATL/WTL not required for libscylla). Re-run it to refresh both
x86 and x64 Release DLLs.

License: GPL-3.0-only (inherited from upstream Scylla). See `runtime/pyscylla-README.md`.

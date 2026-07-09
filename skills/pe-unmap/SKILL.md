---
name: pe-unmap
description: "Convert between PE file alignments via hasherezade's pe_unmapper (libpeconv): UNMAP a memory dump back to raw-file alignment, MAP raw→virtual, or REALIGN. Essential for finishing a memory dump into a loadable EXE. Windows-only vendored binary. Static: reads bytes, writes a converted file, runs no target."
---

# pe-unmap — PE Alignment Converter

Convert between PE file alignments with hasherezade's
[pe_unmapper](https://github.com/hasherezade/pe_unmapper) (built on libpeconv).
Essential for finishing a memory dump into a loadable EXE — the memory layout
(virtual-aligned) differs from the on-disk layout (raw/file-aligned), and loaders
expect raw alignment.

**Static transform** — reads a PE file, writes a converted file, never runs it.
**Windows-only** vendored binary (run on a Windows analysis host).

## Modes

| `--mode` | Direction | Use when |
|---|---|---|
| `unmap` (default) | Virtual → Raw | You have a **memory dump** and want a loadable EXE. Auto-detects the base if `--base` is omitted. |
| `map` | Raw → Virtual | You need the in-memory layout (e.g. to feed an analyzer that expects mapped bytes). |
| `realign` | Virtual → Raw (Raw == Virtual) | Sections are memory-aligned (`VirtualAlignment=0x1000`) but you need `FileAlignment=0x200`-consistent output. |

## Usage

```bash
# recover an EXE from a memory dump (the common case)
rekit run pe-unmap dump.mem ./out --mode unmap --base 0x400000

# realign a Scylla/memory dump before IAT rebuild
rekit run pe-unmap raw_dump.exe ./out --mode realign
```

Result JSON: `{ok, mode, input, output, outputSize}`.

## In the dump-recovery pipeline

This is step 3 of the classic unpack pipeline:

1. **OEP find** (skill: a debugger / Frida trace) — stop at the original entry point.
2. **Dump** (skill: pyscylla `dump`, or Scylla) — write the process memory.
3. **Realign** ← this skill — convert virtual→raw alignment.
4. **IAT rebuild** (skill: pyscylla `fix` + `rebuild`) — reconstruct imports.

Pair it with **pyscylla** for the dump + IAT rebuild steps.

## Rebuild from source

The committed `bin/pe_unmapper.exe` is a Release x64 build. To refresh from upstream:

```powershell
.\scripts\build.ps1   # needs VS 2022 + CMake; clones --recursive upstream
```

License: BSD-2-Clause (pe_unmapper + libpeconv, hasherezade) — see
`bin/LICENSE.pe_unmapper` and `bin/LICENSE.libpeconv`.

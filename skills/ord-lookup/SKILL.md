---
name: ord-lookup
description: "Resolve Windows DLL ordinal imports to exported symbol names from a vendored static database (ws2_32/wsock32, oleaut32). Stripped or by-ordinal imports become readable. Pure static lookup — reads no input file, runs no target."
---

# ord-lookup — Ordinal Import Resolver

Resolve Windows DLL **ordinal imports** to their exported symbol names from a
vendored static database. Stripped or by-ordinal imports (common in packed/malware
binaries and DLLs linked without symbolic info) become readable.

Pure static lookup — reads no sample, runs no target.

## Covered DLLs

| DLL | Entries | Notes |
|---|---|---|
| `ws2_32.dll` | 117 | Winsock; `wsock32` and `mswsock` are aliased here |
| `oleaut32.dll` | 398 | OLE Automation |

## Usage

```bash
# resolve a single ordinal
rekit run ord-lookup ws2_32 1          # accept
rekit run ord-lookup oleaut32.dll 7    # SysStringLen

# dump every ordinal for a DLL
rekit run ord-lookup ws2_32 --all

# list known DLLs
rekit run ord-lookup --list

# JSON output (for agent consumption)
rekit run ord-lookup ws2_32 16 --format json
# {"dll":"ws2_32.dll","ordinal":16,"name":"recv","known":true}
```

When an ordinal isn't in the database, the runner falls back to a synthetic
`ord<N>` name (so an import table is never left with a bare number). `known:false`
in JSON marks these synthetic fallbacks.

## Refactor note

Consolidated from the standalone `ordlookup` package (three Python modules of dict
literals) into one JSON data file + a pure-stdlib runner, dropping the package
overhead and the duplicated `wsock32` copy of the `ws2_32` table.

# pyscylla Python API

Python bindings for `libscylla` — dump, realign, and rebuild IATs of
Windows PE binaries from Python. A programmatic successor to the
classic [Scylla](https://github.com/NtQuery/Scylla) GUI tool, designed
for agent-driven memory dump cleanup workflows.

## External libscylla setup

Rekit intentionally does not commit, download, or build `libscylla`. On Windows,
obtain an architecture-matched DLL from the external
[Scylla project](https://github.com/NtQuery/Scylla) and review its GPL-3.0-only
license. The simplest private setup is the Git-ignored local cache:

```text
skills/pyscylla/bin/libscylla-x64.dll
skills/pyscylla/bin/libscylla-x86.dll
```

The loader selects the DLL matching Python's architecture. You may instead point
`PYSCYLLA_DLL` to an absolute path:

```powershell
$env:PYSCYLLA_DLL = "C:\tools\scylla\libscylla-x64.dll"
bin/rekit doctor pyscylla
```

The DLL may also be available on `PATH` as `libscylla-x64.dll`,
`libscylla-x86.dll`, or `libscylla.dll`.

From the Rekit repository root:

```powershell
bin/rekit run pyscylla version
bin/rekit run pyscylla arch --pid 1234
```

The wrapper configures `PYTHONPATH` and returns JSON. For direct library or module use,
add `skills/pyscylla/scripts` to `PYTHONPATH` first.

## The arch-match rule (read this before anything else)

**`sizeof(DWORD_PTR)` is baked at libscylla compile time.** A 64-bit
libscylla can only correctly process 64-bit targets; a 32-bit libscylla
only 32-bit targets. Matching the wrong arch produces silently corrupt
output (every IAT entry becomes its own import descriptor).

| Target arch | Required Python | Required DLL              |
|-------------|-----------------|---------------------------|
| x64         | 64-bit Python   | `libscylla-x64.dll`       |
| x86         | 32-bit Python   | `libscylla-x86.dll`       |

`pyscylla` selects the DLL based on Python's arch at import time. The
`arch` CLI subcommand and the `check_arch_match` MCP tool surface the
match status so agents can spawn the right Python.

## Three integration patterns

### 1. Direct library use (Python in-process)

```python
import pyscylla as ps

target = ps.process.get_by_name("game.exe")
region = ps.iat.search(target.pid, search_start=target.image_base)
with ps.iat.parse_live(target.pid, region.address, region.size) as lst:
    lst.invalidate_suspect()
    ps.dump.process(target.pid, "game.dmp",
                    image_base=target.image_base,
                    entry_point=target.image_base + target.entry_point_rva)
    ps.iat.fix("game.dmp", "game_fixed.exe", lst)
```

### 2. CLI with JSON output (shell-driven / agent-friendly)

Every subcommand takes `--json`:

```bash
python -m pyscylla arch --pid 1234 --json
# {"pid": 1234, "target_arch": "x64", "python_arch": "x64", "match": true}

python -m pyscylla procs --json | jq '.processes[] | select(.filename=="game.exe")'

python -m pyscylla iat-find --pid 1234 --json
python -m pyscylla fix --pid 1234 --addr 0x405000 --size 0x100 \
    --dump game.dmp --out game_fixed.exe --json
python -m pyscylla rebuild --file game_fixed.exe --json
```

### 3. MCP server

```bash
python -m pyscylla.mcp_server
```

Register it with any MCP client:

```json
{
  "mcpServers": {
    "pyscylla": {
      "command": "python",
      "args": ["-m", "pyscylla.mcp_server"],
      "env": {"PYTHONPATH": "C:/path/to/rekit/skills/pyscylla/scripts"}
    }
  }
}
```

Tools provided: `server_info`, `list_processes`, `find_process`,
`check_arch_match`, `dump_process`, `iat_search`, `iat_parse_live`,
`iat_fix_auto`, `rebuild_file`, `tree_save`, `tree_load`,
`reference_scan`.

## Dump-recovery workflow

Use a debugger or instrumentation tool to find the original entry point and resolve
questionable addresses, then use pyscylla for the mechanical recovery steps:

1. **OEP discovery** — debugger or instrumentation tool.
2. **API resolution** — debugger or module-export data.
3. **This skill (pyscylla)** — given the PID + OEP, does:
   ```
   ps.iat.search(pid, search_start=oep) → IAT region
   ps.iat.parse_live(pid, region.address, region.size) → IatList
   ps.dump.process(pid, ...) → dump file
   ps.iat.fix(dump, fixed.exe, iat_list) → repaired file
   ps.rebuild.file(fixed.exe) → realigned, checksummed
   ```

## CLI reference

```
python -m pyscylla version
python -m pyscylla arch      --pid PID [--json]
python -m pyscylla procs     [--json]
python -m pyscylla dump      (--pid PID | --name NAME) --out FILE [--json]
python -m pyscylla iat-find  --pid PID [--start ADDR] [--advanced] [--json]
python -m pyscylla fix       --pid PID --addr A --size N --dump FILE --out FILE [--json]
python -m pyscylla rebuild   --file FILE [--backup] [--skip-checksum] [--json]
python -m pyscylla tree      --load PATH | --save PATH [--pid PID --addr A --size N]
python -m pyscylla refs      --pid PID --iat-addr A --iat-size N [--patch]
```

## Debugger bridges

`pyscylla.debugger_bridge` exposes a `DebuggerFeed` Protocol with three
adapters:

- **`Win32Feed(pid)`** — `OpenProcess` + `ReadProcessMemory` (no
  debugger required; this is Scylla's native data path)
- **`X64DbgMcpFeed`** — drives x64dbg via MCP tools (bind with
  `feed.bind_tools(MemoryRead=x64dbg_MemoryRead, …)`)
- **`GhidraMcpFeed`** — drives Ghidra via MCP tools (static-only flows)

All three feed the same analysis path. MCP adapters receive their tool callables from
the host through `bind_tools`; pyscylla does not manage debugger lifecycles.

## Obtaining libscylla

Use the upstream project's source and build documentation. Rekit deliberately does not
mirror the source, ship prebuilt DLLs, or automate that third-party build. This keeps
the repository's Apache-2.0 code and the optional GPL dependency visibly separate.

## License

The Rekit-maintained adapter and orchestration code under `skills/pyscylla/scripts/`
is distributed under Rekit's root Apache-2.0 license. The external Scylla/libscylla
project is GPL-3.0-only and is not part of Rekit's tracked files. Ignored local DLLs
remain operator-managed. Operators who obtain, build, use, modify, or redistribute
them are responsible for reviewing and complying with the upstream terms.

# pyscylla

Python bindings for `libscylla` — dump, realign, and rebuild IATs of
Windows PE binaries from Python. A programmatic successor to the
classic [Scylla](https://github.com/NtQuery/Scylla) GUI tool, designed
for agent-driven memory dump cleanup workflows.

## Status

v0.1 — wraps libscylla's C ABI for: process enumeration (with arch
detection), dumping, PE rebuild / realign, IAT search/parse/edit/fix,
XML tree round-trip, and IAT reference scanning.

## Install

The native DLL is vendored as `pyscylla/bin/libscylla-{x86,x64}.dll`.
No compile step is required on the consumer side.

```powershell
cd pyscylla
uv sync
uv run python -m pyscylla version
```

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

### 3. MCP server (best for LLM agents)

```bash
pyscylla-mcp           # or: python -m pyscylla.mcp_server
```

Register with Claude Desktop / opencode / Cursor:

```json
{
  "mcpServers": {
    "pyscylla": {
      "command": "uv",
      "args": ["run", "--directory", "C:/path/to/pyscylla",
               "python", "-m", "pyscylla.mcp_server"]
    }
  }
}
```

Tools provided: `server_info`, `list_processes`, `find_process`,
`check_arch_match`, `dump_process`, `iat_search`, `iat_parse_live`,
`iat_fix_auto`, `rebuild_file`, `tree_save`, `tree_load`,
`reference_scan`.

## Agent workflow (the design target)

This package is built for the pattern where one agent skill is handed
a PID and told to clean up the dump. Other skills handle the harder
reverse-engineering work via [x64dbg-mcp](../x64dbgMCP/) and friends:

1. **OEP discovery** — separate skill, x64dbg-mcp tricks (hw breakpoint
   on `GetCommandLineA`/`W`, walk stack to `_start`)
2. **API resolution** — separate skill, x64dbg-mcp resolves
   suspicious VAs against loaded module exports
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

All three feed the same analysis path so an agent can drive pyscylla
from any of the debuggers already in this workspace.

## Building libscylla

Self-contained: `build-native.ps1` fetches tinyxml automatically then
builds both x86 and x64 Release DLLs.

```powershell
.\build-native.ps1
```

Prerequisites:
- Visual Studio 2022 with the v143 toolset (Desktop C++ workload)
- diStorm (vendored at `Scylla/diStorm/`)
- tinyxml (auto-fetched, or see `Scylla/tinyxml/README`)
- **ATL and WTL are NOT required** for libscylla

## License

GPL-3.0-only — inherited from the upstream Scylla project.

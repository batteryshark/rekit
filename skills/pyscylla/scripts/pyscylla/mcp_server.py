"""MCP server exposing pyscylla operations as tools.

Run via stdio transport:

    python -m pyscylla.mcp_server

Or register with Claude Desktop / opencode / Cursor by adding to the
appropriate MCP config:

    {
      "mcpServers": {
        "pyscylla": {
          "command": "uv",
          "args": ["run", "--directory", "<path-to-pyscylla>",
                   "python", "-m", "pyscylla.mcp_server"]
        }
      }
    }

Arch note: a 64-bit Python can only load libscylla-x64.dll and only
correctly operates on 64-bit targets. For 32-bit targets, spawn this
server under 32-bit Python. The ``arch`` tool surfaces the match
status so the agent can branch.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

try:
    from mcp.server.fastmcp import FastMCP
except ImportError as exc:  # pragma: no cover
    raise SystemExit(
        "The 'mcp' package is required. Install with: "
        "uv sync --extra debugger-bridge"
    ) from exc

import pyscylla as ps

mcp = FastMCP("pyscylla")


def _arch_match() -> dict[str, Any]:
    py_arch = "x64" if sys.maxsize > 2**32 else "x86"
    try:
        v = ps.version()
    except ps.DllNotFoundError as e:
        return {"python_arch": py_arch, "loaded": False, "error": str(e)}
    return {
        "python_arch": py_arch,
        "loaded": True,
        "libscylla_version": v,
        "libscylla_dword": f"0x{ps.version_dword():08x}",
    }


# ---------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------


@mcp.tool()
def server_info() -> dict:
    """Report Python arch and loaded libscylla version. Call this first
    to determine whether the server can operate on a given target arch.
    """
    return _arch_match()


@mcp.tool()
def list_processes() -> list[dict]:
    """Enumerate all visible processes. Returns pid, arch, image_base,
    filename for each. Use to find the PID of a target by name."""
    procs = ps.process.list_processes()
    return [
        {
            "pid": p.pid,
            "arch": p.arch.name.lower(),
            "image_base": p.image_base,
            "image_size": p.image_size,
            "entry_point_rva": p.entry_point_rva,
            "filename": p.filename,
            "full_path": p.full_path,
        }
        for p in procs
    ]


@mcp.tool()
def find_process(pid: int | None = None, name: str | None = None) -> dict:
    """Look up a single process by PID or by case-insensitive filename.
    Returns the same fields as list_processes for one process.
    """
    if pid is not None:
        p = ps.process.get_by_pid(pid)
    elif name is not None:
        p = ps.process.get_by_name(name)
    else:
        raise ValueError("provide pid or name")
    return {
        "pid": p.pid,
        "arch": p.arch.name.lower(),
        "image_base": p.image_base,
        "image_size": p.image_size,
        "entry_point_rva": p.entry_point_rva,
        "filename": p.filename,
        "full_path": p.full_path,
    }


@mcp.tool()
def check_arch_match(pid: int) -> dict:
    """Verify the target's arch matches this server's Python arch.
    Returns {target_arch, python_arch, match}. If match is false, the
    agent should spawn a server of the other arch before continuing."""
    info = ps.process.get_by_pid(pid)
    py_arch = "x64" if sys.maxsize > 2**32 else "x86"
    tgt = info.arch.name.lower()
    return {
        "pid": pid,
        "target_arch": tgt,
        "python_arch": py_arch,
        "match": tgt == py_arch,
    }


@mcp.tool()
def dump_process(
    pid: int,
    save_path: str,
    entry_point: int | None = None,
    file_to_dump: str | None = None,
) -> dict:
    """Dump a live process's primary image to save_path. entry_point is
    an absolute VA; if omitted, image_base + entry_point_rva is used.
    """
    info = ps.process.get_by_pid(pid)
    ep = entry_point if entry_point is not None else info.image_base + info.entry_point_rva
    ps.dump.process(
        pid, save_path,
        image_base=info.image_base,
        entry_point=ep,
        file_to_dump=file_to_dump,
    )
    out = Path(save_path)
    return {"ok": True, "pid": pid, "out": save_path,
            "size": out.stat().st_size if out.exists() else 0}


@mcp.tool()
def iat_search(
    pid: int,
    search_start: int | None = None,
    advanced: bool = False,
) -> dict:
    """Find the IAT in a live process. search_start defaults to image
    base. Returns the IAT region {address, size}."""
    info = ps.process.get_by_pid(pid)
    start = search_start if search_start is not None else info.image_base
    try:
        region = ps.iat.search(pid, search_start=start, advanced=advanced)
    except ps.IatNotFoundError as e:
        return {"ok": False, "error": str(e), "status": "iat_not_found"}
    return {"ok": True, "address": region.address, "size": region.size}


@mcp.tool()
def iat_parse_live(pid: int, iat_address: int, iat_size: int) -> dict:
    """Parse the IAT of a live process and return all modules + thunks.
    Resolution uses the target's loaded modules."""
    with ps.iat.parse_live(pid, iat_address, iat_size) as lst:
        modules = []
        for m_idx in range(lst.module_count):
            m = lst.get_module(m_idx)
            modules.append({
                "index": m_idx,
                "name": m.module_name,
                "first_thunk": m.first_thunk,
                "thunks": [
                    {
                        "name": t.name,
                        "module": t.module_name,
                        "va": t.va,
                        "rva": t.rva,
                        "ordinal": t.ordinal,
                        "valid": t.valid,
                        "suspect": t.suspect,
                    }
                    for t in m.thunks
                ],
            })
        return {
            "ok": True,
            "module_count": lst.module_count,
            "total_thunks": lst.total_thunk_count,
            "invalid_thunks": lst.invalid_thunk_count,
            "suspect_thunks": lst.suspect_thunk_count,
            "modules": modules,
        }


@mcp.tool()
def iat_fix_auto(
    pid: int,
    iat_address: int,
    iat_size: int,
    dump_file: str,
    out_file: str,
) -> dict:
    """One-shot: parse the live IAT of pid and write a fixed dump to
    out_file. Equivalent to Scylla's "Fix Dump" button."""
    ps.iat.fix_auto(
        pid,
        iat_address=iat_address,
        iat_size=iat_size,
        dump_file=dump_file,
        out_file=out_file,
    )
    out = Path(out_file)
    return {"ok": True, "dump": dump_file, "out": out_file,
            "size": out.stat().st_size if out.exists() else 0}


@mcp.tool()
def rebuild_file(
    file_path: str,
    remove_dos_stub: bool = False,
    update_pe_header_checksum: bool = True,
    create_backup: bool = False,
) -> dict:
    """Realign / fix a dumped PE file in place: file alignment, DOS stub
    removal, PE header checksum update."""
    ps.rebuild.file(
        file_path,
        remove_dos_stub=remove_dos_stub,
        update_pe_header_checksum=update_pe_header_checksum,
        create_backup=create_backup,
    )
    return {"ok": True, "file": file_path}


@mcp.tool()
def tree_save(
    path: str,
    pid: int,
    iat_address: int,
    iat_size: int,
    oep: int | None = None,
    image_base: int | None = None,
) -> dict:
    """Save a Scylla-GUI-compatible XML tree from a live process."""
    info = ps.process.get_by_pid(pid) if image_base is None else None
    if image_base is None:
        image_base = info.image_base
    with ps.iat.parse_live(pid, iat_address, iat_size) as lst:
        ps.tree.save(
            path, lst,
            meta=ps.TreeMeta(
                address_oep=oep or 0,
                address_iat=iat_address,
                size_iat=iat_size,
                image_base=image_base,
            ),
        )
    return {"ok": True, "path": path,
            "size": Path(path).stat().st_size if Path(path).exists() else 0}


@mcp.tool()
def tree_load(path: str) -> dict:
    """Load a Scylla XML tree file. Returns meta + module list."""
    lst, meta = ps.tree.load(path)
    with lst:
        modules = []
        for m_idx in range(lst.module_count):
            m = lst.get_module(m_idx)
            modules.append({
                "name": m.module_name,
                "first_thunk": m.first_thunk,
                "thunk_count": len(m.thunks),
            })
        return {
            "ok": True,
            "meta": {
                "address_oep": meta.address_oep,
                "address_iat": meta.address_iat,
                "size_iat": meta.size_iat,
                "image_base": meta.image_base,
                "process_name": meta.process_name,
            },
            "modules": modules,
        }


@mcp.tool()
def reference_scan(
    pid: int,
    iat_address: int,
    iat_size: int,
    scan_direct: bool = True,
    scan_normal: bool = True,
) -> dict:
    """Scan a live process for IAT references — the 'trace bad imports'
    engine. Returns counts; the direct_apis_not_in_iat count is the
    number of unresolved direct imports."""
    info = ps.process.get_by_pid(pid)
    with ps.reference_scan.scan_live(
        pid,
        image_base=info.image_base,
        image_size=info.image_size,
        iat_address=iat_address,
        iat_size=iat_size,
        scan_direct=scan_direct,
        scan_normal=scan_normal,
    ) as scan:
        return {
            "ok": True,
            "direct_count": scan.direct_count,
            "direct_unique_count": scan.direct_unique_count,
            "direct_apis_not_in_iat_count": scan.direct_apis_not_in_iat_count,
            "normal_count": scan.normal_count,
        }


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()

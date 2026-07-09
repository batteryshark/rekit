"""Command-line interface: ``python -m pyscylla <subcommand>``.

Mirrors ScyllaTest.exe plus the GUI hotkeys. Each subcommand maps to
one pyscylla module. ``--json`` switches the output to a single JSON
object on stdout (one per subcommand) for agent / programmatic use.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _emit(args: argparse.Namespace, payload: dict) -> int:
    """Print payload as JSON if --json, otherwise pretty-print."""
    if getattr(args, "json", False):
        print(json.dumps(payload, default=str))
    else:
        for k, v in payload.items():
            if isinstance(v, list):
                for row in v:
                    print(f"  {row}")
            else:
                print(f"{k}: {v}")
    return int(payload.get("_exit", 0))


def _cmd_version(args: argparse.Namespace) -> int:
    from ._native import get_native

    nat = get_native()
    v_a = nat.ScyllaVersionInformationA().decode()
    v_d = nat.ScyllaVersionInformationDword()
    if getattr(args, "json", False):
        return _emit(args, {"version": v_a, "dword": f"0x{v_d:08x}"})
    print(v_a)
    print(f"DWORD: 0x{v_d:08x}")
    return 0


def _cmd_arch(args: argparse.Namespace) -> int:
    """Print just the target's architecture — useful for agents to
    decide which Python to spawn."""
    import sys

    from . import process

    info = process.get_by_pid(args.pid)
    py_arch = "x64" if sys.maxsize > 2**32 else "x86"
    if getattr(args, "json", False):
        return _emit(args, {
            "pid": info.pid,
            "target_arch": info.arch.name.lower(),
            "python_arch": py_arch,
            "match": (info.arch.name.lower() == py_arch),
        })
    print(f"target={info.arch.name.lower()}  python={py_arch}  "
          f"match={'OK' if info.arch.name.lower() == py_arch else 'MISMATCH'}")
    return 0


def _cmd_procs(args: argparse.Namespace) -> int:
    from . import process

    procs = process.list_processes()
    if getattr(args, "json", False):
        return _emit(args, {"processes": [
            {"pid": p.pid, "arch": p.arch.name.lower(),
             "image_base": f"0x{p.image_base:x}", "filename": p.filename}
            for p in procs
        ]})
    for p in procs:
        print(f"{p.pid:>8}  arch={p.arch.name:<7}  {p.image_base:#011x}  {p.filename}")
    return 0


def _cmd_dump(args: argparse.Namespace) -> int:
    from . import dump, process

    p = process.get_by_pid(args.pid) if args.pid else process.get_by_name(args.name)
    ep = args.entry_point if args.entry_point is not None else p.image_base + p.entry_point_rva
    dump.process(
        p.pid,
        args.out,
        image_base=p.image_base,
        entry_point=ep,
        file_to_dump=args.file,
    )
    return _emit(args, {
        "ok": True,
        "pid": p.pid,
        "out": str(args.out),
        "size": args.out.stat().st_size if args.out.exists() else 0,
    }) if getattr(args, "json", False) else (print(f"Dumped PID {p.pid} -> {args.out}") or 0)


def _cmd_iat_find(args: argparse.Namespace) -> int:
    from . import iat, process

    p = process.get_by_pid(args.pid)
    start = args.start if args.start is not None else p.image_base
    try:
        region = iat.search(p.pid, search_start=start, advanced=args.advanced)
    except Exception as exc:
        if getattr(args, "json", False):
            return _emit(args, {"ok": False, "error": str(exc), "_exit": 1})
        raise
    return _emit(args, {
        "ok": True,
        "address": f"0x{region.address:x}",
        "size": f"0x{region.size:x}",
    }) if getattr(args, "json", False) else (
        print(f"iat_address=0x{region.address:x}  iat_size=0x{region.size:x}") or 0
    )


def _cmd_fix(args: argparse.Namespace) -> int:
    from . import iat

    iat.fix_auto(
        args.pid,
        iat_address=args.addr,
        iat_size=args.size,
        dump_file=args.dump,
        out_file=args.out,
    )
    return _emit(args, {
        "ok": True, "dump": str(args.dump), "out": str(args.out),
    }) if getattr(args, "json", False) else (
        print(f"Fixed {args.dump} -> {args.out}") or 0
    )


def _cmd_rebuild(args: argparse.Namespace) -> int:
    from . import rebuild

    rebuild.file(
        args.file,
        remove_dos_stub=not args.keep_dos_stub,
        update_pe_header_checksum=not args.skip_checksum,
        create_backup=args.backup,
    )
    return _emit(args, {"ok": True, "file": str(args.file)}) if getattr(args, "json", False) else (
        print(f"Rebuilt {args.file}") or 0
    )


def _cmd_tree(args: argparse.Namespace) -> int:
    from . import iat, tree
    from .types import TreeMeta

    if args.load:
        lst, meta = tree.load(args.load)
        with lst:
            print(f"Loaded {args.load}: {lst.module_count} modules, "
                  f"{lst.total_thunk_count} thunks, "
                  f"{lst.invalid_thunk_count} invalid")
            print(f"  oep=0x{meta.address_oep:x}  iat=0x{meta.address_iat:x}  size=0x{meta.size_iat:x}")
            if args.json:
                _dump_tree_json(lst, meta)
    elif args.save:
        # Read from stdin or a source PID
        if not args.pid:
            print("--pid required with --save", file=sys.stderr)
            return 2
        if not (args.addr and args.size):
            print("--addr and --size required with --save", file=sys.stderr)
            return 2
        meta = TreeMeta(
            address_oep=args.oep or 0,
            address_iat=args.addr,
            size_iat=args.size,
        )
        with iat.parse_live(args.pid, args.addr, args.size) as lst:
            tree.save(args.save, lst, meta=meta)
        print(f"Saved tree {args.save}")
    return 0


def _dump_tree_json(lst, meta) -> None:
    obj = {
        "meta": {
            "oep": meta.address_oep,
            "iat": meta.address_iat,
            "size": meta.size_iat,
        },
        "modules": [
            {
                "name": m.module_name,
                "first_thunk": m.first_thunk,
                "thunks": [
                    {
                        "name": t.name,
                        "module": t.module_name,
                        "valid": t.valid,
                        "suspect": t.suspect,
                        "va": t.va,
                    }
                    for t in m.thunks
                ],
            }
            for m in lst.modules()
        ],
    }
    print(json.dumps(obj, indent=2))


def _cmd_refs(args: argparse.Namespace) -> int:
    from . import process, reference_scan

    p = process.get_by_pid(args.pid)
    with reference_scan.scan_live(
        p.pid,
        image_base=p.image_base,
        image_size=p.image_size,
        iat_address=args.iat_addr,
        iat_size=args.iat_size,
        scan_direct=not args.normal_only,
        scan_normal=True,
    ) as scan:
        print(f"direct_count={scan.direct_count}  unique={scan.direct_unique_count}  "
              f"normal={scan.normal_count}  bad={scan.direct_apis_not_in_iat_count}")
        if args.patch:
            scan.patch_direct_memory()
            print("Patched.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="pyscylla", description="libscylla Python bindings")
    sub = p.add_subparsers(dest="cmd", required=True)

    # Global --json available on every subcommand
    json_kwargs = {"action": "store_true", "help": "emit JSON for agent consumption"}

    sub.add_parser("version", help="print libscylla version").set_defaults(func=_cmd_version)

    a = sub.add_parser("arch", help="print target arch + Python arch (for agent branching)")
    a.add_argument("--pid", type=int, required=True)
    a.add_argument("--json", **json_kwargs)
    a.set_defaults(func=_cmd_arch)

    pe = sub.add_parser("procs", help="list processes")
    pe.add_argument("--json", **json_kwargs)
    pe.set_defaults(func=_cmd_procs)

    d = sub.add_parser("dump", help="dump a live process")
    g = d.add_mutually_exclusive_group(required=True)
    g.add_argument("--pid", type=int)
    g.add_argument("--name", type=str)
    d.add_argument("--out", type=Path, required=True)
    d.add_argument("--file", type=Path, help="on-disk file to parse PE layout from")
    d.add_argument("--entry-point", type=lambda s: int(s, 0))
    d.add_argument("--json", **json_kwargs)
    d.set_defaults(func=_cmd_dump)

    f = sub.add_parser("iat-find", help="find the IAT in a live process")
    f.add_argument("--pid", type=int, required=True)
    f.add_argument("--start", type=lambda s: int(s, 0))
    f.add_argument("--advanced", action="store_true")
    f.add_argument("--json", **json_kwargs)
    f.set_defaults(func=_cmd_iat_find)

    fix = sub.add_parser("fix", help="dump + fix IAT (auto mode by default)")
    fix.add_argument("--pid", type=int, required=True)
    fix.add_argument("--addr", type=lambda s: int(s, 0), required=True)
    fix.add_argument("--size", type=lambda s: int(s, 0), required=True)
    fix.add_argument("--dump", type=Path, required=True)
    fix.add_argument("--out", type=Path, required=True)
    fix.add_argument("--json", **json_kwargs)
    fix.set_defaults(func=_cmd_fix)

    rb = sub.add_parser("rebuild", help="realign a dumped PE file")
    rb.add_argument("--file", type=Path, required=True)
    rb.add_argument("--keep-dos-stub", action="store_true")
    rb.add_argument("--skip-checksum", action="store_true")
    rb.add_argument("--backup", action="store_true")
    rb.add_argument("--json", **json_kwargs)
    rb.set_defaults(func=_cmd_rebuild)

    tr = sub.add_parser("tree", help="XML tree load/save")
    tr.add_argument("--load", type=Path)
    tr.add_argument("--save", type=Path)
    tr.add_argument("--pid", type=int)
    tr.add_argument("--addr", type=lambda s: int(s, 0))
    tr.add_argument("--size", type=lambda s: int(s, 0))
    tr.add_argument("--oep", type=lambda s: int(s, 0))
    tr.add_argument("--json", action="store_true")
    tr.set_defaults(func=_cmd_tree)

    rs = sub.add_parser("refs", help="scan for IAT references (trace bad imports)")
    rs.add_argument("--pid", type=int, required=True)
    rs.add_argument("--iat-addr", type=lambda s: int(s, 0), required=True)
    rs.add_argument("--iat-size", type=lambda s: int(s, 0), required=True)
    rs.add_argument("--normal-only", action="store_true")
    rs.add_argument("--patch", action="store_true")
    rs.add_argument("--json", action="store_true")
    rs.set_defaults(func=_cmd_refs)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except Exception as exc:
        from .errors import DllNotFoundError

        if isinstance(exc, DllNotFoundError):
            print(f"error: {exc}", file=sys.stderr)
            print(
                "hint: build libscylla first — see pyscylla/build-native.ps1 "
                "or the 'Building libscylla' section of the README.",
                file=sys.stderr,
            )
            return 127
        raise


if __name__ == "__main__":
    sys.exit(main())

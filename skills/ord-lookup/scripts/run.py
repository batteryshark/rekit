"""ord-lookup — resolve Windows DLL ordinal imports to symbol names.

Static lookup against a vendored ordinal→name database (ws2_32, oleaut32, and
aliases). Many DLLs are imported by ordinal only when stripped; this resolves
those ordinals to their exported symbol names so an import table becomes readable.

    python3 run.py <dll> <ordinal> [--format json|text]
    python3 run.py --list            # list known DLLs
"""

from __future__ import annotations

import argparse
import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_DATA = os.path.join(os.path.dirname(_HERE), "bin", "ordinals.json")

# Pure aliases — resolve before lookup.
_ALIASES = {
    "wsock32.dll": "ws2_32.dll",
    "mswsock.dll": "ws2_32.dll",
}


def _load() -> dict:
    with open(_DATA) as f:
        return json.load(f)


def _normalize(libname: str) -> str:
    name = libname.lower().strip()
    if not name.endswith(".dll"):
        name += ".dll"
    return _ALIASES.get(name, name)


def lookup(libname: str, ordinal: int, make_name: bool = False) -> str | None:
    db = _load()
    names = db.get(_normalize(libname))
    if names is None:
        return f"ord{ordinal}" if make_name else None
    return names.get(str(ordinal)) or (f"ord{ordinal}" if make_name else None)


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="ord-lookup")
    p.add_argument("dll", nargs="?", help="DLL name (e.g. ws2_32, oleaut32.dll)")
    p.add_argument("ordinal", nargs="?", type=int, help="ordinal number to resolve")
    p.add_argument("--list", action="store_true", help="list known DLLs and exit")
    p.add_argument("--all", action="store_true", help="dump every ordinal for the DLL")
    p.add_argument("--format", choices=["text", "json"], default="text")
    a = p.parse_args(argv[1:])

    db = _load()

    if a.list:
        rows = {dll: len(entries) for dll, entries in db.items()}
        if a.format == "json":
            print(json.dumps({"dlls": rows}))
        else:
            for dll, n in sorted(rows.items()):
                print(f"{dll:<16} {n} ordinals")
        return 0

    if not a.dll:
        p.error("dll is required (or use --list)")

    norm = _normalize(a.dll)
    if a.all:
        entries = db.get(norm, {})
        if a.format == "json":
            print(json.dumps({"dll": norm, "ordinals": entries}))
        else:
            for o in sorted(entries, key=int):
                print(f"{int(o):>4}  {entries[o]}")
        return 0

    if a.ordinal is None:
        p.error("ordinal is required (or use --all / --list)")

    name = lookup(a.dll, a.ordinal, make_name=True)
    if a.format == "json":
        print(json.dumps({"dll": norm, "ordinal": a.ordinal,
                          "name": name, "known": name is not None and not name.startswith("ord")}))
    else:
        print(name or "(unknown)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

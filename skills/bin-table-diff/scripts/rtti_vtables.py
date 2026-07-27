#!/usr/bin/env python3
"""Recover C++ class names and vtable layouts from a stripped Itanium-ABI binary.

RTTI survives stripping: `type_info` records live in .rodata as data, not symbols.
So a binary with no symbol table still states, in its own bytes, what its
polymorphic classes are called and which function occupies each vtable slot.

That makes it ground truth for checking inferred names. A slot in `CFoo`'s vtable
holds a `CFoo` virtual method — if a name assigned there belongs to another class
or to a library, the name is wrong, and no amount of plausibility fixes it.

    rtti_vtables.py <binary> [--json]
    rtti_vtables.py <binary> --check names.json

`--check` takes {address: name} (hex or decimal keys) and reports, per vtable
slot, whether the assigned name agrees with the slot's owning class.

Layout (Itanium C++ ABI, 32-bit):
    vtable:  [offset-to-top][typeinfo*][vfunc0][vfunc1]...
    typeinfo: [vptr][name*] (+ [base*] for single inheritance)
    A negative offset-to-top starts a secondary vtable for another base.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from run import Image, TableError  # noqa: E402

# A type_info name is a mangled type: "11CPlayEngine", or "N5boost..." for
# namespaced ones. Only the simple length-prefixed form is decoded here.
LENGTH_PREFIXED = re.compile(r"^(\d+)(.+)$")


def demangle_simple(name: str) -> str | None:
    match = LENGTH_PREFIXED.match(name)
    if not match:
        return None
    length, body = int(match.group(1)), match.group(2)
    return body[:length] if len(body) >= length else None


class Binary:
    def __init__(self, path: str):
        self.image = Image(path)
        self.data = self.image.data

    def word(self, vaddr: int) -> int | None:
        off = self.image.to_offset(vaddr)
        if off is None or off + 4 > len(self.data):
            return None
        return struct.unpack_from("<I", self.data, off)[0]

    def string(self, vaddr: int, limit: int = 256) -> str | None:
        off = self.image.to_offset(vaddr)
        if off is None:
            return None
        end = self.data.find(b"\0", off, off + limit)
        if end <= off:
            return None
        return self.data[off:end].decode("latin-1")

    def is_code(self, vaddr: int) -> bool:
        """Crude executable-range test: inside a segment and not obviously data."""
        return self.image.to_offset(vaddr) is not None


def find_typeinfos(binary: Binary) -> dict:
    """vaddr -> class name, for every type_info record we can decode."""
    found = {}
    for vaddr, offset, size in binary.image.segments:
        for pos in range(offset, offset + size - 8, 4):
            candidate = vaddr + (pos - offset)
            name_ptr = binary.word(candidate + 4)
            if not name_ptr:
                continue
            raw = binary.string(name_ptr, 64)
            if not raw:
                continue
            decoded = demangle_simple(raw)
            if decoded and len(decoded) >= 3 and decoded[0].isupper():
                # A real type_info also has a vptr into a __cxxabi vtable.
                if binary.word(candidate):
                    found[candidate] = decoded
    return found


def find_vtables(binary: Binary, typeinfos: dict, max_slots: int = 64) -> list:
    """Locate vtables by their [offset-to-top][typeinfo*] prologue."""
    tables = []
    for vaddr, offset, size in binary.image.segments:
        for pos in range(offset, offset + size - 8, 4):
            here = vaddr + (pos - offset)
            ti = binary.word(here + 4)
            if ti not in typeinfos:
                continue
            top = binary.word(here)
            # offset-to-top is 0 for a primary vtable, negative for a secondary.
            if top is None or (top != 0 and top < 0x80000000):
                continue
            slots = []
            slot = here + 8
            while len(slots) < max_slots:
                value = binary.word(slot)
                if not value or not binary.is_code(value):
                    break
                # another vtable prologue starts here -> stop
                if binary.word(slot + 4) in typeinfos:
                    break
                slots.append(value)
                slot += 4
            if slots:
                tables.append({
                    "vtable": here,
                    "class": typeinfos[ti],
                    "typeinfo": ti,
                    "secondary": top != 0,
                    "slots": slots,
                })
    return tables


def load_names(path: str) -> dict:
    with open(path, encoding="utf-8") as handle:
        raw = json.load(handle)
    names = {}
    for key, value in (raw.items() if isinstance(raw, dict) else []):
        text = str(key).strip()
        try:
            # Addresses are hex. Deciding base from isdigit() silently reads
            # "8062820" as decimal, so every address whose hex form has no
            # letters lands on the wrong key and looks unnamed.
            names[int(text, 16) if not text.startswith("0d") else int(text[2:])] = value
        except ValueError:
            continue
    return names


def check(tables: list, names: dict) -> dict:
    """Compare assigned names against the class that owns each vtable slot."""
    agree, mismatch, unnamed = [], [], []
    for table in tables:
        owner = table["class"]
        for index, addr in enumerate(table["slots"]):
            assigned = names.get(addr)
            record = {"class": owner, "slot": index, "address": f"{addr:08x}",
                      "name": assigned, "vtable": f"{table['vtable']:08x}",
                      "secondary": table["secondary"]}
            # A mangled symbol (_ZN<len><Class>...) names its class too, and IDA
            # stores destructors that way so it can demangle them for display.
            mangled = re.match(r"^_ZN(\d+)([A-Za-z_]\w*)", assigned or "")
            if mangled and len(mangled.group(2)) >= int(mangled.group(1)):
                assigned = mangled.group(2)[:int(mangled.group(1))] + "::"

            if not assigned or re.match(r"^(sub|nullsub|loc|j_)_", assigned):
                unnamed.append(record)
            elif "::" in assigned:
                if assigned.split("::")[0].split("<")[0] == owner:
                    agree.append(record)
                else:
                    mismatch.append(record)
            else:
                # a bare name in a class vtable: not disproof, but not corroborated
                mismatch.append(record)
    return {"agree": agree, "mismatch": mismatch, "unnamed": unnamed}


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="rtti-vtables")
    parser.add_argument("binary")
    parser.add_argument("--check", help="JSON {address: name} to verify")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv[1:])

    try:
        binary = Binary(args.binary)
    except TableError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}))
        return 1

    typeinfos = find_typeinfos(binary)
    tables = find_vtables(binary, typeinfos)
    classes = sorted({t["class"] for t in tables})

    if args.check:
        result = check(tables, load_names(args.check))
        summary = {"ok": True, "classes": len(classes), "vtables": len(tables),
                   "agree": len(result["agree"]),
                   "mismatch": len(result["mismatch"]),
                   "unnamed": len(result["unnamed"])}
        if args.json:
            print(json.dumps({**summary, "detail": result}, indent=2))
        else:
            print(f"classes {summary['classes']}  vtables {summary['vtables']}  "
                  f"slots: agree {summary['agree']}  MISMATCH {summary['mismatch']}  "
                  f"unnamed {summary['unnamed']}")
            for m in result["mismatch"]:
                print(f"  MISMATCH {m['class']} vtable 0x{m['vtable']} slot {m['slot']}"
                      f"  0x{m['address']} named {m['name']!r}")
        return 0

    if args.json:
        print(json.dumps({"ok": True, "classes": classes, "vtables": tables}, indent=2))
    else:
        print(f"{len(classes)} polymorphic classes, {len(tables)} vtables")
        for table in tables:
            kind = "secondary" if table["secondary"] else "primary"
            print(f"  {table['class']:<22} 0x{table['vtable']:08x} {kind:<9} "
                  f"{len(table['slots'])} slots")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

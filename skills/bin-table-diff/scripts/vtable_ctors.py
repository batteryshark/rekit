#!/usr/bin/env python3
"""Identify constructors by the vtable pointer they install.

Every constructor of a polymorphic class writes that class's vtable pointer into
the object. The value written is the address of the vtable's first virtual slot
(`vtable + 8` in the Itanium ABI, past offset-to-top and typeinfo), and it appears
in the code as a literal immediate. So scanning for that immediate finds the
functions that construct the class — with certainty about *which* class, because
the constant is unique to it.

Destructors install it too (they reset the vptr while unwinding), so slots already
known to be destructors from the vtable are excluded.

    vtable_ctors.py <binary> --functions funcs.json [--names names.json]

`funcs.json` is {hex_address: size}, used to map an immediate's position back to
its containing function.
"""

from __future__ import annotations

import argparse
import bisect
import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from rtti_vtables import Binary, find_typeinfos, find_vtables, load_names  # noqa: E402


def containing_function(starts: list, sizes: dict, vaddr: int) -> int | None:
    index = bisect.bisect_right(starts, vaddr) - 1
    if index < 0:
        return None
    start = starts[index]
    return start if vaddr < start + sizes.get(start, 0) else None


def find_vptr_writers(binary: Binary, tables: list, starts: list,
                      sizes: dict) -> dict:
    """class -> {function address: number of vptr installs}."""
    # The pointer stored in objects targets the first virtual slot.
    targets = {}
    for table in tables:
        if not table["secondary"]:
            targets.setdefault(table["vtable"] + 8, table["class"])

    hits: dict = {}
    for seg_vaddr, seg_off, seg_size in binary.image.segments:
        data = binary.data
        for pos in range(seg_off, seg_off + seg_size - 4):
            value = struct.unpack_from("<I", data, pos)[0]
            owner = targets.get(value)
            if not owner:
                continue
            va = seg_vaddr + (pos - seg_off)
            func = containing_function(starts, sizes, va)
            if func is None:
                continue
            hits.setdefault(owner, {}).setdefault(func, 0)
            hits[owner][func] += 1
    return hits


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="vtable-ctors")
    parser.add_argument("binary")
    parser.add_argument("--functions", required=True)
    parser.add_argument("--names")
    parser.add_argument("--out")
    args = parser.parse_args(argv[1:])

    binary = Binary(args.binary)
    tables = find_vtables(binary, find_typeinfos(binary))
    sizes = {int(k, 16): v for k, v in json.load(open(args.functions)).items()}
    starts = sorted(sizes)
    names = load_names(args.names) if args.names else {}

    # Functions already accounted for as virtual methods of their class.
    slot_owner = {}
    for table in tables:
        for addr in table["slots"]:
            slot_owner.setdefault(addr, table["class"])

    hits = find_vptr_writers(binary, tables, starts, sizes)
    proposals = []
    for owner, funcs in sorted(hits.items()):
        for func, count in sorted(funcs.items()):
            if slot_owner.get(func) == owner:
                continue  # a destructor of this class: already named
            current = names.get(func, "")
            proposals.append({"address": f"{func:08x}", "class": owner,
                              "installs": count, "current": current,
                              "size": sizes.get(func, 0)})

    # A function installing several different classes' vptrs is a factory or an
    # inlined caller, not a constructor — report it but do not rename it.
    by_func: dict = {}
    for p in proposals:
        by_func.setdefault(p["address"], []).append(p["class"])
    # Installing a class's vptr only means an object of that class is built
    # somewhere in the function. With inlining that includes every screen that
    # merely embeds a small helper — CIncrementer showed up inside half the
    # codebase. The inference only holds for a function that is *nothing but* a
    # constructor: tiny, single-class, and not already identified.
    PLACEHOLDER = ("inline_getter_at_", "thunk_to_", "sub_", "nullsub_", "")
    single = [p for p in proposals
              if len(by_func[p["address"]]) == 1
              and p["size"] <= 64
              and (p["current"].startswith(PLACEHOLDER[:-1]) or not p["current"])]
    multi = sorted({p["address"] for p in proposals if len(by_func[p["address"]]) > 1})

    print(f"classes with vptr installs: {len(hits)}   "
          f"single-class functions (constructor candidates): {len(single)}   "
          f"multi-class functions (skipped): {len(multi)}")
    for p in single:
        suffix = "" if p["current"].startswith(f"{p['class']}::") else "  <-- rename"
        print(f"  {p['class']:<18} 0x{p['address']}  {p['size']:>5}B  "
              f"installs {p['installs']}  now: {p['current'][:34]:<34}{suffix}")

    if args.out:
        lines = "\n".join(
            f"    (0x{p['address']}, {p['class']}::{p['class']}!r),"
            for p in single)
        json.dump(single, open(args.out, "w"), indent=2)
        print(f"\nwrote {len(single)} candidates to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

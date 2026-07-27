#!/usr/bin/env python3
"""Locate a record table in a binary using on-disk asset filenames as ground truth.

`bin-table-diff` finds tables by structure alone — a run of records at a fixed
stride sharing a column of string pointers. That fails when a record leads with
integer fields, or when smaller nearby tables score higher.

When the shipped assets are available, they beat the heuristic outright: the
filenames *are* the key column. Searching for a fixed-stride run of those exact
ids finds the table in one pass, and the proportion of ids that resolve to real
files is a validation the structural method cannot offer.

    asset_table.py <binary> --assets DIR --pattern '(\\d+)\\.STX'

Ids are matched both as decimal and as hex-of-the-digits: Pump It Up stores
`102.STX` as 0x102, so a decimal-only search silently truncates the table.
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


def asset_ids(directory: str, pattern: str) -> tuple[set, set]:
    """Return (decimal ids, hex-of-digits ids) drawn from filenames."""
    rx = re.compile(pattern, re.I)
    decimal, as_hex = set(), set()
    for name in os.listdir(directory):
        match = rx.match(name)
        if not match:
            continue
        digits = match.group(1)
        decimal.add(int(digits, 10))
        try:
            as_hex.add(int(digits, 16))
        except ValueError:
            pass
    return decimal, as_hex


def find_runs(image: Image, ids: set, min_records: int, strides: range,
              id_field: int) -> list:
    data = image.data
    def value(off):
        return struct.unpack_from("<I", data, off)[0] if 0 <= off <= len(data) - 4 else None
    def is_id(off):
        return value(off) in ids
    runs = []
    for stride in strides:
        off = 0
        limit = len(data) - stride
        while off < limit:
            here = off + id_field
            if is_id(here) and not is_id(here - stride):
                count, cursor = 0, here
                while is_id(cursor):
                    count += 1
                    cursor += stride
                if count >= min_records:
                    seen = {value(here + k * stride) for k in range(count)}
                    runs.append({"records": count, "stride": stride,
                                 "offset": off, "idField": id_field,
                                 "distinct": len(seen)})
            off += 4
    # Rank by DISTINCT ids, not record count: a long run of one repeated value
    # scores highly on count while being no table at all. A real key column is
    # near-unique, so distinctness is the signal.
    runs.sort(key=lambda r: (-r["distinct"], -r["records"]))
    return runs


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="asset-table")
    parser.add_argument("binary")
    parser.add_argument("--assets", required=True)
    parser.add_argument("--pattern", default=r"(\d+)\.STX")
    parser.add_argument("--min-records", type=int, default=8)
    parser.add_argument("--max-stride", type=int, default=300)
    parser.add_argument("--out")
    args = parser.parse_args(argv[1:])

    try:
        image = Image(args.binary)
    except TableError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}))
        return 1

    decimal, as_hex = asset_ids(args.assets, args.pattern)
    print(f"assets: {len(decimal)} ids from {args.assets}")

    best = None
    for label, ids in (("hex-of-digits", as_hex), ("decimal", decimal)):
        for id_field in (0, 4, 8):
            runs = find_runs(image, ids, args.min_records,
                             range(8, args.max_stride + 1, 4), id_field)
            if runs and (best is None or runs[0]["distinct"] > best[1]["distinct"]):
                best = (label, runs[0], ids)

    if not best:
        print(json.dumps({"ok": False, "error": "no id run found"}))
        return 1

    label, run, ids = best
    start = run["offset"]
    vaddr = None
    for seg_vaddr, seg_off, seg_size in image.segments:
        if seg_off <= start < seg_off + seg_size:
            vaddr = seg_vaddr + (start - seg_off)
    print(f"table: VA 0x{vaddr:08x}  file 0x{start:X}  stride {run['stride']}  "
          f"records {run['records']} ({run['distinct']} distinct)  "
          f"id at +{run['idField']} ({label})")

    # Validation the structural detector cannot do: how many ids are real files?
    found = set()
    for i in range(run["records"]):
        v = struct.unpack_from("<I", image.data,
                               start + i * run["stride"] + run["idField"])[0]
        found.add(v)
    print(f"validation: {len(found & ids)}/{len(found)} ids correspond to real assets")

    if args.out:
        json.dump({"vaddr": vaddr, "offset": start, **run,
                   "idsResolved": len(found & ids), "idsTotal": len(found)},
                  open(args.out, "w"), indent=2)
        print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

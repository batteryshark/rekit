#!/usr/bin/env python3
"""bin-table-diff — find, extract and diff static record tables inside binaries.

Games and embedded firmware of a certain era compile their content straight into
the executable: an array of fixed-size structs holding song metadata, level
tables, item stats, string catalogues. Function-level diffing is blind to all of
it — a rebalanced difficulty or an added track changes no code at all.

This finds those tables without being told where they are, infers each column's
type from the data, and diffs two builds record by record.

Detection works from a signal that is hard to fake: a run of records at a fixed
stride where the same intra-record offset holds a pointer into the binary's own
string data. Layouts differ between eras, so nothing about the shape is assumed —
stride, record start, and column types are all recovered from the bytes.

    run.py find    <binary>                       locate candidate tables
    run.py extract <binary> <outdir>              extract to JSON + CSV
    run.py diff    <binaryA> <binaryB> <outdir>   record-level diff

Read-only and pure stdlib; never executes the input.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import struct
import sys
from collections import Counter, defaultdict

# Field-count and stride bounds for a plausible record table.
MIN_STRIDE, MAX_STRIDE = 16, 512
MIN_RECORDS = 8
# A run of this many consecutive string pointers is the detection anchor.
ANCHOR_POINTERS = 3
MAX_STRING = 200

# Region-specific builds of the same program store their catalogues in the local
# codepage, so a corpus spans several. Order matters: utf-8 first because it
# rejects almost anything that is not genuinely utf-8, then the CJK codepages.
# These overlap — EUC-KR can "successfully" decode Big5 bytes into wrong glyphs —
# so a decoded string from a foreign-market build is a best guess, not a
# certainty. Pass --encoding to pin one when you know the market.
TEXT_ENCODINGS = ("utf-8", "euc-kr", "big5", "gb18030", "shift_jis", "cp1252")


class TableError(Exception):
    pass


# --------------------------------------------------------------------------- #
# ELF address translation
# --------------------------------------------------------------------------- #

class Image:
    """A loaded binary plus its virtual-address -> file-offset mapping.

    Reading the program headers rather than assuming a load base keeps this
    working for any non-relocated ELF, not just the 0x8048000 i386 convention.
    """

    def __init__(self, path: str):
        with open(path, "rb") as handle:
            self.data = handle.read()
        self.path = path
        self.segments: list[tuple[int, int, int]] = []
        self._parse_elf()

    def _parse_elf(self) -> None:
        d = self.data
        if d[:4] != b"\x7fELF":
            raise TableError(f"not an ELF file: {self.path}")
        is64 = d[4] == 2
        little = d[5] == 1
        end = "<" if little else ">"
        if is64:
            e_phoff, = struct.unpack_from(f"{end}Q", d, 0x20)
            e_phentsize, e_phnum = struct.unpack_from(f"{end}HH", d, 0x36)
            fmt, voff, ooff, foff = f"{end}Q", 0x10, 0x08, 0x20
        else:
            e_phoff, = struct.unpack_from(f"{end}I", d, 0x1C)
            e_phentsize, e_phnum = struct.unpack_from(f"{end}HH", d, 0x2A)
            fmt, voff, ooff, foff = f"{end}I", 0x08, 0x04, 0x10
        for i in range(e_phnum):
            base = e_phoff + i * e_phentsize
            p_type, = struct.unpack_from(f"{end}I", d, base)
            if p_type != 1:  # PT_LOAD
                continue
            vaddr, = struct.unpack_from(fmt, d, base + voff)
            offset, = struct.unpack_from(fmt, d, base + ooff)
            filesz, = struct.unpack_from(fmt, d, base + foff)
            self.segments.append((vaddr, offset, filesz))
        if not self.segments:
            raise TableError(f"no PT_LOAD segments in {self.path}")

    def to_offset(self, vaddr: int) -> int | None:
        for seg_vaddr, seg_off, seg_size in self.segments:
            if seg_vaddr <= vaddr < seg_vaddr + seg_size:
                return seg_off + (vaddr - seg_vaddr)
        return None

    def string_at(self, vaddr: int) -> bytes | None:
        off = self.to_offset(vaddr)
        if off is None:
            return None
        end = self.data.find(b"\0", off, off + MAX_STRING)
        if end <= off:
            return None
        raw = self.data[off:end]
        # Printable in some single- or multi-byte encoding: no control bytes.
        if any(c < 0x20 and c not in (9,) for c in raw):
            return None
        return raw


def decode(raw: bytes, preferred: str | None = None) -> tuple[str, str]:
    """Decode a table string, reporting which encoding actually worked.

    Korean-market builds store EUC-KR alongside ASCII in the same table, so the
    encoding is a per-string property, not a per-table one.
    """
    order = ((preferred,) + TEXT_ENCODINGS) if preferred else TEXT_ENCODINGS
    for encoding in order:
        try:
            return raw.decode(encoding), encoding
        except UnicodeDecodeError:
            continue
    return raw.decode("latin-1"), "latin-1"


# --------------------------------------------------------------------------- #
# Detection
# --------------------------------------------------------------------------- #

def _pointer_columns(image: Image) -> list[bool]:
    """Per dword slot: does it hold a pointer to a printable string?"""
    d = image.data
    count = (len(d) - 4) // 4
    flags = [False] * count
    cache: dict = {}
    for i in range(count):
        value, = struct.unpack_from("<I", d, i * 4)
        hit = cache.get(value)
        if hit is None:
            raw = image.string_at(value) if value else None
            hit = bool(raw) and len(raw) >= 2
            cache[value] = hit
        flags[i] = hit
    return flags


def find_tables(image: Image, min_records: int = MIN_RECORDS,
                limit: int = 10) -> list[dict]:
    """Locate fixed-stride record tables by their string-pointer columns."""
    flags = _pointer_columns(image)
    anchors = {i * 4 for i in range(len(flags) - ANCHOR_POINTERS + 1)
               if all(flags[i + k] for k in range(ANCHOR_POINTERS))}
    if not anchors:
        return []

    candidates: list[dict] = []
    claimed: set = set()
    for stride in range(MIN_STRIDE, MAX_STRIDE + 1, 4):
        for anchor in sorted(anchors):
            if anchor - stride in anchors or anchor in claimed:
                continue
            run = [anchor]
            cursor = anchor + stride
            while cursor in anchors:
                run.append(cursor)
                cursor += stride
            if len(run) < min_records:
                continue
            candidates.append({"stride": stride, "anchor": anchor,
                               "records": len(run)})
            claimed.update(run)
    # Prefer the biggest tables: most records first, then the tighter stride.
    candidates.sort(key=lambda c: (-c["records"] * c["stride"], c["stride"]))
    return _dedupe([_refine(image, c) for c in candidates])[:limit]


def _record_plausible(image: Image, offset: int, stride: int,
                      pointer_fields: list[int]) -> bool:
    if offset < 0 or offset + stride > len(image.data):
        return False
    populated = 0
    for field in pointer_fields:
        value, = struct.unpack_from("<I", image.data, offset + field)
        # A record may legitimately carry a null string slot; a wild pointer
        # means we have walked off the end of the table.
        if value:
            if image.string_at(value) is None:
                return False
            populated += 1
    # ...but an all-null record is zero padding, not a row. Without this the
    # walk runs straight off the front of the table into the .bss-style run of
    # zeros before it and reports dozens of empty leading records.
    return populated > 0


def _refine(image: Image, candidate: dict) -> dict:
    """Extend a detected run to the table's full extent.

    Offsets are reported **anchor-relative**: the run is found by its block of
    string pointers, and where that block sits inside the struct is not
    recoverable from pointer validity alone — every candidate shift describes the
    same bytes, so testing shifts proves nothing. Rather than invent an alignment,
    the pointer block is treated as column 0 and every column is labelled relative
    to it. Extraction stays self-consistent and two builds diff correctly, because
    both are detected the same way. Pass --offset/--stride when you know the true
    struct start and want struct-relative columns.
    """
    stride, anchor = candidate["stride"], candidate["anchor"]
    pointer_fields = [0, 4, 8]
    start = anchor
    while start - stride >= 0 and _record_plausible(image, start - stride, stride,
                                                    pointer_fields):
        start -= stride
    end = anchor
    while _record_plausible(image, end + stride, stride, pointer_fields):
        end += stride
    return {"stride": stride, "offset": start,
            "records": (end - start) // stride + 1,
            "anchorRelative": True}


def _dedupe(tables: list[dict]) -> list[dict]:
    """Collapse candidates describing the same byte range.

    One table is detected once per pointer column it contains, so the same run
    surfaces several times at offsets a few dwords apart.
    """
    kept: list[dict] = []
    for table in tables:
        lo = table["offset"]
        hi = lo + table["stride"] * table["records"]
        if any(t["stride"] == table["stride"]
               and lo < t["offset"] + t["stride"] * t["records"]
               and t["offset"] < hi for t in kept):
            continue
        kept.append(table)
    return kept


# --------------------------------------------------------------------------- #
# Layout inference
# --------------------------------------------------------------------------- #

def infer_layout(image: Image, table: dict) -> list[dict]:
    """Type each 4-byte column from how its values behave across all records."""
    stride, offset, records = table["stride"], table["offset"], table["records"]
    columns = []
    for field in range(0, stride - 3, 4):
        values = [struct.unpack_from("<I", image.data, offset + i * stride + field)[0]
                  for i in range(records)]
        strings = sum(1 for v in values if v and image.string_at(v) is not None)
        nulls = sum(1 for v in values if v == 0)
        non_null = len(values) - nulls

        kind = "int"
        pointers = sum(1 for v in values if v and image.to_offset(v) is not None)
        if non_null and strings / non_null > 0.9:
            kind = "string"
        elif non_null and pointers / non_null > 0.9:
            # Points somewhere in the image but not at a string — a chart array, a
            # nested struct. The VA itself shifts between builds even when the
            # pointed-to content is identical, so comparing the raw value reports a
            # change that did not happen. Diffed as present/absent instead.
            kind = "pointer"
        else:
            floats = [struct.unpack("<f", struct.pack("<I", v))[0] for v in values]
            sane = sum(1 for f in floats
                       if f == f and 0.001 < abs(f) < 1e6) if values else 0
            if non_null and sane / max(non_null, 1) > 0.9:
                kind = "float"
            elif all(v <= 0xFF or v == 0xFFFFFFFF for v in values):
                kind = "byte" if max(values) <= 1 else "small"
        columns.append({"field": field, "kind": kind,
                        "distinct": len(set(values)), "nulls": nulls})
    return columns


def read_table(image: Image, table: dict, layout: list[dict],
               encoding: str | None = None) -> list[dict]:
    stride, offset, records = table["stride"], table["offset"], table["records"]
    rows = []
    for i in range(records):
        base = offset + i * stride
        row: dict = {"_index": i, "_offset": base}
        for column in layout:
            name = f"f{column['field']:02X}"
            value, = struct.unpack_from("<I", image.data, base + column["field"])
            if column["kind"] == "string":
                raw = image.string_at(value) if value else None
                row[name] = decode(raw, encoding)[0] if raw else ""
            elif column["kind"] == "pointer":
                row[name] = "<ptr>" if value else ""
            elif column["kind"] == "float":
                row[name] = round(struct.unpack("<f", struct.pack("<I", value))[0], 4)
            else:
                row[name] = value - 0x100000000 if value > 0x7FFFFFFF else value
        rows.append(row)
    return rows


def choose_key(rows: list[dict], layout: list[dict],
               explicit: str | None = None) -> str | None:
    """Pick the column that best identifies a record across two builds.

    A record's position shifts when entries are inserted, so diffing by index
    would report everything after an insertion as changed. A near-unique string
    column (a name) is the stable identity.
    """
    if explicit:
        return explicit
    scored = []
    for column in layout:
        if column["kind"] != "string":
            continue
        name = f"f{column['field']:02X}"
        values = [r[name] for r in rows if r[name]]
        # A column that is blank for half the table cannot identify records even
        # if its populated values are unique.
        if len(values) < 0.5 * len(rows):
            continue
        scored.append((len(set(values)) / len(values), name))
    if not scored:
        return None
    scored.sort(reverse=True)
    # A single column is rarely unique on its own: the same song appears once per
    # chart type, the same artist many times over. Combining the two most
    # distinctive string columns identifies a record far more reliably, and
    # KEY_SEPARATOR-joined names stay readable in the report.
    return KEY_SEPARATOR.join(name for _, name in scored[:2])


KEY_SEPARATOR = "+"


def record_key(row: dict, key: str, seen: Counter) -> str:
    """Composite key plus an occurrence suffix for genuine duplicate rows.

    Some tables legitimately repeat a key (one row per difficulty). Numbering
    repeats keeps them distinct and stable, so a diff pairs the first with the
    first rather than declaring both changed.
    """
    value = " | ".join(str(row.get(part, "")).strip()
                       for part in key.split(KEY_SEPARATOR))
    seen[value] += 1
    return value if seen[value] == 1 else f"{value} #{seen[value]}"


def diff_tables(rows_a: list[dict], rows_b: list[dict], key: str | None) -> dict:
    if not key:
        # No stable identity: fall back to positional comparison and say so.
        added = rows_b[len(rows_a):]
        removed = rows_a[len(rows_b):]
        changed = []
        for a, b in zip(rows_a, rows_b):
            fields = {k: [a[k], b[k]] for k in a
                      if not k.startswith("_") and a.get(k) != b.get(k)}
            if fields:
                changed.append({"index": a["_index"], "fields": fields})
        return {"key": None, "positional": True, "added": added,
                "removed": removed, "changed": changed}

    seen_a, seen_b = Counter(), Counter()
    index_a = {record_key(r, key, seen_a): r for r in rows_a}
    index_b = {record_key(r, key, seen_b): r for r in rows_b}
    added = [index_b[k] for k in index_b if k not in index_a]
    removed = [index_a[k] for k in index_a if k not in index_b]
    changed = []
    for k in index_a:
        if k not in index_b:
            continue
        a, b = index_a[k], index_b[k]
        fields = {f: [a[f], b[f]] for f in a
                  if not f.startswith("_") and a.get(f) != b.get(f)}
        if fields:
            changed.append({"key": k, "fields": fields})
    return {"key": key, "positional": False, "added": added,
            "removed": removed, "changed": changed}


# --------------------------------------------------------------------------- #

def _write_csv(path: str, rows: list[dict]) -> None:
    if not rows:
        return
    with open(path, "w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def _pick_table(image: Image, args) -> tuple[dict, list[dict], list[dict]]:
    if args.offset is not None and args.stride is not None:
        table = {"stride": args.stride, "offset": args.offset,
                 "records": args.records or 0, "pointerField": 0}
        if not table["records"]:
            raise TableError("--offset/--stride also need --records")
    else:
        found = find_tables(image, args.min_records)
        if not found:
            raise TableError(f"no record table found in {image.path}")
        table = found[0]
    layout = infer_layout(image, table)
    return table, layout, read_table(image, table, layout, args.encoding)


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="bin-table-diff")
    p.add_argument("op", choices=["find", "extract", "diff"])
    p.add_argument("target")
    p.add_argument("other", nargs="?")
    p.add_argument("outdir", nargs="?")
    p.add_argument("--offset", type=lambda v: int(v, 0))
    p.add_argument("--stride", type=lambda v: int(v, 0))
    p.add_argument("--records", type=int)
    p.add_argument("--key", help="column that identifies a record (e.g. f14)")
    p.add_argument("--encoding", help="pin the string codepage (e.g. big5) "
                                      "instead of guessing per string")
    p.add_argument("--min-records", type=int, default=MIN_RECORDS)
    p.add_argument("--top", type=int, default=25)
    p.add_argument("--format", choices=["text", "json"], default="text")
    a = p.parse_args(argv[1:])

    try:
        if a.op == "find":
            image = Image(a.target)
            tables = find_tables(image, a.min_records)
            result = {"ok": bool(tables), "tool": "bin-table-diff",
                      "tables": tables}
            if a.format == "json":
                print(json.dumps(result))
            else:
                if not tables:
                    print("bin-table-diff: no record tables found")
                for t in tables:
                    print(f"  offset 0x{t['offset']:X}  stride {t['stride']}  "
                          f"records {t['records']}")
            return 0 if tables else 1

        if a.op == "extract":
            if not a.other:
                return _fail({"ok": False, "error": "extract needs an outdir"}, 2)
            image = Image(a.target)
            table, layout, rows = _pick_table(image, a)
            os.makedirs(a.other, exist_ok=True)
            json_path = os.path.join(a.other, "table.json")
            csv_path = os.path.join(a.other, "table.csv")
            with open(json_path, "w", encoding="utf-8") as handle:
                json.dump({"table": table, "layout": layout, "rows": rows},
                          handle, indent=2, ensure_ascii=False)
            _write_csv(csv_path, rows)
            summary = {"ok": True, "tool": "bin-table-diff", **table,
                       "columns": len(layout), "jsonFile": json_path,
                       "csvFile": csv_path}
            if a.format == "json":
                print(json.dumps(summary))
            else:
                print(f"bin-table-diff: {table['records']} records × "
                      f"{len(layout)} columns at 0x{table['offset']:X} "
                      f"(stride {table['stride']}) → {csv_path}")
            return 0

        # diff
        if not (a.other and a.outdir):
            return _fail({"ok": False,
                          "error": "diff needs <binaryA> <binaryB> <outdir>"}, 2)
        image_a, image_b = Image(a.target), Image(a.other)
        table_a, layout_a, rows_a = _pick_table(image_a, a)
        table_b, layout_b, rows_b = _pick_table(image_b, a)
        key = choose_key(rows_a, layout_a, a.key)
        result = diff_tables(rows_a, rows_b, key)
        # A struct that gained or lost a field between builds shifts every column
        # after it, so field-by-field comparison compares unrelated data and
        # reports the whole table as changed. Added/removed by key stay valid.
        stride_mismatch = table_a["stride"] != table_b["stride"]
        if stride_mismatch:
            result["strideMismatch"] = {"primary": table_a["stride"],
                                        "secondary": table_b["stride"]}
        os.makedirs(a.outdir, exist_ok=True)
        out_path = os.path.join(a.outdir, "table-diff.json")
        with open(out_path, "w", encoding="utf-8") as handle:
            json.dump({"primary": table_a, "secondary": table_b,
                       "diff": result}, handle, indent=2, ensure_ascii=False)
        summary = {
            "ok": True, "tool": "bin-table-diff",
            "key": result["key"], "positional": result["positional"],
            "primaryRecords": table_a["records"],
            "secondaryRecords": table_b["records"],
            "added": len(result["added"]), "removed": len(result["removed"]),
            "changed": len(result["changed"]), "diffFile": out_path,
            "strideMismatch": result.get("strideMismatch"),
        }
        if a.format == "json":
            print(json.dumps(summary, ensure_ascii=False))
        else:
            print(f"bin-table-diff: {table_a['records']} → {table_b['records']} records"
                  f"  (key {result['key'] or 'POSITIONAL — no stable identity'})")
            print(f"  added {len(result['added'])}  removed {len(result['removed'])}"
                  f"  changed {len(result['changed'])}")
            if result.get("strideMismatch"):
                mismatch = result["strideMismatch"]
                print(f"  WARNING: record size differs ({mismatch['primary']} vs "
                      f"{mismatch['secondary']} bytes) — the struct gained or lost a "
                      f"field, so every column after it shifts. Treat 'changed' as "
                      f"meaningless here; added/removed by key are still valid.")
            for entry in result["changed"][:a.top]:
                label = entry.get("key", entry.get("index"))
                fields = ", ".join(f"{f}: {v[0]} → {v[1]}"
                                   for f, v in list(entry["fields"].items())[:4])
                print(f"    {label}: {fields}")
            for row in result["added"][:a.top]:
                label = (" | ".join(str(row.get(p, "")).strip()
                                    for p in result["key"].split("+"))
                         if result["key"] else row["_index"])
                print(f"    + {label}")
            for row in result["removed"][:a.top]:
                label = (" | ".join(str(row.get(p, "")).strip()
                                    for p in result["key"].split("+"))
                         if result["key"] else row["_index"])
                print(f"    - {label}")
        return 0

    except TableError as exc:
        return _fail({"ok": False, "error": str(exc)}, 1)


def _fail(payload: dict, code: int) -> int:
    print(json.dumps(payload))
    return code


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

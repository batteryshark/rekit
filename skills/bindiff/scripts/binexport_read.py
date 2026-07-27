#!/usr/bin/env python3
"""Minimal, read-only BinExport2 reader — pure stdlib, no protobuf runtime.

A `.BinExport` file is a serialized `BinExport2` protobuf. BinDiff's result
database only records *matched* function pairs, so the interesting other half of
a patch diff — functions that exist in only one side — has to come from the
exports themselves. Rather than depend on the protobuf runtime (and a generated
module) just to read two repeated fields, we walk the wire format directly.

Field numbers are from `binexport2.proto` (github.com/google/binexport), which is
append-only and stable across BinExport v2 versions:

    BinExport2.meta_information = 1   (Meta)
    BinExport2.call_graph       = 8   (CallGraph)
    Meta.executable_name        = 1   Meta.executable_id    = 2
    Meta.architecture_name      = 3   Meta.timestamp        = 4
    CallGraph.vertex            = 1   (repeated Vertex)
    Vertex.address              = 1   Vertex.type           = 2
    Vertex.mangled_name         = 3   Vertex.demangled_name = 4

Unknown fields are skipped generically, so a newer producer cannot break this.
"""

from __future__ import annotations

import json
import sys

# Vertex.Type enum
VERTEX_TYPES = {0: "normal", 1: "library", 2: "imported", 3: "thunk", 4: "invalid"}

# Vertex kinds BinDiff can actually build a flow graph for (and therefore match).
# Imports and invalid functions have no body, so listing them as added/removed
# code would be noise.
MATCHABLE_TYPES = ("normal", "library", "thunk")


class BinExportError(Exception):
    """Raised when a file is not a parseable BinExport2 protobuf."""


def _varint(buf: bytes, pos: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while True:
        if pos >= len(buf):
            raise BinExportError("truncated varint")
        if shift > 63:
            raise BinExportError("varint too long")
        byte = buf[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, pos
        shift += 7


def _fields(buf: bytes, start: int = 0, end: int | None = None):
    """Yield (field_number, value) over one protobuf message.

    `value` is an int for varint/fixed fields and a memoryview-backed bytes slice
    for length-delimited ones.
    """
    pos = start
    end = len(buf) if end is None else end
    while pos < end:
        tag, pos = _varint(buf, pos)
        field, wire = tag >> 3, tag & 0x07
        if field == 0:
            raise BinExportError("invalid field number 0")
        if wire == 0:  # varint
            value, pos = _varint(buf, pos)
            yield field, value
        elif wire == 2:  # length-delimited
            length, pos = _varint(buf, pos)
            if pos + length > end:
                raise BinExportError("length-delimited field overruns message")
            yield field, buf[pos:pos + length]
            pos += length
        elif wire == 5:  # fixed32
            yield field, int.from_bytes(buf[pos:pos + 4], "little")
            pos += 4
        elif wire == 1:  # fixed64
            yield field, int.from_bytes(buf[pos:pos + 8], "little")
            pos += 8
        else:
            raise BinExportError(f"unsupported wire type {wire}")


def _text(raw: bytes) -> str:
    return raw.decode("utf-8", "replace") if isinstance(raw, (bytes, bytearray)) else ""


def parse(data: bytes) -> dict:
    """Parse a BinExport2 blob into {meta, functions}. Read-only; never executes."""
    meta: dict = {}
    functions: list[dict] = []
    for field, value in _fields(data):
        if field == 1 and isinstance(value, bytes):  # meta_information
            for mfield, mvalue in _fields(value):
                if mfield == 1:
                    meta["executable_name"] = _text(mvalue)
                elif mfield == 2:
                    meta["executable_id"] = _text(mvalue)
                elif mfield == 3:
                    meta["architecture"] = _text(mvalue)
                elif mfield == 4 and isinstance(mvalue, int):
                    meta["timestamp"] = mvalue
        elif field == 8 and isinstance(value, bytes):  # call_graph
            for cgfield, cgvalue in _fields(value):
                if cgfield != 1 or not isinstance(cgvalue, bytes):  # vertex
                    continue
                fn = {"address": 0, "type": "normal", "name": "", "demangled": ""}
                for vfield, vvalue in _fields(cgvalue):
                    if vfield == 1 and isinstance(vvalue, int):
                        fn["address"] = vvalue
                    elif vfield == 2 and isinstance(vvalue, int):
                        fn["type"] = VERTEX_TYPES.get(vvalue, f"unknown({vvalue})")
                    elif vfield == 3:
                        fn["name"] = _text(vvalue)
                    elif vfield == 4:
                        fn["demangled"] = _text(vvalue)
                functions.append(fn)
    if not functions and not meta:
        raise BinExportError("no BinExport2 metadata or call graph found")
    return {"meta": meta, "functions": functions}


def read(path: str) -> dict:
    """Parse a `.BinExport` file from disk."""
    try:
        with open(path, "rb") as handle:
            data = handle.read()
    except OSError as exc:
        raise BinExportError(f"cannot read {path}: {exc}") from exc
    if not data:
        raise BinExportError(f"empty file: {path}")
    return parse(data)


def label(fn: dict) -> str:
    """Best display name for a function: demangled > mangled > sub_<addr>."""
    return fn.get("demangled") or fn.get("name") or f"sub_{fn['address']:x}"


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: binexport_read.py <file.BinExport>", file=sys.stderr)
        return 2
    try:
        parsed = read(argv[1])
    except BinExportError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}))
        return 1
    print(json.dumps({"ok": True, "meta": parsed["meta"],
                      "functions": len(parsed["functions"])}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

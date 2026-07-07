#!/usr/bin/env python3
"""Hex viewer skill — offset + hex + ASCII dump of a file or byte range.

Pure stdlib, zero dependencies. Read-only: opens the file for bytes and prints a
view; it never imports, parses as code, or executes the input.

    python3 hexview.py <input> [--offset N] [--length N] [--width N] [--format text|json]

text mode  -> classic hexdump on stdout (the view is the output)
json mode  -> one JSON object {ok, path, offset, length, totalBytes, sha256, rows}
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys

_RENDER_CAP = 1 << 20          # never render more than 1 MiB at once
_SHA_CAP = 256 * 1024 * 1024   # skip sha256 for files larger than 256 MiB


def emit_json(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj) + "\n")


def sha256_file(path: str) -> str | None:
    if os.path.getsize(path) > _SHA_CAP:
        return None
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def read_slice(path: str, offset: int, length: int) -> tuple[bytes, int, int]:
    size = os.path.getsize(path)
    if offset < 0:
        offset = max(0, size + offset)
    offset = min(offset, size)
    if not length:  # 0 / None -> to end
        length = size - offset
    length = max(0, min(length, size - offset, _RENDER_CAP))
    with open(path, "rb") as f:
        f.seek(offset)
        data = f.read(length)
    return data, offset, size


def _ascii(chunk: bytes) -> str:
    return "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)


def rows(data: bytes, base: int, width: int) -> list[dict]:
    out = []
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        out.append({
            "offset": base + i,
            "hex": " ".join(f"{b:02x}" for b in chunk),
            "ascii": _ascii(chunk),
        })
    return out


def text_dump(data: bytes, base: int, width: int) -> str:
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        hexs = " ".join(f"{b:02x}" for b in chunk)
        lines.append(f"{base + i:08x}  {hexs:<{width * 3}}  |{_ascii(chunk)}|")
    return "\n".join(lines)


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="hexview", add_help=True)
    p.add_argument("input")
    p.add_argument("--offset", type=int, default=0)
    p.add_argument("--length", type=int, default=256)
    p.add_argument("--width", type=int, default=16)
    p.add_argument("--format", choices=["text", "json"], default="text")
    args = p.parse_args(argv[1:])

    if not os.path.isfile(args.input):
        emit_json({"ok": False, "error": f"file not found: {args.input}"})
        return 2
    if args.width < 1:
        args.width = 16

    data, offset, size = read_slice(args.input, args.offset, args.length)
    sha = sha256_file(args.input)
    truncated = (offset + len(data)) < size

    if args.format == "json":
        emit_json({
            "ok": True, "path": os.path.abspath(args.input), "offset": offset,
            "length": len(data), "totalBytes": size, "sha256": sha,
            "truncated": truncated, "rows": rows(data, offset, args.width),
        })
    else:
        header = f"file: {args.input}  size: {size} bytes"
        if sha:
            header += f"  sha256: {sha}"
        print(header)
        print(f"showing {len(data)} byte(s) at offset {offset} (0x{offset:x})"
              f"{' [truncated]' if truncated else ''}")
        print(text_dump(data, offset, args.width))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

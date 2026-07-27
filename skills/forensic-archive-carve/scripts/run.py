#!/usr/bin/env python3
"""Carve structurally validated classic ZIP and RAR4 ranges from an image."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
from pathlib import Path
from typing import BinaryIO, Dict, Iterable, List, Optional, Tuple


ZIP_EOCD = b"PK\x05\x06"
ZIP_CENTRAL = b"PK\x01\x02"
ZIP_LOCAL = b"PK\x03\x04"
RAR4 = b"Rar!\x1a\x07\x00"


def fail(message: str, code: int = 2) -> int:
    print(json.dumps({"ok": False, "tool": "forensic-archive-carve", "error": message}))
    return code


def read_hits(path: Path) -> Iterable[Tuple[str, int]]:
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
                kind = record["kind"]
                offset = int(record["offset"])
            except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
                raise ValueError("{}:{}: invalid hit: {}".format(path, line_number, exc))
            yield str(kind), offset


def scan_offsets(image: BinaryIO, image_size: int, chunk_size: int = 64 * 1024 * 1024):
    signatures = (("zipEocd", ZIP_EOCD), ("rar4", RAR4))
    overlap = max(len(signature) for _, signature in signatures) - 1
    carry = b""
    absolute = 0
    while absolute < image_size:
        image.seek(absolute)
        chunk = image.read(min(chunk_size, image_size - absolute))
        if not chunk:
            break
        data = carry + chunk
        base = absolute - len(carry)
        for kind, signature in signatures:
            position = data.find(signature)
            while position >= 0:
                offset = base + position
                if 0 <= offset < image_size:
                    yield kind, offset
                position = data.find(signature, position + 1)
        carry = data[-overlap:]
        absolute += len(chunk)


def zip_candidate(
    image: BinaryIO, eocd_offset: int, image_size: int, max_size: int
) -> Tuple[Optional[dict], str]:
    image.seek(eocd_offset)
    fixed = image.read(22)
    if len(fixed) != 22 or fixed[:4] != ZIP_EOCD:
        return None, "short-or-missing-eocd"
    _, disk, central_disk, entries_disk, entries, central_size, central_offset, comment = (
        struct.unpack("<4sHHHHIIH", fixed)
    )
    if disk or central_disk or entries_disk != entries:
        return None, "multi-disk-zip"
    if central_size == 0xFFFFFFFF or central_offset == 0xFFFFFFFF or entries == 0xFFFF:
        return None, "zip64-unsupported"
    start = eocd_offset - central_size - central_offset
    end = eocd_offset + 22 + comment
    size = end - start
    if start < 0 or end > image_size or size < 22 or size > max_size:
        return None, "range-out-of-bounds"
    central_start = eocd_offset - central_size
    cursor = central_start
    local_offsets = []
    for _ in range(entries):
        image.seek(cursor)
        header = image.read(46)
        if len(header) != 46 or header[:4] != ZIP_CENTRAL:
            return None, "invalid-central-directory"
        name_length, extra_length, comment_length = struct.unpack_from("<HHH", header, 28)
        disk_start = struct.unpack_from("<H", header, 34)[0]
        local_offset = struct.unpack_from("<I", header, 42)[0]
        if disk_start or local_offset == 0xFFFFFFFF:
            return None, "split-or-zip64-entry"
        cursor += 46 + name_length + extra_length + comment_length
        if cursor > central_start + central_size:
            return None, "central-directory-overrun"
        local_offsets.append(local_offset)
    if cursor != central_start + central_size:
        return None, "central-directory-size-mismatch"
    for local_offset in local_offsets:
        image.seek(start + local_offset)
        if image.read(4) != ZIP_LOCAL:
            return None, "missing-local-header"
    return (
        {
            "kind": "zip",
            "start": start,
            "endExclusive": end,
            "size": size,
            "eocdOffset": eocd_offset,
            "entries": entries,
            "centralDirectorySize": central_size,
            "validation": "eocd-central-directory-local-headers",
        },
        "",
    )


def rar4_candidate(
    image: BinaryIO, start: int, image_size: int, max_size: int
) -> Tuple[Optional[dict], str]:
    image.seek(start)
    if image.read(len(RAR4)) != RAR4:
        return None, "missing-rar4-signature"
    cursor = start + len(RAR4)
    blocks = 0
    while cursor + 7 <= image_size and cursor - start <= max_size:
        image.seek(cursor)
        header = image.read(7)
        if len(header) != 7:
            return None, "short-rar-block"
        _, block_type, flags, header_size = struct.unpack("<HBHH", header)
        if header_size < 7 or header_size > 1024 * 1024:
            return None, "invalid-rar-header-size"
        additional = 0
        if flags & 0x8000:
            raw = image.read(4)
            if len(raw) != 4:
                return None, "short-rar-additional-size"
            additional = struct.unpack("<I", raw)[0]
        block_size = header_size + additional
        next_cursor = cursor + block_size
        if (
            block_size < header_size
            or block_size > max_size
            or next_cursor > image_size
            or next_cursor - start > max_size
        ):
            return None, "rar-range-out-of-bounds"
        blocks += 1
        if block_type == 0x7B:
            return (
                {
                    "kind": "rar",
                    "start": start,
                    "endExclusive": next_cursor,
                    "size": next_cursor - start,
                    "blocks": blocks,
                    "validation": "rar4-block-walk-end-marker",
                },
                "",
            )
        cursor = next_cursor
    return None, "missing-rar-end-marker"


def copy_range(image: BinaryIO, start: int, end: int, output: Path) -> str:
    digest = hashlib.sha256()
    remaining = end - start
    image.seek(start)
    with output.open("xb") as destination:
        while remaining:
            chunk = image.read(min(8 * 1024 * 1024, remaining))
            if not chunk:
                raise EOFError("short read at byte {}".format(image.tell()))
            destination.write(chunk)
            digest.update(chunk)
            remaining -= len(chunk)
    return digest.hexdigest()


def ensure_empty_output(outdir: Path) -> None:
    if outdir.exists():
        if not outdir.is_dir():
            raise ValueError("output exists and is not a directory: {}".format(outdir))
        if any(outdir.iterdir()):
            raise ValueError("output directory must be empty: {}".format(outdir))
    else:
        outdir.mkdir(parents=True)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("outdir", type=Path)
    parser.add_argument("--hits", type=Path)
    parser.add_argument("--max-size", type=int, default=2 * 1024**3)
    parser.add_argument("--max-candidates", type=int, default=10_000)
    args = parser.parse_args(argv)
    if not args.input.is_file():
        return fail("input is not a regular file: {}".format(args.input))
    if args.hits and not args.hits.is_file():
        return fail("--hits is not a regular file: {}".format(args.hits))
    if args.max_size < 22 or args.max_size > 16 * 1024**3:
        return fail("--max-size must be between 22 and 17179869184")
    if args.max_candidates < 1 or args.max_candidates > 1_000_000:
        return fail("--max-candidates must be between 1 and 1000000")
    try:
        ensure_empty_output(args.outdir)
        image_size = args.input.stat().st_size
        rejection_counts: Dict[str, int] = {}
        candidates = []
        seen_hits = set()
        with args.input.open("rb", buffering=0) as image:
            hits = read_hits(args.hits) if args.hits else scan_offsets(image, image_size)
            for kind, offset in hits:
                normalized = kind.casefold().replace("_", "")
                if normalized in ("zipeocd", "zipeocdrecord"):
                    hit_kind = "zip"
                elif normalized == "rar4":
                    hit_kind = "rar"
                elif normalized in ("zip64eocd", "rar5"):
                    rejection_counts["{}-unsupported".format(normalized)] = (
                        rejection_counts.get("{}-unsupported".format(normalized), 0) + 1
                    )
                    continue
                else:
                    continue
                hit_key = (hit_kind, offset)
                if hit_key in seen_hits:
                    continue
                seen_hits.add(hit_key)
                candidate, rejection = (
                    zip_candidate(image, offset, image_size, args.max_size)
                    if hit_kind == "zip"
                    else rar4_candidate(image, offset, image_size, args.max_size)
                )
                if candidate:
                    candidates.append(candidate)
                    if len(candidates) >= args.max_candidates:
                        break
                else:
                    rejection_counts[rejection] = rejection_counts.get(rejection, 0) + 1
            candidates.sort(key=lambda item: (item["start"], item["endExclusive"]))
            identities: Dict[str, str] = {}
            for index, candidate in enumerate(candidates, 1):
                extension = candidate["kind"]
                filename = "{:04d}_{:012x}_{:012x}.{}".format(
                    index, candidate["start"], candidate["size"], extension
                )
                output = args.outdir / filename
                digest = copy_range(
                    image, candidate["start"], candidate["endExclusive"], output
                )
                candidate["file"] = str(output.resolve())
                candidate["sha256"] = digest
                candidate["duplicateOf"] = identities.get(digest)
                identities.setdefault(digest, filename)
        manifest = args.outdir / "manifest.jsonl"
        with manifest.open("w", encoding="utf-8", newline="\n") as handle:
            for candidate in candidates:
                handle.write(json.dumps(candidate, sort_keys=True) + "\n")
        result = {
            "ok": True,
            "tool": "forensic-archive-carve",
            "image": str(args.input.resolve()),
            "imageSize": image_size,
            "hitsFile": str(args.hits.resolve()) if args.hits else None,
            "candidateCount": len(candidates),
            "uniqueSha256Count": len(identities),
            "candidateLimitReached": len(candidates) >= args.max_candidates,
            "rejections": dict(sorted(rejection_counts.items())),
            "outputDir": str(args.outdir.resolve()),
            "manifest": str(manifest.resolve()),
        }
    except (OSError, ValueError, EOFError, struct.error) as exc:
        return fail("carving failed: {}".format(exc), 1)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

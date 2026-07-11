#!/usr/bin/env python3
"""Structured, read-only file and directory comparison utilities."""
from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import os
import unicodedata
import zlib
from pathlib import Path
from typing import Any, Iterable


def emit(result: dict[str, Any], text: str | None = None) -> None:
    if ARGS.format == "text" and text is not None:
        print(text)
    else:
        print(json.dumps(result, ensure_ascii=False))
    raise SystemExit(0 if result.get("ok") else 1)


def fail(op: str, error: str) -> None:
    emit({"ok": False, "op": op, "error": error})


def file_hashes(path: Path) -> tuple[str, str]:
    crc = 0
    sha256 = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            crc = zlib.crc32(chunk, crc)
            sha256.update(chunk)
    return f"{crc & 0xffffffff:08x}", sha256.hexdigest()


def is_text(path: Path) -> bool:
    with path.open("rb") as stream:
        return b"\0" not in stream.read(4096)


def require_file(op: str, value: str | None, label: str) -> Path:
    if not value:
        fail(op, f"{label} is required")
    path = Path(value)
    if not path.is_file():
        fail(op, f"{label} is not a file: {value}")
    return path


def require_dir(op: str, value: str | None, label: str) -> Path:
    if not value:
        fail(op, f"{label} is required")
    path = Path(value)
    if not path.is_dir():
        fail(op, f"{label} is not a directory: {value}")
    return path


def normalize(text: str) -> str:
    if ARGS.unicode_normalize:
        text = unicodedata.normalize("NFKC", text)
    if ARGS.normalize_tabs:
        text = text.expandtabs()
    if ARGS.ignore_newlines:
        text = text.replace("\r\n", "\n").replace("\r", "\n")
    if ARGS.ignore_case:
        text = text.casefold()
    lines = text.splitlines(keepends=True)
    if ARGS.ignore_whitespace:
        lines = [line.strip() + ("\n" if line.endswith(("\n", "\r")) else "") for line in lines]
    if ARGS.ignore_blank:
        lines = [line for line in lines if line.strip()]
    return "".join(lines)


def op_hash() -> None:
    path = require_file("hash", ARGS.target, "target")
    stat = path.stat()
    crc32, sha256 = file_hashes(path)
    result = {
        "ok": True, "op": "hash", "path": str(path.resolve()), "size": stat.st_size,
        "type": "text" if is_text(path) else "binary", "crc32": crc32, "sha256": sha256,
        "modified": stat.st_mtime, "created": stat.st_ctime,
    }
    emit(result, "\n".join(f"{key}: {value}" for key, value in result.items() if key not in {"ok", "op"}))


def op_compare() -> None:
    left = require_file("compare", ARGS.target, "target")
    right = require_file("compare", ARGS.other, "other")
    left_text, right_text = is_text(left), is_text(right)
    effective_mode = ARGS.mode
    if effective_mode == "smart" and not (left_text and right_text):
        fail("compare", "smart mode requires two text files; use --mode exact for binary data")

    diff: list[str] = []
    truncated = False
    left_crc, left_sha = file_hashes(left)
    right_crc, right_sha = file_hashes(right)
    if effective_mode == "smart":
        left_value = normalize(left.read_text(encoding="utf-8", errors="replace"))
        right_value = normalize(right.read_text(encoding="utf-8", errors="replace"))
        identical = left_value == right_value
        if not identical:
            generated = difflib.unified_diff(
                left_value.splitlines(), right_value.splitlines(),
                fromfile=str(left), tofile=str(right), lineterm="",
            )
            diff = list(_take(generated, ARGS.max_diff_lines + 1))
            truncated = len(diff) > ARGS.max_diff_lines
            diff = diff[:ARGS.max_diff_lines]
    else:
        identical = left_sha == right_sha

    result = {
        "ok": True, "op": "compare", "identical": identical, "mode": effective_mode,
        "left": {"path": str(left.resolve()), "size": left.stat().st_size, "crc32": left_crc, "sha256": left_sha},
        "right": {"path": str(right.resolve()), "size": right.stat().st_size, "crc32": right_crc, "sha256": right_sha},
        "diff": diff, "diffTruncated": truncated,
    }
    text = ("IDENTICAL" if identical else "DIFFERENT")
    if diff:
        text += "\n" + "\n".join(diff) + ("\n... diff truncated" if truncated else "")
    emit(result, text)


def _take(values: Iterable[str], count: int) -> Iterable[str]:
    for index, value in enumerate(values):
        if index >= count:
            break
        yield value


def walk_files(root: Path) -> Iterable[tuple[str, Path]]:
    root = root.resolve()
    for current, dirs, files in os.walk(root, followlinks=False):
        relative_dir = Path(current).relative_to(root)
        depth = len(relative_dir.parts)
        dirs[:] = sorted(d for d in dirs if (ARGS.include_hidden or not d.startswith(".")) and depth < ARGS.depth)
        if depth > ARGS.depth:
            continue
        for name in sorted(files):
            if ARGS.include_hidden or not name.startswith("."):
                path = Path(current) / name
                if not path.is_symlink() and path.is_file():
                    yield path.relative_to(root).as_posix(), path


def inventory(root: Path, include_binary: bool = True) -> dict[str, dict[str, Any]]:
    found: dict[str, dict[str, Any]] = {}
    for relative, path in walk_files(root):
        text = is_text(path)
        if include_binary or text:
            crc32, sha256 = file_hashes(path)
            found[relative] = {"size": path.stat().st_size, "text": text, "crc32": crc32, "sha256": sha256}
    return found


def op_folder_compare() -> None:
    left = require_dir("folder-compare", ARGS.target, "target")
    right = require_dir("folder-compare", ARGS.other, "other")
    left_files = inventory(left, ARGS.binary)
    right_files = inventory(right, ARGS.binary)
    left_names, right_names = set(left_files), set(right_files)
    common = sorted(left_names & right_names)
    identical = [name for name in common if left_files[name]["sha256"] == right_files[name]["sha256"]]
    different = [name for name in common if left_files[name]["sha256"] != right_files[name]["sha256"]]
    result = {
        "ok": True, "op": "folder-compare", "left": str(left.resolve()), "right": str(right.resolve()),
        "identical": identical, "different": different,
        "leftOnly": sorted(left_names - right_names), "rightOnly": sorted(right_names - left_names),
        "counts": {"left": len(left_files), "right": len(right_files), "identical": len(identical),
                   "different": len(different), "leftOnly": len(left_names - right_names),
                   "rightOnly": len(right_names - left_names)},
    }
    emit(result, json.dumps(result, indent=2))


def op_duplicates() -> None:
    root = require_dir("duplicates", ARGS.target, "target")
    groups: dict[tuple[int, str], list[str]] = {}
    for relative, path in walk_files(root):
        size = path.stat().st_size
        sha256 = file_hashes(path)[1]
        groups.setdefault((size, sha256), []).append(relative)
    duplicates = [
        {"size": size, "sha256": digest, "files": files, "wastedBytes": size * (len(files) - 1)}
        for (size, digest), files in sorted(groups.items()) if len(files) > 1
    ]
    result = {
        "ok": True, "op": "duplicates", "path": str(root.resolve()),
        "fileCount": sum(len(files) for files in groups.values()), "duplicateGroups": duplicates,
        "duplicateGroupCount": len(duplicates), "wastedBytes": sum(group["wastedBytes"] for group in duplicates),
    }
    emit(result, json.dumps(result, indent=2))


def op_lines() -> None:
    path = require_file("lines", ARGS.target, "target")
    if not is_text(path):
        fail("lines", f"target is not a text file: {path}")
    if ARGS.start < 1 or ARGS.context < 0 or (ARGS.end is not None and ARGS.end < ARGS.start):
        fail("lines", "require start >= 1, context >= 0, and end >= start")
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    end = min(ARGS.end if ARGS.end is not None else len(lines), len(lines))
    actual_start, actual_end = max(1, ARGS.start - ARGS.context), min(len(lines), end + ARGS.context)
    selected = [
        {"number": number, "text": lines[number - 1], "selected": ARGS.start <= number <= end}
        for number in range(actual_start, actual_end + 1)
    ]
    result = {"ok": True, "op": "lines", "path": str(path.resolve()), "totalLines": len(lines), "lines": selected}
    text = "\n".join(f"{'>>> ' if line['selected'] else '    '}{line['number']:4d}| {line['text']}" for line in selected)
    emit(result, text)


parser = argparse.ArgumentParser(description="Compare files and folders, find duplicates, hash files, or read line ranges")
parser.add_argument("op", choices=["compare", "folder-compare", "duplicates", "hash", "lines"])
parser.add_argument("target")
parser.add_argument("other", nargs="?")
parser.add_argument("--mode", choices=["exact", "smart"], default="exact")
parser.add_argument("--ignore-blank", action="store_true")
parser.add_argument("--ignore-newlines", action="store_true")
parser.add_argument("--ignore-whitespace", action="store_true")
parser.add_argument("--ignore-case", action="store_true")
parser.add_argument("--normalize-tabs", action="store_true")
parser.add_argument("--unicode-normalize", action="store_true")
parser.add_argument("--binary", action="store_true", help="include binary files in folder comparison")
parser.add_argument("--include-hidden", action="store_true")
parser.add_argument("--depth", type=int, default=10)
parser.add_argument("--start", type=int, default=1)
parser.add_argument("--end", type=int)
parser.add_argument("--context", type=int, default=0)
parser.add_argument("--max-diff-lines", type=int, default=2000)
parser.add_argument("--format", choices=["text", "json"], default="json")
ARGS = parser.parse_args()

if ARGS.depth < 0 or ARGS.max_diff_lines < 0:
    fail(ARGS.op, "depth and max-diff-lines must be non-negative")

try:
    {"compare": op_compare, "folder-compare": op_folder_compare, "duplicates": op_duplicates,
     "hash": op_hash, "lines": op_lines}[ARGS.op]()
except OSError as error:
    fail(ARGS.op, str(error))

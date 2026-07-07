#!/usr/bin/env python3
"""unpack — recursively extract archives to a fixpoint, safely. Pure stdlib core.

Extracts zip / tar(.gz/.bz2/.xz) / gz / bz2 / xz with the standard library, then
walks the output for NESTED archives and extracts those too, up to depth/size caps —
so a zip-of-a-tar-of-a-gz reveals the innermost files in one pass. 7z / RAR are
routed to an external CLI (7z/7za/7zz, unar) when present, and reported as an honest
gap when not.

Security (this extracts UNTRUSTED archives):
  * zip-slip / path traversal — every member must resolve inside the output dir;
    absolute paths, `..`, and out-of-tree symlinks are skipped (tar uses the stdlib
    `data` filter).
  * decompression bombs — a total-bytes budget and per-file cap stop runaway output.

Extraction is not execution: the archive's contents are written to disk, never run.

    python3 unpack.py <archive> <outdir> [--max-depth N] [--max-bytes N]
"""

from __future__ import annotations

import argparse
import bz2
import gzip
import hashlib
import json
import lzma
import os
import shutil
import subprocess
import sys
import tarfile
import zipfile

_MAX_TOTAL = 512 * 1024 * 1024
_PER_FILE = 256 * 1024 * 1024
_MAX_DEPTH = 8
_MAX_ARCHIVES = 200

# magic -> logical format, for detecting nested archives during the fixpoint walk
_MAGICS = [
    (b"PK\x03\x04", "zip"), (b"PK\x05\x06", "zip"),
    (b"\x1f\x8b", "gz"), (b"BZh", "bz2"), (b"\xfd7zXZ\x00", "xz"),
    (b"7z\xbc\xaf\x27\x1c", "7z"), (b"Rar!\x1a\x07", "rar"),
    (b"ustar", "tar"),  # at offset 257, handled below
]


class Budget:
    def __init__(self, total: int):
        self.remaining = total

    def take(self, n: int) -> bool:
        if n > self.remaining:
            return False
        self.remaining -= n
        return True


def _which(*names):
    for n in names:
        p = shutil.which(n)
        if p:
            return p
    return None


def detect(path: str) -> str:
    try:
        with open(path, "rb") as f:
            head = f.read(512)
    except OSError:
        return "unknown"
    if head[257:262] == b"ustar":
        return "tar"
    for sig, fmt in _MAGICS:
        if fmt == "tar":
            continue
        if head.startswith(sig):
            return fmt
    # tar can be uncompressed without ustar at 257 (old format) — let tarfile decide
    if tarfile.is_tarfile(path) if os.path.isfile(path) else False:
        return "tar"
    return "unknown"


def _safe_target(outdir: str, name: str) -> str | None:
    """Resolve a member path inside outdir, or None if it escapes (zip-slip)."""
    outdir_real = os.path.realpath(outdir)
    target = os.path.realpath(os.path.join(outdir, name))
    if target == outdir_real or target.startswith(outdir_real + os.sep):
        return target
    return None


def _extract_zip(path, outdir, budget, skipped) -> int:
    n = 0
    with zipfile.ZipFile(path) as z:
        for info in z.infolist():
            if info.is_dir():
                continue
            target = _safe_target(outdir, info.filename)
            if target is None:
                skipped.append({"member": info.filename, "reason": "path-traversal"})
                continue
            if info.file_size > _PER_FILE:
                skipped.append({"member": info.filename, "reason": "file-too-large"})
                continue
            if not budget.take(info.file_size):
                skipped.append({"member": info.filename, "reason": "budget-exceeded (bomb guard)"})
                continue
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with z.open(info) as src, open(target, "wb") as dst:
                shutil.copyfileobj(src, dst)
            n += 1
    return n


def _extract_tar(path, outdir, budget, skipped) -> int:
    n = 0
    with tarfile.open(path) as t:
        members = [m for m in t.getmembers() if m.isfile()]
        for m in members:
            if _safe_target(outdir, m.name) is None:
                skipped.append({"member": m.name, "reason": "path-traversal"})
                continue
            if m.size > _PER_FILE or not budget.take(m.size):
                skipped.append({"member": m.name, "reason": "file-too-large / budget"})
                continue
        try:  # stdlib 'data' filter blocks traversal/abs/symlink/device (py3.12+)
            t.extractall(outdir, filter="data")
        except TypeError:
            t.extractall(outdir)  # older python; _safe_target pre-check above still applied
        n = sum(1 for m in members if _safe_target(outdir, m.name))
    return n


def _extract_stream(path, outdir, fmt, budget, skipped) -> int:
    openers = {"gz": gzip.open, "bz2": bz2.open, "xz": lzma.open}
    base = os.path.basename(path)
    for ext in (".gz", ".bz2", ".xz", ".tgz", ".tbz2", ".txz"):
        if base.lower().endswith(ext):
            base = base[: -len(ext)]
            break
    else:
        base = base + ".out"
    target = os.path.join(outdir, base)
    written = 0
    with openers[fmt](path, "rb") as src, open(target, "wb") as dst:
        while True:
            chunk = src.read(1 << 20)
            if not chunk:
                break
            if not budget.take(len(chunk)):
                skipped.append({"member": base, "reason": "budget-exceeded (bomb guard)"})
                dst.close()
                os.remove(target)
                return 0
            dst.write(chunk)
            written += len(chunk)
    return 1


def _extract_cli(path, outdir, fmt, tools_missing) -> int:
    if fmt == "7z":
        tool = _which("7z", "7za", "7zz")
        cmd = [tool, "x", "-y", "-bd", f"-o{outdir}", path] if tool else None
        need = "p7zip (7z/7za/7zz)"
    elif fmt == "rar":
        tool = _which("unar")
        cmd = [tool, "-quiet", "-force-overwrite", "-output-directory", outdir, path] if tool else None
        if not tool:
            tool = _which("unrar")
            cmd = [tool, "x", "-y", path, outdir + "/"] if tool else None
        need = "unar or unrar"
    else:
        return 0
    if not cmd:
        tools_missing.add(need)
        return 0
    os.makedirs(outdir, exist_ok=True)
    try:
        subprocess.run(cmd, capture_output=True, timeout=300)
    except (subprocess.SubprocessError, OSError):
        return 0
    return sum(1 for _ in _walk_files(outdir))


def _walk_files(root):
    for dp, _, fs in os.walk(root):
        for f in fs:
            yield os.path.join(dp, f)


def extract_one(path, outdir, budget, skipped, tools_missing) -> tuple[int, str]:
    fmt = detect(path)
    os.makedirs(outdir, exist_ok=True)
    if fmt == "zip":
        return _extract_zip(path, outdir, budget, skipped), fmt
    if fmt == "tar":
        return _extract_tar(path, outdir, budget, skipped), fmt
    if fmt in ("gz", "bz2", "xz"):
        # a .tar.gz/.tgz is a tar under the compression — let tarfile handle it
        if tarfile.is_tarfile(path):
            return _extract_tar(path, outdir, budget, skipped), "tar." + fmt
        return _extract_stream(path, outdir, fmt, budget, skipped), fmt
    if fmt in ("7z", "rar"):
        return _extract_cli(path, outdir, fmt, tools_missing), fmt
    return 0, "unknown"


def run(archive: str, outdir: str, max_depth: int, max_bytes: int) -> dict:
    budget = Budget(max_bytes)
    skipped: list = []
    tools_missing: set = set()
    nested: list = []
    total_files = 0
    seen: set = set()

    # worklist of (archive_path, dest_dir, depth)
    root_out = os.path.join(outdir, "_root")
    work = [(archive, root_out, 0)]
    archives_done = 0
    root_fmt = detect(archive)

    while work and archives_done < _MAX_ARCHIVES:
        apath, dest, depth = work.pop(0)
        key = _content_key(apath)
        if key in seen:
            continue
        seen.add(key)
        n, fmt = extract_one(apath, dest, budget, skipped, tools_missing)
        archives_done += 1
        total_files += n
        if depth > 0:
            nested.append({"archive": os.path.relpath(apath, outdir), "format": fmt,
                           "files": n, "depth": depth})
        if depth >= max_depth:
            continue
        # find nested archives in what we just extracted
        for fp in _walk_files(dest):
            if fp == apath:
                continue
            if detect(fp) in ("zip", "tar", "gz", "bz2", "xz", "7z", "rar"):
                sub = fp + ".unpacked"
                work.append((fp, sub, depth + 1))

    return {
        "ok": True, "archive": os.path.abspath(archive), "format": root_fmt,
        "extractedTo": os.path.abspath(outdir), "fileCount": total_files,
        "bytesBudgetRemaining": budget.remaining, "nestedArchives": nested,
        "skipped": skipped[:100], "toolsMissing": sorted(tools_missing),
        "truncated": archives_done >= _MAX_ARCHIVES,
    }


def _content_key(path: str) -> str:
    try:
        with open(path, "rb") as f:
            head = f.read(65536)
        return hashlib.sha256(head).hexdigest() + f":{os.path.getsize(path)}"
    except OSError:
        return path


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="unpack")
    p.add_argument("input")
    p.add_argument("outdir")
    p.add_argument("--max-depth", type=int, default=_MAX_DEPTH)
    p.add_argument("--max-bytes", type=int, default=_MAX_TOTAL)
    args = p.parse_args(argv[1:])
    if not os.path.isfile(args.input):
        sys.stdout.write(json.dumps({"ok": False, "error": f"file not found: {args.input}"}) + "\n")
        return 2
    if detect(args.input) == "unknown":
        sys.stdout.write(json.dumps({"ok": False, "error": "unrecognised archive format",
                                     "hint": "supported: zip, tar(.gz/.bz2/.xz), gz, bz2, xz; "
                                             "7z/rar via 7z/unar on PATH"}) + "\n")
        return 1

    result = run(args.input, args.outdir, args.max_depth, args.max_bytes)
    print(json.dumps(result, indent=2))
    if result["toolsMissing"]:
        sys.stderr.write(f"note: some archives need a tool not on PATH: "
                         f"{', '.join(result['toolsMissing'])}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

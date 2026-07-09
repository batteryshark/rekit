#!/usr/bin/env python3
"""pyinstaller-extract — carve the Python out of a PyInstaller executable.

PyInstaller bundles an app's `.pyc` modules (plus data and native libs) into a
"CArchive" appended to the frozen executable. This finds that archive, extracts every
entry, and unpacks the inner **PYZ** archive into individual `.pyc` files with a
reconstructed header — ready for `pyc-decompile`.

Static and read-only: it parses the archive structures and (once) `marshal.loads`
the PYZ table of contents (deserialization, NOT execution). It never runs the
executable or the extracted code.

    python3 extract.py <pyinstaller-exe> <outdir> [--format text|json]
"""

from __future__ import annotations

import argparse
import json
import marshal
import os
import struct
import sys
import zlib

_MAGIC = b"MEI\014\013\012\013\016"  # PyInstaller cookie magic
_COOKIE_V20 = struct.Struct("!8sIIII")        # magic, lenPkg, toc, tocLen, pyver
_COOKIE_V21 = struct.Struct("!8sIIII64s")     # + pylibname
_ENTRY = struct.Struct("!IIIIBc")             # entrySize, pos, csize, usize, cflag, type
_PER_FILE = 256 * 1024 * 1024


def _safe(outdir: str, name: str) -> str | None:
    name = name.replace("\\", "/").lstrip("/")
    target = os.path.realpath(os.path.join(outdir, name))
    root = os.path.realpath(outdir)
    return target if (target == root or target.startswith(root + os.sep)) else None


def _reconstruct_pyc(pyc_magic: bytes, code_bytes: bytes) -> bytes:
    # 3.7+ header = 4-byte magic + 4 flags + 4 mtime + 4 size = 16 bytes. Decompilers
    # read the version from the magic; the other fields are ignored, so zero them.
    return pyc_magic + b"\x00" * 12 + code_bytes


def _extract_pyz(pyz: bytes, outdir: str, skipped: list) -> int:
    if pyz[:4] != b"PYZ\x00":
        return 0
    pyc_magic = pyz[4:8]
    toc_pos = struct.unpack("!I", pyz[8:12])[0]
    try:
        toc = marshal.loads(pyz[toc_pos:])  # deserialize (does not execute)
    except Exception:
        return 0
    items = toc.items() if isinstance(toc, dict) else toc
    n = 0
    for entry in items:
        try:
            name, (is_pkg, pos, length) = entry
        except (ValueError, TypeError):
            continue
        name = name.decode() if isinstance(name, bytes) else str(name)
        rel = name.replace(".", "/") + ("/__init__.pyc" if is_pkg else ".pyc")
        target = _safe(outdir, os.path.join("PYZ-contents", rel))
        if target is None:
            skipped.append({"member": rel, "reason": "path-traversal"})
            continue
        blob = pyz[pos:pos + length]
        try:
            blob = zlib.decompress(blob)
        except zlib.error:
            pass
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "wb") as f:
            f.write(_reconstruct_pyc(pyc_magic, blob))
        n += 1
    return n


def analyze(path: str, outdir: str):
    with open(path, "rb") as f:
        data = f.read()
    pos = data.rfind(_MAGIC)
    if pos == -1:
        return {"isPyInstaller": False,
                "note": "no PyInstaller cookie found — not a PyInstaller executable"}, [], 0

    if len(data) - pos >= _COOKIE_V21.size:
        magic, len_pkg, toc, toc_len, pyver, _lib = _COOKIE_V21.unpack(data[pos:pos + _COOKIE_V21.size])
        cookie_size = _COOKIE_V21.size
    else:
        magic, len_pkg, toc, toc_len, pyver = _COOKIE_V20.unpack(data[pos:pos + _COOKIE_V20.size])
        cookie_size = _COOKIE_V20.size

    tail = len(data) - pos - cookie_size
    overlay_pos = len(data) - (len_pkg + tail)
    toc_pos = overlay_pos + toc

    skipped: list = []
    os.makedirs(outdir, exist_ok=True)
    entries, pyz_modules, files = [], 0, 0
    pyc_magic = None
    scripts: list = []   # (name, marshalled-code) for s/m/M entries — .pyc after we know the magic
    parsed = 0
    toc_blob = data[toc_pos:toc_pos + toc_len]
    while parsed + _ENTRY.size <= len(toc_blob):
        e_size, e_pos, c_size, u_size, c_flag, e_type = _ENTRY.unpack(toc_blob[parsed:parsed + _ENTRY.size])
        if e_size <= 0:
            break
        name = toc_blob[parsed + _ENTRY.size:parsed + e_size].rstrip(b"\x00").decode("utf-8", "replace")
        parsed += e_size
        t = e_type.decode("latin-1")
        entries.append({"name": name, "type": t, "size": u_size})
        if u_size > _PER_FILE:
            skipped.append({"member": name, "reason": "file-too-large"})
            continue
        raw = data[overlay_pos + e_pos:overlay_pos + e_pos + c_size]
        if c_flag:
            try:
                raw = zlib.decompress(raw)
            except zlib.error:
                pass
        target = _safe(outdir, name)
        if target is None:
            skipped.append({"member": name, "reason": "path-traversal"})
            continue
        os.makedirs(os.path.dirname(target) or outdir, exist_ok=True)
        with open(target, "wb") as f:
            f.write(raw)
        files += 1
        if t in ("z", "Z") or raw[:4] == b"PYZ\x00":  # PYZ archive → carve modules
            if raw[:4] == b"PYZ\x00":
                pyc_magic = raw[4:8]
            pyz_modules += _extract_pyz(raw, outdir, skipped)
        elif t in ("s", "m", "M"):  # entry-point script / module: marshalled code, no header
            scripts.append((name, raw))

    # Reconstruct .pyc for the script/module entries now that we know the magic.
    scripts_recovered = 0
    if pyc_magic:
        for name, raw in scripts:
            target = _safe(outdir, os.path.join("PYZ-contents", name.replace("/", "_") + ".pyc"))
            if target is None:
                continue
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with open(target, "wb") as f:
                f.write(_reconstruct_pyc(pyc_magic, raw))
            scripts_recovered += 1

    info = {
        "isPyInstaller": True, "pythonVersion": f"{pyver // 100}.{pyver % 100}",
        "archiveEntries": len(entries), "filesWritten": files,
        "pyzModulesExtracted": pyz_modules, "scriptsRecovered": scripts_recovered,
        "extractedTo": os.path.abspath(outdir),
        "entryTypes": sorted({e["type"] for e in entries}), "skipped": skipped[:50],
    }
    return info, entries, pyz_modules


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="pyinstaller-extract")
    p.add_argument("input")
    p.add_argument("outdir")
    p.add_argument("--format", choices=["text", "json"], default="text")
    args = p.parse_args(argv[1:])
    if not os.path.isfile(args.input):
        sys.stdout.write(json.dumps({"ok": False, "error": f"file not found: {args.input}"}) + "\n")
        return 2

    try:
        info, entries, pyz_modules = analyze(args.input, args.outdir)
    except Exception as exc:  # pragma: no cover
        sys.stdout.write(json.dumps({"ok": False, "error": f"extract failed: {exc}"}) + "\n")
        return 1

    result = {"ok": True, "path": os.path.abspath(args.input), **info}
    if args.format == "json":
        sys.stdout.write(json.dumps(result) + "\n")
        return 0

    if not info.get("isPyInstaller"):
        print(f"pyinstaller-extract: {info['note']}")
        return 1
    print(f"pyinstaller-extract: {os.path.basename(args.input)}  (Python {info['pythonVersion']})")
    print(f"  archive entries: {info['archiveEntries']}  written: {info['filesWritten']}  "
          f"PYZ .pyc modules: {info['pyzModulesExtracted']}  scripts→.pyc: {info['scriptsRecovered']}")
    print(f"  entry types: {', '.join(info['entryTypes'])}")
    print(f"  → {info['extractedTo']}  (decompile the PYZ-contents/*.pyc with pyc-decompile)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

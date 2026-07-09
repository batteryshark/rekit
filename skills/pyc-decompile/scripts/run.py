#!/usr/bin/env python3
"""Runner for the pyc-decompile skill.

Adds the vendored ./site to sys.path, detects the target bytecode's Python
version (via xdis), and decompiles with decompyle3 — writing decompiled.py and
printing ONE json result line.

    python3 run.py <input.pyc> <outdir>

STATIC: xdis unmarshals the code object and decompyle3 reconstructs source from
disassembled bytecode. The .pyc is never imported, exec'd, or run.
"""

from __future__ import annotations

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "site"))

# decompyle3 targets these CPython bytecode versions.
_SUPPORTED = {(3, 7), (3, 8)}


def emit(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj) + "\n")


def fail(msg: str, code: int = 1) -> None:
    emit({"ok": False, "error": msg})
    raise SystemExit(code)


def detect_version(path: str):
    """Return (major, minor) of the .pyc's bytecode, or None."""
    try:
        from xdis import load
        info = load.load_module(path)
        ver = info[0] if isinstance(info, (tuple, list)) else None
        if ver:
            return (int(ver[0]), int(ver[1]))
    except Exception:
        pass
    return None


def main(argv: list[str]) -> int:
    if len(argv) < 3:
        fail("usage: run.py <input.pyc> <outdir>", 2)
    inp, outdir = argv[1], argv[2]
    if not os.path.isfile(inp):
        fail(f"input not found: {inp}", 2)

    vshort = detect_version(inp)
    supported = (vshort in _SUPPORTED) if vshort else None

    os.makedirs(outdir, exist_ok=True)
    outfile = os.path.join(outdir, "decompiled.py")

    try:
        import contextlib
        import io
        import decompyle3
        with open(outfile, "w", encoding="utf-8") as fh:
            # decompile_file's default showgrammar prints a grammar-derivation trace
            # to stdout; silence stdout so our contract (one JSON line) stays clean.
            # The reconstructed source is written to `fh`, not stdout.
            with contextlib.redirect_stdout(io.StringIO()):
                decompyle3.decompile_file(inp, fh, showgrammar={})
    except Exception as exc:  # unsupported version, corrupt bytecode, grammar gap
        note = ""
        if vshort and not supported:
            note = (f" Detected bytecode Python {vshort[0]}.{vshort[1]}, which is outside "
                    f"decompyle3's 3.7-3.8 range — use uncompyle6 for older bytecode, or a "
                    f"version-matched decompiler for 3.9+.")
        # Clean up any partial file so a failure never looks like a result.
        try:
            if os.path.exists(outfile):
                os.remove(outfile)
        except OSError:
            pass
        fail(f"decompyle3 failed: {exc}.{note}")

    src = ""
    try:
        with open(outfile, encoding="utf-8") as fh:
            src = fh.read()
    except OSError:
        pass

    emit({
        "ok": True,
        "outputFile": os.path.abspath(outfile),
        "detectedVersion": f"{vshort[0]}.{vshort[1]}" if vshort else None,
        "supported": supported,
        "bytesOut": len(src.encode("utf-8")),
    })
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

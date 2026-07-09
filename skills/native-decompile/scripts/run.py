#!/usr/bin/env python3
"""native-decompile — decompile a native binary (ELF/PE/Mach-O) with rizin.

Uses rizin's built-in Ghidra decompiler (`pdg`) over all functions. Requires `rizin`
(or `r2`) on PATH. Static: rizin analyses and decompiles; it does not run the target.
Pair with elf/pe/macho-analyze (triage first, decompile the interesting function).

    python3 run.py <binary> <outdir> [--format text|json]
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="native-decompile")
    p.add_argument("input")
    p.add_argument("outdir")
    p.add_argument("--format", choices=["text", "json"], default="text")
    a = p.parse_args(argv[1:])
    if not os.path.isfile(a.input):
        print(json.dumps({"ok": False, "error": f"file not found: {a.input}"}))
        return 2
    tool = shutil.which("rizin") or shutil.which("r2")
    if not tool:
        print(json.dumps({"ok": False, "error": "rizin/r2 not on PATH",
                          "hint": "install rizin (https://rizin.re) — its `pdg` is a built-in Ghidra decompiler"}))
        return 3
    os.makedirs(a.outdir, exist_ok=True)
    # analyse all, then decompile every function (@@F) with the Ghidra decompiler.
    cmd = [tool, "-q", "-e", "scr.color=0", "-c", "aaa; pdg @@F", a.input]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
    except (subprocess.SubprocessError, OSError) as exc:
        print(json.dumps({"ok": False, "error": f"rizin failed: {exc}"}))
        return 1
    out = os.path.join(a.outdir, "decompiled.c")
    with open(out, "w", encoding="utf-8") as f:
        f.write(proc.stdout or "")
    ok = bool((proc.stdout or "").strip())
    res = {"ok": ok, "tool": os.path.basename(tool), "outputFile": os.path.abspath(out),
           "bytes": len(proc.stdout or ""), "exitCode": proc.returncode}
    if a.format == "json":
        print(json.dumps(res))
    else:
        print(f"native-decompile: {res['bytes']} bytes of pseudocode → {out}  ({res['tool']} exit {proc.returncode})")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

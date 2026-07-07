#!/usr/bin/env python3
"""jvm-decompile — decompile Java/Android (.apk/.dex/.jar/.class) to source with jadx.

Requires `jadx` on PATH (jadx needs a JRE). Static: jadx reads bytecode and
reconstructs source; it does not execute the input. The dispatcher won't even reach
this runner unless the `jadx` prerequisite is satisfied.

    python3 run.py <input> <outdir> [--format text|json]
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="jvm-decompile")
    p.add_argument("input")
    p.add_argument("outdir")
    p.add_argument("--format", choices=["text", "json"], default="text")
    a = p.parse_args(argv[1:])
    if not os.path.isfile(a.input):
        print(json.dumps({"ok": False, "error": f"file not found: {a.input}"}))
        return 2
    jadx = shutil.which("jadx")
    if not jadx:
        print(json.dumps({"ok": False, "error": "jadx not on PATH",
                          "hint": "install jadx (https://github.com/skylot/jadx); needs a JRE"}))
        return 3
    os.makedirs(a.outdir, exist_ok=True)
    try:
        proc = subprocess.run([jadx, "--no-res", "-d", a.outdir, a.input],
                              capture_output=True, text=True, timeout=1800)
    except (subprocess.SubprocessError, OSError) as exc:
        print(json.dumps({"ok": False, "error": f"jadx failed: {exc}"}))
        return 1
    files = sum(len(fs) for _, _, fs in os.walk(a.outdir))
    res = {"ok": files > 0, "tool": "jadx", "outputDir": os.path.abspath(a.outdir),
           "filesWritten": files, "exitCode": proc.returncode}
    if a.format == "json":
        print(json.dumps(res))
    else:
        print(f"jvm-decompile: {files} file(s) → {a.outdir}  (jadx exit {proc.returncode})")
    return 0 if res["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

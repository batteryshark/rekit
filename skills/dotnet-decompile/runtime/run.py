#!/usr/bin/env python3
"""dotnet-decompile — decompile a .NET assembly (IL) to C# with ilspycmd.

Requires the `ilspycmd` dotnet tool on PATH (which needs the .NET runtime). Static:
ilspycmd reads metadata + IL and reconstructs C#; it does not run the assembly. Pair
with dotnet-analyze (which finds the P/Invoke surface first).

    python3 run.py <assembly.dll|exe> <outdir> [--format text|json]
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="dotnet-decompile")
    p.add_argument("input")
    p.add_argument("outdir")
    p.add_argument("--format", choices=["text", "json"], default="text")
    a = p.parse_args(argv[1:])
    if not os.path.isfile(a.input):
        print(json.dumps({"ok": False, "error": f"file not found: {a.input}"}))
        return 2
    tool = shutil.which("ilspycmd")
    if not tool:
        print(json.dumps({"ok": False, "error": "ilspycmd not on PATH",
                          "hint": "dotnet tool install -g ilspycmd (needs the .NET SDK/runtime)"}))
        return 3
    os.makedirs(a.outdir, exist_ok=True)
    try:
        proc = subprocess.run([tool, a.input, "-o", a.outdir], capture_output=True, text=True, timeout=1800)
    except (subprocess.SubprocessError, OSError) as exc:
        print(json.dumps({"ok": False, "error": f"ilspycmd failed: {exc}"}))
        return 1
    files = sum(len(fs) for _, _, fs in os.walk(a.outdir))
    res = {"ok": files > 0, "tool": "ilspycmd", "outputDir": os.path.abspath(a.outdir),
           "filesWritten": files, "exitCode": proc.returncode}
    if a.format == "json":
        print(json.dumps(res))
    else:
        print(f"dotnet-decompile: {files} file(s) → {a.outdir}  (ilspycmd exit {proc.returncode})")
    return 0 if res["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

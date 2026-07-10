#!/usr/bin/env python3
"""ghidra-decompile — decompile a native binary with Ghidra headless.

The higher-fidelity option above native-decompile (rizin's `pdg`): full Ghidra
auto-analysis + decompiler via `analyzeHeadless`, driven by the bundled Ghidra
script `ghidra_decompile.py` (decompiles every function to one C file). Static:
Ghidra analyses and decompiles; it never runs the binary.

Requires Ghidra's `analyzeHeadless` (Ghidra + a JRE 17+). It's usually at
`<ghidra>/support/analyzeHeadless` — put it on PATH or set `GHIDRA_HOME`.

    python3 run.py <binary> <outdir> [--format text|json]
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile


def _find_headless() -> str | None:
    t = shutil.which("analyzeHeadless")
    if t:
        return t
    for env in ("GHIDRA_HOME", "GHIDRA_INSTALL_DIR", "GHIDRA_ROOT"):
        h = os.environ.get(env)
        if h:
            cand = os.path.join(h, "support", "analyzeHeadless")
            if os.path.isfile(cand):
                return cand
    return None


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="ghidra-decompile")
    p.add_argument("input")
    p.add_argument("outdir")
    p.add_argument("--format", choices=["text", "json"], default="text")
    a = p.parse_args(argv[1:])
    if not os.path.isfile(a.input):
        print(json.dumps({"ok": False, "error": f"file not found: {a.input}"}))
        return 2
    tool = _find_headless()
    if not tool:
        print(json.dumps({"ok": False, "error": "Ghidra analyzeHeadless not found",
                          "hint": "install Ghidra (https://ghidra-sre.org), needs a JRE 17+; put "
                                  "<ghidra>/support/analyzeHeadless on PATH or set GHIDRA_HOME"}))
        return 3
    os.makedirs(a.outdir, exist_ok=True)
    out = os.path.abspath(os.path.join(a.outdir, "decompiled.c"))
    scriptdir = os.path.dirname(os.path.abspath(__file__))
    proj = tempfile.mkdtemp(prefix="ghidra_proj_")
    cmd = [tool, proj, "rekit-project", "-import", os.path.abspath(a.input),
           "-scriptPath", scriptdir, "-postScript", "ghidra_decompile.py", out,
           "-deleteProject", "-analysisTimeoutPerFile", "1800"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=5400)
    except (subprocess.SubprocessError, OSError) as exc:
        print(json.dumps({"ok": False, "error": f"analyzeHeadless failed: {exc}"}))
        return 1
    finally:
        shutil.rmtree(proj, ignore_errors=True)
    size = os.path.getsize(out) if os.path.isfile(out) else 0
    res = {"ok": size > 0, "tool": "ghidra", "outputFile": out, "bytes": size,
           "exitCode": proc.returncode}
    if a.format == "json":
        print(json.dumps(res))
    else:
        print(f"ghidra-decompile: {size} bytes of pseudocode → {out}  (analyzeHeadless exit {proc.returncode})")
    return 0 if res["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

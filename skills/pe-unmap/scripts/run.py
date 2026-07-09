"""pe-unmap — convert between PE alignments (raw ↔ virtual) via hasherezade's pe_unmapper.

Wraps the vendored pe_unmapper.exe (built from libpeconv). Recovers executables
dumped from memory (virtual→raw), maps raw→virtual, or realigns. Windows-only
vendored binary.

    python3 run.py <input> <outdir> [--mode unmap|map|realign] [--base 0xADDR] [--format json|text]
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_EXE = os.path.join(os.path.dirname(_HERE), "bin", "pe_unmapper.exe")

# rekit --mode enum → pe_unmapper /mode char
_MODES = {"unmap": "U", "map": "M", "realign": "R"}


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="pe-unmap")
    p.add_argument("input", help="input PE file (raw or virtual-aligned)")
    p.add_argument("outdir", help="output directory")
    p.add_argument("--mode", choices=list(_MODES), default="unmap",
                   help="unmap=Virtual→Raw [default] | map=Raw→Virtual | realign=Virtual→Raw(Raw==Virtual)")
    p.add_argument("--base", default=None, help="load base address in hex (e.g. 0x10000000); auto-detected if omitted")
    p.add_argument("--out-name", default=None, help="output filename (default: <input-stem>_unmapped.exe)")
    p.add_argument("--format", choices=["text", "json"], default="json")
    a = p.parse_args(argv[1:])

    if sys.platform != "win32" and not (os.environ.get("REKIT_ALLOW_WINE") == "1"):
        print(json.dumps({"ok": False,
                          "error": "pe_unmapper.exe is a Windows binary; run on a Windows analysis host "
                                   "(or set REKIT_ALLOW_WINE=1 to attempt via wine)"}))
        return 3
    if not os.path.isfile(_EXE):
        print(json.dumps({"ok": False, "error": f"vendored payload missing: {_EXE}"}))
        return 3
    if not os.path.isfile(a.input):
        print(json.dumps({"ok": False, "error": f"input not found: {a.input}"}))
        return 2

    os.makedirs(a.outdir, exist_ok=True)
    stem = os.path.splitext(os.path.basename(a.input))[0]
    out_file = os.path.join(a.outdir, a.out_name or f"{stem}_{a.mode}.exe")

    cmd = [_EXE if sys.platform == "win32" else (["wine", _EXE] if os.environ.get("REKIT_ALLOW_WINE") == "1" else _EXE)]
    if isinstance(cmd[0], list):
        cmd = cmd[0]
    cmd += [f"/in", a.input, f"/out", out_file, f"/mode", _MODES[a.mode]]
    if a.base:
        cmd += [f"/base", a.base]

    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except subprocess.TimeoutExpired:
        print(json.dumps({"ok": False, "error": "pe_unmapper timed out"}))
        return 1
    except (OSError, subprocess.SubprocessError) as exc:
        print(json.dumps({"ok": False, "error": f"failed to run pe_unmapper: {exc}"}))
        return 1

    ok = r.returncode == 0 and os.path.isfile(out_file)
    res = {
        "ok": ok, "mode": a.mode, "input": a.input,
        "output": out_file if ok else None,
        "outputSize": os.path.getsize(out_file) if ok else 0,
        "tool": "pe_unmapper (libpeconv)",
        "stdout": (r.stdout or "").strip()[:800],
        "error": None if ok else (r.stderr or r.stdout or f"exit {r.returncode}").strip()[:300],
    }
    if a.format == "json":
        print(json.dumps(res, indent=2))
    else:
        print(("OK: " if ok else "FAIL: ") + (out_file if ok else res["error"]))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))

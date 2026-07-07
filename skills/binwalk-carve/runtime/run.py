#!/usr/bin/env python3
"""binwalk-carve — carve & extract embedded files from a firmware image / blob.

Wraps binwalk (v3 Rust or v2 Python): signature-scan the input, then recursively
extract embedded filesystems, bootloaders, and nested archives. The heavy sibling of
bin-triage's embedded-signature preview. Requires `binwalk` on PATH.

Extraction is version-agnostic: binwalk runs with cwd set to the output dir, so the
carved tree lands there whatever binwalk version is installed.

    python3 run.py <firmware> <outdir> [--format text|json]
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="binwalk-carve")
    p.add_argument("input")
    p.add_argument("outdir")
    p.add_argument("--format", choices=["text", "json"], default="text")
    a = p.parse_args(argv[1:])
    if not os.path.isfile(a.input):
        print(json.dumps({"ok": False, "error": f"file not found: {a.input}"}))
        return 2
    tool = shutil.which("binwalk")
    if not tool:
        print(json.dumps({"ok": False, "error": "binwalk not on PATH",
                          "hint": "install binwalk v3 (https://github.com/ReFirmLabs/binwalk) — a single "
                                  "Rust binary; some extractors also want system tools (unsquashfs, jefferson, …)"}))
        return 3
    os.makedirs(a.outdir, exist_ok=True)
    inp = os.path.abspath(a.input)
    try:
        # -e extracts; cwd=outdir makes the carved tree land under outdir on both v2 and v3.
        proc = subprocess.run([tool, "-e", inp], cwd=a.outdir,
                              capture_output=True, text=True, timeout=3600)
    except (subprocess.SubprocessError, OSError) as exc:
        print(json.dumps({"ok": False, "error": f"binwalk failed: {exc}"}))
        return 1
    files = sum(len(fs) for _, _, fs in os.walk(a.outdir))
    res = {"ok": files > 0, "tool": "binwalk", "extractedTo": os.path.abspath(a.outdir),
           "filesExtracted": files, "exitCode": proc.returncode,
           "scan": (proc.stdout or "")[:2000]}
    if a.format == "json":
        print(json.dumps(res))
    else:
        print(f"binwalk-carve: {files} file(s) carved → {a.outdir}  (binwalk exit {proc.returncode})")
        if proc.stdout:
            print("  --- binwalk scan (head) ---")
            print("\n".join(proc.stdout.splitlines()[:15]))
    return 0 if res["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

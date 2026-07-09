#!/usr/bin/env python3
"""yara-scan — scan a file or directory with YARA rules.

Uses the classic `yara` CLI or the newer `yara-x` (`yara-x`/`yr`) if that's what's on
PATH. Defaults to the bundled starter rule pack; point --rules at a real corpus
(YARA-Rules, Neo23x0/signature-base, your own) for serious coverage. Read-only —
YARA matches patterns; it does not run the target.

    python3 run.py <file-or-dir> [--rules <file|dir>] [--format text|json]
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys

_DEFAULT_RULES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "assets", "starter.yar")


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="yara-scan")
    p.add_argument("input")
    p.add_argument("--rules", default=None, help="rules file/dir (default: bundled starter pack)")
    p.add_argument("--format", choices=["text", "json"], default="text")
    a = p.parse_args(argv[1:])
    if not os.path.exists(a.input):
        print(json.dumps({"ok": False, "error": f"not found: {a.input}"}))
        return 2

    flavor = "yara"
    tool = shutil.which("yara")
    if not tool:
        tool = shutil.which("yara-x") or shutil.which("yr")
        flavor = "yara-x" if tool else flavor
    if not tool:
        print(json.dumps({"ok": False, "error": "yara not on PATH",
                          "hint": "install yara (https://virustotal.github.io/yara/) or "
                                  "yara-x (https://virustotal.github.io/yara-x/)"}))
        return 3

    rules = os.path.abspath(a.rules or _DEFAULT_RULES)
    if not os.path.exists(rules):
        print(json.dumps({"ok": False, "error": f"rules not found: {rules}"}))
        return 2

    recursive = os.path.isdir(a.input)
    if flavor == "yara":
        cmd = [tool, "-w"] + (["-r"] if recursive else []) + [rules, a.input]
    else:  # yara-x
        cmd = [tool, "scan"] + (["-r"] if recursive else []) + [rules, a.input]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
    except (subprocess.SubprocessError, OSError) as exc:
        print(json.dumps({"ok": False, "error": f"{flavor} failed: {exc}"}))
        return 1

    matches = []
    for line in (proc.stdout or "").splitlines():
        line = line.strip()
        if not line or line.startswith("error"):
            continue
        parts = line.split(None, 1)
        matches.append({"rule": parts[0], "target": parts[1] if len(parts) > 1 else ""})

    res = {"ok": True, "tool": flavor, "rules": rules, "matchCount": len(matches),
           "matches": matches[:200], "exitCode": proc.returncode}
    if a.format == "json":
        print(json.dumps(res))
    else:
        print(f"yara-scan: {len(matches)} match(es)  [{flavor}, rules={os.path.basename(rules)}]")
        for m in matches[:50]:
            print(f"  {m['rule']}  {m['target']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

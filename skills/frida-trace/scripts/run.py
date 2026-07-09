"""frida-trace — spawn a target under Frida and trace interesting API calls. DYNAMIC.

Uses `frida-trace` to hook a curated set of network / exec / file / crypto functions,
spawn the target, and log the calls it makes — dynamic instrumentation without a
debugger. Captures the trace for a bounded duration.

⚠️ EXECUTES the target (Frida spawns it). rekit gates this behind --allow-dynamic; the
runner also checks REKIT_ALLOW_DYNAMIC=1 / --yes-i-consent. Run only where you don't
mind the risk.

    python3 run.py <target> [--patterns "recv*,send*,..."] [--timeout N]
                    [--format text|json] [--yes-i-consent]
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys

# Curated default hooks: network, exec, file, crypto — cross-platform-ish globs.
_DEFAULT = ["recv*", "send*", "connect*", "socket", "open", "openat", "read", "write",
            "execve*", "CreateProcess*", "WinExec", "InternetOpen*", "URLDownloadToFile*",
            "Crypt*", "BCrypt*"]


def _consented(a) -> bool:
    return a.yes_i_consent or os.environ.get("REKIT_ALLOW_DYNAMIC") == "1"


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="frida-trace")
    p.add_argument("target")
    p.add_argument("--patterns", default=",".join(_DEFAULT),
                   help="comma-separated function globs to hook")
    p.add_argument("--timeout", type=int, default=20)
    p.add_argument("--format", choices=["text", "json"], default="text")
    p.add_argument("--yes-i-consent", action="store_true")
    a = p.parse_args(argv[1:])
    if not _consented(a):
        print(json.dumps({"ok": False, "error": "frida-trace EXECUTES the target",
                          "hint": "run via `rekit run --allow-dynamic frida-trace …`"}))
        return 4
    if not os.path.isfile(a.target):
        print(json.dumps({"ok": False, "error": f"target not found: {a.target}"}))
        return 2
    tool = shutil.which("frida-trace")
    if not tool:
        print(json.dumps({"ok": False, "error": "frida-trace not on PATH",
                          "hint": "pip install frida-tools (needs the frida native core)"}))
        return 3

    target = os.path.abspath(a.target)
    cmd = [tool, "-f", target]
    for pat in a.patterns.split(","):
        pat = pat.strip()
        if pat:
            cmd += ["-i", pat]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=a.timeout)
        out = proc.stdout or ""
    except subprocess.TimeoutExpired as exc:
        out = (exc.stdout or "") if isinstance(exc.stdout, str) else (exc.stdout or b"").decode("utf-8", "replace")
    except (OSError, subprocess.SubprocessError) as exc:
        print(json.dumps({"ok": False, "error": f"frida-trace failed: {exc}"}))
        return 1

    # frida-trace logs like "  1234 ms  funcName(args)" — count per hooked function.
    hits: dict = {}
    for m in re.finditer(r"^\s*\d+\s*ms\s+([A-Za-z_][\w:]*)\(", out, re.M):
        fn = m.group(1)
        hits[fn] = hits.get(fn, 0) + 1
    res = {"ok": True, "tool": "frida-trace", "target": target,
           "hookedCalls": dict(sorted(hits.items(), key=lambda x: -x[1])[:40]),
           "totalCalls": sum(hits.values()), "raw": out[:4000]}
    if a.format == "json":
        print(json.dumps(res))
        return 0
    print(f"frida-trace: {os.path.basename(target)}  {res['totalCalls']} hooked call(s)")
    for fn, n in list(res["hookedCalls"].items())[:15]:
        print(f"  {fn:32} {n}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

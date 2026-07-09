#!/usr/bin/env python3
"""syscall-trace — run a target under a syscall tracer and summarize. DYNAMIC.

Uses `strace` (Linux) or `dtruss` (macOS; needs root + a permissive SIP). Runs the
target, records its syscalls, and summarizes the behaviour: files opened, network
connects, processes exec'd, and a syscall histogram.

⚠️ EXECUTES the target. rekit gates this behind --allow-dynamic; the runner also
refuses direct calls without REKIT_ALLOW_DYNAMIC=1 / --yes-i-consent. Run it only where
you don't mind the risk.

    python3 run.py <target> [--timeout N] [--format text|json] [--yes-i-consent]
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys


def _consented(a) -> bool:
    return a.yes_i_consent or os.environ.get("REKIT_ALLOW_DYNAMIC") == "1"


def _summarize_strace(trace: str) -> dict:
    hist: dict = {}
    files, nets, execs = [], [], []
    for line in trace.splitlines():
        m = re.match(r"^(?:\[[^\]]*\]\s*)?(?:\d+\s+)?(?:[\d:.]+\s+)?([a-z_][a-z0-9_]+)\(", line)
        if not m:
            continue
        sc = m.group(1)
        hist[sc] = hist.get(sc, 0) + 1
        if sc in ("open", "openat"):
            fm = re.search(r'"([^"]+)"', line)
            if fm and fm.group(1) not in files:
                files.append(fm.group(1))
        elif sc in ("connect", "sendto", "socket"):
            nets.append(line.strip()[:160])
        elif sc in ("execve", "execveat"):
            execs.append(line.strip()[:160])
    return {"syscallHistogram": dict(sorted(hist.items(), key=lambda x: -x[1])[:25]),
            "filesOpened": files[:100], "network": nets[:50], "execs": execs[:50]}


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="syscall-trace")
    p.add_argument("target")
    p.add_argument("--timeout", type=int, default=30)
    p.add_argument("--format", choices=["text", "json"], default="text")
    p.add_argument("--yes-i-consent", action="store_true")
    a = p.parse_args(argv[1:])
    if not _consented(a):
        print(json.dumps({"ok": False, "error": "syscall-trace EXECUTES the target",
                          "hint": "run via `rekit run --allow-dynamic syscall-trace …`"}))
        return 4
    if not os.path.isfile(a.target):
        print(json.dumps({"ok": False, "error": f"target not found: {a.target}"}))
        return 2
    target = os.path.abspath(a.target)

    strace, dtruss = shutil.which("strace"), shutil.which("dtruss")
    if strace:
        tool, cmd = "strace", [strace, "-f", "-tt", target]
    elif dtruss:
        tool, cmd = "dtruss", [dtruss, target]  # typically needs sudo + permissive SIP
    else:
        print(json.dumps({"ok": False, "error": "no syscall tracer on PATH",
                          "hint": "install strace (Linux) or use dtruss (macOS, needs root + SIP)"}))
        return 3
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=a.timeout)
    except subprocess.TimeoutExpired as exc:
        proc = type("P", (), {"stdout": exc.stdout or "", "stderr": exc.stderr or "", "returncode": None})()
    except (OSError, subprocess.SubprocessError) as exc:
        print(json.dumps({"ok": False, "error": f"{tool} failed: {exc}",
                          "hint": "dtruss needs sudo + a permissive SIP; strace needs ptrace perms"}))
        return 1

    trace = proc.stderr or ""  # strace/dtruss write the trace to stderr
    summ = _summarize_strace(trace) if tool == "strace" else {"raw": trace[:4000]}
    res = {"ok": True, "tool": tool, "target": target, "exitCode": proc.returncode,
           "targetStdout": (proc.stdout or "")[:4000], **summ}
    if a.format == "json":
        print(json.dumps(res))
        return 0
    print(f"syscall-trace: {os.path.basename(target)}  [{tool}]  exit={proc.returncode}")
    if tool == "strace":
        top = ", ".join(f"{k}={v}" for k, v in list(summ["syscallHistogram"].items())[:10])
        print(f"  top syscalls: {top}")
        if summ["filesOpened"]:
            print(f"  files opened: {', '.join(summ['filesOpened'][:12])}")
        if summ["network"]:
            print(f"  network: {len(summ['network'])} call(s)")
        if summ["execs"]:
            print(f"  execs: {len(summ['execs'])}")
    else:
        print("  (dtruss raw trace captured — see JSON)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

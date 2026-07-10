#!/usr/bin/env python3
"""exec-observe — run a target and observe its behavior. DYNAMIC (executes the input).

A minimal behavioral primitive: run the target in a fresh working directory with a
timeout, and capture exit code, stdout/stderr, wall-clock time, and any files it
created. Use the tracer skills when syscall, API, or network visibility is required.

⚠️ This EXECUTES the target. Run it only where you don't mind the risk — a disposable
VM or a dedicated analysis box — or behind an isolation provider. rekit's dispatcher
gates this behind --allow-dynamic; run.py also refuses unless UNSAFE consent is given
when invoked directly.

    python3 run.py <target> [--timeout N] [--format text|json] [--yes-i-consent]
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="exec-observe")
    p.add_argument("target")
    p.add_argument("--timeout", type=int, default=30)
    p.add_argument("--format", choices=["text", "json"], default="text")
    p.add_argument("--yes-i-consent", action="store_true",
                   help="required only when calling run.py directly (rekit passes it)")
    a = p.parse_args(argv[1:])

    # Belt-and-suspenders: rekit's --allow-dynamic gate already covers dispatcher runs;
    # this covers someone calling the runner directly.
    if not a.yes_i_consent and os.environ.get("REKIT_ALLOW_DYNAMIC") != "1":
        print(json.dumps({"ok": False, "error": "exec-observe EXECUTES the target",
                          "hint": "run via `rekit run --allow-dynamic exec-observe …`, or pass "
                                  "--yes-i-consent / set REKIT_ALLOW_DYNAMIC=1 for a direct call"}))
        return 4
    if not os.path.exists(a.target):
        print(json.dumps({"ok": False, "error": f"target not found: {a.target}"}))
        return 2

    target = os.path.abspath(a.target)
    workdir = tempfile.mkdtemp(prefix="exec_observe_")
    before = set(os.listdir(workdir))
    start = time.time()
    timed_out = False
    try:
        proc = subprocess.run([target], cwd=workdir, capture_output=True, timeout=a.timeout)
        rc, out, err = proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired as exc:
        timed_out, rc = True, None
        out, err = exc.stdout or b"", exc.stderr or b""
    except OSError as exc:
        shutil.rmtree(workdir, ignore_errors=True)
        print(json.dumps({"ok": False, "error": f"could not execute target: {exc}",
                          "hint": "ensure it's executable, or point at an interpreter wrapper "
                                  "(e.g. a shell script that runs it)"}))
        return 1
    dur = round(time.time() - start, 3)
    created = sorted(set(os.listdir(workdir)) - before)

    res = {"ok": True, "target": target, "exitCode": rc, "timedOut": timed_out,
           "durationSec": dur, "filesCreated": created, "workdir": workdir,
           "stdout": out[:20000].decode("utf-8", "replace"),
           "stderr": err[:20000].decode("utf-8", "replace")}
    if a.format == "json":
        print(json.dumps(res))
        return 0
    print(f"exec-observe: {os.path.basename(target)}  exit={rc}"
          f"{' (TIMED OUT)' if timed_out else ''}  {dur}s")
    if created:
        print(f"  files created: {', '.join(created)}")
    if res["stdout"].strip():
        print("  --- stdout (head) ---")
        print("\n".join("  " + ln for ln in res["stdout"].splitlines()[:20]))
    if res["stderr"].strip():
        print("  --- stderr (head) ---")
        print("\n".join("  " + ln for ln in res["stderr"].splitlines()[:10]))
    print(f"  workdir: {workdir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

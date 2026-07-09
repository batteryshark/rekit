"""qiling-emulate — emulate a full binary with Qiling. CONTAINED (emulated OS).

Where emulate-code (Unicorn) runs *raw bytes* on a virtual CPU with no OS, Qiling
emulates the whole userland: it loads a real PE / ELF / Mach-O / etc., and implements
the syscalls itself against a BYO rootfs — so a Linux ELF or Windows PE can be
"detonated" on this host **without native execution and without a VM**, cross-arch and
cross-OS. Syscalls hit Qiling's emulation, not the host kernel (contained by default).

    python3 run.py <target> --rootfs <dir> [--args "..."] [--timeout N] [--format ...]

Contained (executes_input: sandboxed, tier 2) — NOT behind --allow-dynamic. The operator
CAN widen it (syscall/network passthrough); that's on them and is not the default here.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys
import threading


def _load_site() -> None:
    site = os.path.join(os.path.dirname(os.path.abspath(__file__)), "site")
    if os.path.isdir(site) and site not in sys.path:
        sys.path.insert(0, site)


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="qiling-emulate")
    p.add_argument("target")
    p.add_argument("--rootfs", help="OS rootfs directory Qiling emulates against (BYO)")
    p.add_argument("--args", default="", help="argv to pass the emulated program")
    p.add_argument("--timeout", type=int, default=30, help="wall-clock seconds before emu_stop")
    p.add_argument("--max-log", type=int, default=6000, help="chars of raw log tail to return")
    p.add_argument("--format", choices=["text", "json"], default="text")
    a = p.parse_args(argv[1:])

    if not os.path.isfile(a.target):
        print(json.dumps({"ok": False, "error": f"target not found: {a.target}"}))
        return 2
    # Qiling needs an OS rootfs to resolve the guest's libraries/syscalls. Check this
    # BEFORE importing qiling so the degradation is fast and honest either way.
    if not a.rootfs or not os.path.isdir(a.rootfs):
        print(json.dumps({"ok": False, "error": "Qiling needs an OS rootfs to emulate a userland binary",
                          "hint": "pass --rootfs <dir> matching the target's OS/arch — grab one from "
                                  "github.com/qilingframework/rootfs (its libs/DLLs back the emulation)."}))
        return 3

    _load_site()
    try:
        from qiling import Qiling
    except Exception as exc:  # noqa: BLE001 — any import failure = not vendored
        print(json.dumps({"ok": False, "error": f"qiling not installed: {exc}",
                          "hint": "run scripts/build.sh (uv pip install --target scripts/site qiling)"}))
        return 3
    try:
        from qiling.const import QL_VERBOSE
        verbose = QL_VERBOSE.DEBUG
    except Exception:  # noqa: BLE001 — older/newer const layout
        verbose = 4

    # Qiling logs syscall/API traces through its logger at DEBUG — collect them.
    records: list[str] = []

    class _Collector(logging.Handler):
        def emit(self, rec: logging.LogRecord) -> None:
            try:
                records.append(self.format(rec))
            except Exception:  # noqa: BLE001
                pass

    handler = _Collector()
    handler.setFormatter(logging.Formatter("%(message)s"))

    prog = [os.path.abspath(a.target)] + (a.args.split() if a.args else [])
    try:
        ql = Qiling(prog, os.path.abspath(a.rootfs), verbose=verbose)
    except Exception as exc:  # noqa: BLE001
        print(json.dumps({"ok": False, "error": f"Qiling load failed: {exc}",
                          "hint": "arch/OS auto-detect failed, or the rootfs doesn't match the binary"}))
        return 1
    try:
        ql.log.addHandler(handler)
    except Exception:  # noqa: BLE001
        logging.getLogger("qiling").addHandler(handler)

    outcome = {"stopped": "completed"}

    def _watchdog() -> None:
        outcome["stopped"] = "timeout"
        try:
            ql.emu_stop()
        except Exception:  # noqa: BLE001
            pass

    timer = threading.Timer(max(1, a.timeout), _watchdog)
    timer.daemon = True
    timer.start()
    try:
        ql.run()
    except Exception as exc:  # noqa: BLE001 — guest can fault; that's a result, not a crash
        outcome["stopped"] = "error"
        outcome["error"] = str(exc)
    finally:
        timer.cancel()

    # Best-effort syscall histogram from the debug log. The line format varies across
    # Qiling versions, so we ALSO return the raw tail — nothing is silently dropped.
    syscalls: dict = {}
    for line in records:
        m = re.search(r"\b([a-z_][a-z0-9_]{2,})\(", line)
        if m:
            name = m.group(1)
            syscalls[name] = syscalls.get(name, 0) + 1
    top = dict(sorted(syscalls.items(), key=lambda kv: -kv[1])[:30])
    try:
        arch = ql.arch.type.name
    except Exception:  # noqa: BLE001
        arch = None

    res = {"ok": outcome["stopped"] != "error", "tool": "qiling",
           "target": os.path.abspath(a.target), "outcome": outcome["stopped"], "arch": arch,
           "syscalls": top, "logTail": "\n".join(records)[-a.max_log:]}
    if "error" in outcome:
        res["error"] = outcome["error"]
    if a.format == "json":
        print(json.dumps(res))
        return 0 if res["ok"] else 1
    print(f"qiling: {os.path.basename(a.target)}  [{res['outcome']}]  arch={arch}")
    for k, v in list(top.items())[:15]:
        print(f"  {k:24} {v}")
    if not top and res["logTail"]:
        print("  (no syscalls parsed from this Qiling version — see logTail / --format json)")
    return 0 if res["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

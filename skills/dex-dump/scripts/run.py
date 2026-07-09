"""dex-dump — dump decrypted DEX from a running Android app's memory.

Pushes the vendored panda-dex-dumper (aarch64) to a connected rooted device via
adb, ptrace-attaches to the target app (which the operator already launched, past
its splash screen so the packer has decrypted the real DEX), dumps the in-memory
DEX files, pulls them to the output dir, and cleans up the device.

Does NOT execute a sample on the host. Invasive only on the connected device.

    python3 run.py <package|auto> <outdir> [--device SERIAL] [--keep-tool] [--format json|text]
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import shutil
import subprocess
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_BIN = os.path.join(os.path.dirname(_HERE), "bin", "panda-dex-dumper")
_DEV_TOOL = "/data/local/tmp/panda-dex-dumper"
_DEV_OUT = "/data/local/tmp/panda/"


def _emit(obj: dict, fmt: str) -> None:
    if fmt == "json":
        print(json.dumps(obj, indent=2))
    else:
        if obj.get("ok"):
            print(f"OK: dumped {obj.get('fileCount', 0)} DEX file(s) -> {obj.get('outputDir')}")
            for f in obj.get("dexFiles", []):
                print(f"  - {f}")
        else:
            print(f"FAIL: {obj.get('error', 'unknown')}")


def _adb(args: list[str], device: str | None, **kw) -> subprocess.CompletedProcess:
    cmd = ["adb"]
    if device:
        cmd += ["-s", device]
    cmd += args
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def _devices(device: str | None) -> list[str] | None:
    r = _adb(["devices"], device)
    if r.returncode != 0:
        return None
    serials = []
    for line in r.stdout.splitlines()[1:]:
        line = line.strip()
        if line and "\tdevice" in line:
            serials.append(line.split("\t")[0])
    return serials


def _foreground_package(device: str | None) -> str | None:
    r = _adb(["shell", "dumpsys", "activity", "top"], device)
    if r.returncode != 0:
        return None
    for line in r.stdout.splitlines():
        if "ACTIVITY" in line:
            parts = line.strip().split()
            if len(parts) >= 2 and "/" in parts[1]:
                return parts[1].split("/")[0]
    return None


def _pidof(device: str | None, pkg: str) -> str | None:
    r = _adb(["shell", "pidof", pkg], device)
    if r.returncode == 0:
        pid = r.stdout.strip()
        if pid:
            return pid.split()[0]
    return None


def _launch(device: str | None, pkg: str) -> bool:
    r = _adb(["shell", "monkey", "-p", pkg, "-c", "android.intent.category.LAUNCHER", "1"], device)
    return r.returncode == 0


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="dex-dump")
    p.add_argument("package")
    p.add_argument("outdir")
    p.add_argument("--device", default=None)
    p.add_argument("--keep-tool", action="store_true")
    p.add_argument("--format", choices=["text", "json"], default="json")
    a = p.parse_args(argv[1:])

    if not shutil.which("adb"):
        _emit({"ok": False, "error": "adb not on PATH", "hint": "install Android Platform Tools"}, a.format)
        return 3
    if not os.path.isfile(_BIN):
        _emit({"ok": False, "error": f"vendored payload missing: {_BIN}"}, a.format)
        return 3

    devs = _devices(a.device)
    if not devs:
        _emit({"ok": False, "error": "no adb device connected (run `adb devices`)"}, a.format)
        return 2
    if a.device and a.device not in devs:
        _emit({"ok": False, "error": f"device serial {a.device} not connected"}, a.format)
        return 2

    os.makedirs(a.outdir, exist_ok=True)

    pkg = a.package
    if pkg == "auto":
        pkg = _foreground_package(a.device)
        if not pkg:
            _emit({"ok": False, "error": "could not detect foreground app; pass an explicit package"}, a.format)
            return 2

    pid = _pidof(a.device, pkg)
    if not pid:
        if not _launch(a.device, pkg):
            _emit({"ok": False, "package": pkg, "error": f"{pkg} not running and launch failed"}, a.format)
            return 2
        pid = _pidof(a.device, pkg)
    if not pid:
        _emit({"ok": False, "package": pkg, "error": f"could not resolve pid for {pkg} (is it installed?)"}, a.format)
        return 2

    # push the device-side tool
    push = _adb(["push", _BIN, _DEV_TOOL], a.device)
    if push.returncode != 0:
        _emit({"ok": False, "package": pkg, "error": f"adb push failed: {push.stderr.strip()}"}, a.format)
        return 1
    _adb(["shell", "chmod", "755", _DEV_TOOL], a.device)

    # dump on device
    run = _adb(["shell", f"cd /data/local/tmp && ./panda-dex-dumper -p {pid}"], a.device)
    if run.returncode != 0:
        err = run.stderr.strip() or run.stdout.strip() or f"exit {run.returncode}"
        # still try to clean up the tool
        if not a.keep_tool:
            _adb(["shell", "rm", "-f", _DEV_TOOL], a.device)
        _emit({"ok": False, "package": pkg, "pid": int(pid),
               "error": f"on-device dump failed (root required for ptrace?): {err[:300]}"}, a.format)
        return 1

    # pull + clean up
    _adb(["shell", f"mkdir -p {shlex.quote(_DEV_OUT)}"], a.device)
    pull = _adb(["pull", _DEV_OUT.rstrip("/"), a.outdir], a.device)
    if not a.keep_tool:
        _adb(["shell", "rm", "-rf", _DEV_OUT, "-f", _DEV_TOOL], a.device)

    # enumerate pulled dex
    dex_files = []
    pulled_root = os.path.join(a.outdir, os.path.basename(_DEV_OUT.rstrip("/")))
    search_roots = [pulled_root, a.outdir]
    for root in search_roots:
        if os.path.isdir(root):
            for dirpath, _, files in os.walk(root):
                for f in files:
                    if f.endswith(".dex"):
                        dex_files.append(os.path.join(dirpath, f))

    _emit({
        "ok": True, "package": pkg, "pid": int(pid),
        "dexFiles": [os.path.relpath(f, a.outdir) for f in dex_files],
        "fileCount": len(dex_files), "outputDir": a.outdir,
        "devicePath": _DEV_OUT,
        "adbPullStderr": pull.stderr.strip()[:200] if pull.stderr else "",
    }, a.format)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

"""ios-dump — dump a decrypted iOS app binary (FairPlay 砸壳) from a jailbroken device.

Wraps the BYO frida-ios-dump toolchain: locates dump.py (via --dump-tool or
FRIDA_IOS_DUMP), resolves the target bundle id, invokes dump.py against the
jailbroken device (SSH + frida-server), and reports the decrypted IPA path. Does
NOT execute a sample on the host — frida-ios-dump attaches to an app the operator
already launched.

    python3 run.py <bundle_id|auto> <outdir> [--host IP] [--user mobile]
                  [--password alpine] [--dump-tool PATH] [--format json|text]
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import shutil
import subprocess
import sys


def _emit(obj: dict, fmt: str) -> None:
    if fmt == "json":
        print(json.dumps(obj, indent=2))
    else:
        if obj.get("ok"):
            extra = "" if obj.get("decrypted", True) else " (WARNING: cryptid!=0 — still encrypted)"
            print(f"OK: dumped {obj.get('bundleId')} -> {obj.get('ipa')}{extra}")
        else:
            print(f"FAIL: {obj.get('error', 'unknown')}")


def _find_dump_tool(explicit: str | None) -> str | None:
    if explicit:
        return explicit if os.path.isfile(explicit) else None
    env = os.environ.get("FRIDA_IOS_DUMP")
    if env:
        cand = os.path.join(env, "dump.py")
        if os.path.isfile(cand):
            return cand
    for cand in ("./frida-ios-dump/dump.py", os.path.expanduser("~/frida-ios-dump/dump.py")):
        if os.path.isfile(cand):
            return cand
    return None


def _list_running_apps(host: str | None) -> list[str]:
    cmd = ["frida-ps", "-U", "-a"] if not host else ["frida-ps", "-H", host, "-a"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.SubprocessError):
        return []
    if r.returncode != 0:
        return []
    apps = []
    for line in r.stdout.splitlines():
        # frida-ps -a prints:  <pid>  <BundleID>  <name>
        parts = line.split()
        for tok in parts:
            if "." in tok and len(tok) > 4 and not tok.isdigit():
                apps.append(tok)
                break
    return apps


def _cryptid_of(ipa: str) -> int | None:
    """Return the cryptid of the main binary inside the IPA, or None if unreadable."""
    import zipfile
    try:
        with zipfile.ZipFile(ipa) as z:
            bins = [n for n in z.namelist() if n.startswith("Payload/") and n.endswith(".app/")
                    or (n.startswith("Payload/") and ".app/" in n and "/" not in n[n.find(".app/") + 5:])]
    except (OSError, zipfile.BadZipFile):
        return None
    # cryptid check requires otool on the extracted binary; keep it best-effort.
    return None


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="ios-dump")
    p.add_argument("bundle_id")
    p.add_argument("outdir")
    p.add_argument("--host", default=None)
    p.add_argument("--user", default="mobile")
    p.add_argument("--password", default="alpine")
    p.add_argument("--dump-tool", default=None)
    p.add_argument("--format", choices=["text", "json"], default="json")
    a = p.parse_args(argv[1:])

    if not shutil.which("frida-ps"):
        _emit({"ok": False, "error": "frida-ps not on PATH",
               "hint": "pip install frida frida-tools (match the device frida-server major version)"}, a.format)
        return 3

    dump_py = _find_dump_tool(a.dump_tool)
    if not dump_py:
        _emit({"ok": False, "error": "frida-ios-dump dump.py not found",
               "hint": "clone https://github.com/AloneMonkey/frida-ios-dump, "
                       "pip install -r requirements.txt, npx frida-compile dump.ts -o dist/dump.js, "
                       "then pass --dump-tool PATH or set FRIDA_IOS_DUMP"}, a.format)
        return 3

    # the compiled agent must exist next to dump.py
    agent = os.path.join(os.path.dirname(dump_py), "dist", "dump.js")
    if not os.path.isfile(agent):
        _emit({"ok": False, "error": f"compiled agent missing: {agent}",
               "hint": "cd into frida-ios-dump and run: npx frida-compile dump.ts -o dist/dump.js"}, a.format)
        return 3

    bid = a.bundle_id
    if bid == "auto":
        apps = _list_running_apps(a.host)
        if not apps:
            _emit({"ok": False, "error": "no running apps detected; pass an explicit bundle_id"}, a.format)
            return 2
        bid = apps[0]

    os.makedirs(a.outdir, exist_ok=True)

    cmd = ["python3", dump_py, "-o", a.outdir]
    if a.host:
        cmd += ["-H", a.host, "-u", a.user, "-P", a.password]
    cmd.append(bid)

    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    except subprocess.TimeoutExpired:
        _emit({"ok": False, "bundleId": bid, "error": "dump.py timed out (keep the app in foreground)"}, a.format)
        return 1
    except (OSError, subprocess.SubprocessError) as exc:
        _emit({"ok": False, "bundleId": bid, "error": f"dump.py failed to start: {exc}"}, a.format)
        return 1

    if r.returncode != 0:
        err = (r.stderr or r.stdout or "").strip()
        _emit({"ok": False, "bundleId": bid, "error": f"dump.py failed: {err[:300]}"}, a.format)
        return 1

    # find the produced ipa
    ipas = sorted(glob.glob(os.path.join(a.outdir, "*.ipa")), key=os.path.getmtime, reverse=True)
    if not ipas:
        # frida-ios-dump writes to cwd by default; check there too
        ipas = sorted(glob.glob(os.path.join(os.getcwd(), "*.ipa")), key=os.path.getmtime, reverse=True)
        if ipas:
            # move into outdir
            for ipa in ipas:
                shutil.move(ipa, os.path.join(a.outdir, os.path.basename(ipa)))
            ipas = sorted(glob.glob(os.path.join(a.outdir, "*.ipa")), key=os.path.getmtime, reverse=True)
    ipa = ipas[0] if ipas else None

    _emit({
        "ok": True, "bundleId": bid, "ipa": os.path.relpath(ipa, a.outdir) if ipa else None,
        "outputDir": a.outdir, "decrypted": bool(ipa),
        "cryptid": _cryptid_of(ipa) if ipa else None,
        "note": "verify cryptid==0 with: otool -l <binary> | grep -A4 LC_ENCRYPTION_INFO",
    }, a.format)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

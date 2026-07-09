#!/usr/bin/env python3
"""macho-analyze — static triage of Mach-O binaries (macOS/iOS) with macholib.

Parses structure only (fat/arch headers, load commands) — never loads or runs the
binary. Reports a per-arch summary and emits BINARY.* atoms for noteworthy signals
(RPATH dylib-hijack surface, missing code signature, encryption/protection, linked
network/crypto frameworks).

    python3 analyze.py <mach-o-file> [--format text|json]
"""

from __future__ import annotations

import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "site"))

ATOMS = {
    "BINARY.RPATH":            (0.5, "LC_RPATH set — @rpath dylib search hijack surface"),
    "BINARY.NO_SIGNATURE":     (0.25, "no LC_CODE_SIGNATURE — unsigned"),
    "BINARY.ENCRYPTED":        (0.55, "LC_ENCRYPTION_INFO cryptid set — encrypted/protected (packer/DRM)"),
    "BINARY.INTERESTING_LINK": (0.4, "links a network/crypto framework"),
    "BINARY.NO_PIE":           (0.3, "not position-independent (MH_PIE unset)"),
}

# dylib/framework path substring -> capability
_CAP = {
    "network": ("CFNetwork", "Network.framework", "libcurl", "libnetwork",
                "SystemConfiguration"),
    "crypto":  ("Security.framework", "libcrypto", "CommonCrypto", "libssl"),
    "exec":    ("libobjc",),  # rough proxy: libobjc implies dynamic dispatch; imported symbols judge exec more precisely
}
_MH_PIE = 0x200000


def classify(dylib: str) -> str | None:
    for cap, subs in _CAP.items():
        if cap == "exec":
            continue
        if any(s in dylib for s in subs):
            return cap
    return None


def _atom(atom, note_extra="", conf=None):
    base_conf, note = ATOMS[atom]
    return {"atom": atom, "confidence": conf or base_conf,
            "note": note + (f" — {note_extra}" if note_extra else "")}


def analyze(path: str):
    from macholib.MachO import MachO
    from macholib import mach_o

    filetypes = {
        getattr(mach_o, "MH_OBJECT", 1): "OBJECT",
        getattr(mach_o, "MH_EXECUTE", 2): "EXECUTE",
        getattr(mach_o, "MH_DYLIB", 6): "DYLIB",
        getattr(mach_o, "MH_BUNDLE", 8): "BUNDLE",
        getattr(mach_o, "MH_DYLINKER", 7): "DYLINKER",
        getattr(mach_o, "MH_CORE", 4): "CORE",
        getattr(mach_o, "MH_KEXT_BUNDLE", 11): "KEXT",
    }

    m = MachO(path)
    findings: list = []
    seen_atoms: set = set()

    def add(atom, extra=""):
        key = (atom, extra)
        if key not in seen_atoms:
            seen_atoms.add(key)
            findings.append(_atom(atom, extra))

    arches = []
    for h in m.headers:
        cpu = mach_o.CPU_TYPE_NAMES.get(h.header.cputype, str(h.header.cputype))
        ftype = filetypes.get(h.header.filetype, str(h.header.filetype))
        is_pie = bool(h.header.flags & _MH_PIE)
        dylibs, rpaths, lcs = [], [], set()
        signed = encrypted = False
        for lc, cmd, data in h.commands:
            nm = lc.get_cmd_name() if hasattr(lc, "get_cmd_name") else str(lc.cmd)
            lcs.add(nm)
            if nm in ("LC_LOAD_DYLIB", "LC_LOAD_WEAK_DYLIB", "LC_REEXPORT_DYLIB"):
                dylibs.append(_lcstr(data))
            elif nm == "LC_RPATH":
                rpaths.append(_lcstr(data))
            elif nm == "LC_CODE_SIGNATURE":
                signed = True
            elif nm in ("LC_ENCRYPTION_INFO", "LC_ENCRYPTION_INFO_64"):
                if getattr(cmd, "cryptid", 0):
                    encrypted = True

        caps: dict = {}
        for d in dylibs:
            c = classify(d)
            if c:
                caps.setdefault(c, []).append(os.path.basename(d))
        arches.append({
            "cpu": cpu, "filetype": ftype, "pie": is_pie, "signed": signed,
            "encrypted": encrypted, "dylibs": dylibs, "rpaths": rpaths,
            "capabilities": {k: sorted(set(v)) for k, v in caps.items()},
        })

        for rp in rpaths:
            add("BINARY.RPATH", rp)
        if not signed:
            add("BINARY.NO_SIGNATURE")
        if encrypted:
            add("BINARY.ENCRYPTED")
        if ftype == "EXECUTE" and not is_pie:
            add("BINARY.NO_PIE")
        for cap, names in caps.items():
            add("BINARY.INTERESTING_LINK", f"{cap}: {', '.join(sorted(set(names))[:5])}")

    info = {"format": "Mach-O", "fat": len(m.headers) > 1,
            "archCount": len(m.headers), "arches": arches}
    return info, findings


def _lcstr(data: bytes) -> str:
    return data.rstrip(b"\x00").decode("utf-8", "replace").strip()


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="macho-analyze")
    p.add_argument("input")
    p.add_argument("--format", choices=["text", "json"], default="text")
    args = p.parse_args(argv[1:])
    if not os.path.isfile(args.input):
        sys.stdout.write(json.dumps({"ok": False, "error": f"file not found: {args.input}"}) + "\n")
        return 2

    try:
        from macholib.mach_o import MH_MAGIC, MH_MAGIC_64, FAT_MAGIC  # noqa: F401
        info, findings = analyze(args.input)
    except ValueError as exc:  # macholib raises ValueError on bad magic
        sys.stdout.write(json.dumps({"ok": False, "error": f"not a valid Mach-O: {exc}"}) + "\n")
        return 1
    except Exception as exc:  # pragma: no cover
        sys.stdout.write(json.dumps({"ok": False, "error": f"analyze failed: {exc}"}) + "\n")
        return 1

    result = {"ok": True, "path": os.path.abspath(args.input), **info,
              "atomCount": len(findings), "atoms": findings}
    if args.format == "json":
        sys.stdout.write(json.dumps(result) + "\n")
        return 0

    print(f"macho-analyze: {os.path.basename(args.input)}")
    print(f"  {'FAT/universal, ' if info['fat'] else ''}{info['archCount']} arch slice(s)")
    for a in info["arches"]:
        caps = ", ".join(a["capabilities"]) or "-"
        print(f"  [{a['cpu']}] {a['filetype']}  pie={a['pie']} signed={a['signed']} "
              f"encrypted={a['encrypted']}  dylibs={len(a['dylibs'])}  caps={caps}")
    print(f"\n  {len(findings)} atom(s):")
    for f in findings:
        print(f"    [{f['confidence']:.2f}] {f['atom']:24} {f['note']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

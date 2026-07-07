#!/usr/bin/env python3
"""elf-analyze — static triage of ELF binaries (Linux/BSD) with pyelftools.

Reads structure only (headers, sections, dynamic info, symbols) — never loads or
runs the binary. Reports a structured summary and emits BINARY.* atoms for
noteworthy signals (packed sections, RPATH hijack surface, weak hardening,
network/exec/inject imports).

    python3 analyze.py <elf-file> [--format text|json]
"""

from __future__ import annotations

import argparse
import json
import math
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "site"))

ATOMS = {
    "BINARY.HIGH_ENTROPY": (0.6, "high-entropy section — likely packed/encrypted"),
    "BINARY.RPATH":        (0.5, "RPATH/RUNPATH set — .so search-path hijack surface"),
    "BINARY.EXEC_STACK":   (0.55, "executable stack (no NX) — unusual, exploit-friendly"),
    "BINARY.NO_PIE":       (0.3, "non-PIE executable — weaker ASLR"),
    "BINARY.INTERESTING_IMPORT": (0.4, "imports a network/exec/inject/crypto symbol"),
    "BINARY.TEXTREL":      (0.5, "text relocations — self-modifying / unusual"),
}

# symbol-name substring -> capability category
_CAP = {
    "network": ("socket", "connect", "send", "recv", "gethostby", "getaddrinfo", "inet_",
                "curl_", "SSL_", "bind", "listen"),
    "exec":    ("system", "execv", "execl", "execve", "popen", "fork", "posix_spawn"),
    "inject":  ("mmap", "mprotect", "ptrace", "process_vm_writev", "memfd_create"),
    "load":    ("dlopen", "dlsym"),
    "crypto":  ("EVP_", "AES_", "crypt", "RC4", "MD5_", "SHA256_"),
}


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    h = 0.0
    for c in counts:
        if c:
            p = c / n
            h -= p * math.log2(p)
    return h


def classify(name: str) -> str | None:
    for cap, subs in _CAP.items():
        if any(s in name for s in subs):
            return cap
    return None


def _atom(atom, note_extra="", conf=None):
    base_conf, note = ATOMS[atom]
    return {"atom": atom, "confidence": conf or base_conf,
            "note": note + (f" — {note_extra}" if note_extra else "")}


def analyze(path: str) -> tuple[dict, list]:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.dynamic import DynamicSection
    from elftools.elf.sections import SymbolTableSection

    findings: list = []
    with open(path, "rb") as fh:
        elf = ELFFile(fh)
        hdr = elf.header
        etype = hdr["e_type"]
        info = {
            "format": "ELF",
            "class": f"ELF{elf.elfclass}",
            "endian": "little" if elf.little_endian else "big",
            "machine": hdr["e_machine"],
            "type": etype,
            "entry": hex(hdr["e_entry"]),
        }

        # sections + entropy
        sections = []
        for s in elf.iter_sections():
            size = s["sh_size"]
            data = b"" if s["sh_type"] == "SHT_NOBITS" else s.data()[:262144]
            e = entropy(data)
            sections.append({"name": s.name, "size": size, "entropy": round(e, 2)})
            if e > 7.2 and size > 2048:
                findings.append(_atom("BINARY.HIGH_ENTROPY", f"{s.name} ({e:.2f}/8.0, {size} bytes)"))
        info["sections"] = sections

        # dynamic: needed libs, rpath/runpath, textrel
        needed, runpaths = [], []
        textrel = False
        for sec in elf.iter_sections():
            if isinstance(sec, DynamicSection):
                for tag in sec.iter_tags():
                    t = tag.entry.d_tag
                    if t == "DT_NEEDED":
                        needed.append(tag.needed)
                    elif t == "DT_RPATH":
                        runpaths.append(getattr(tag, "rpath", "?"))
                    elif t == "DT_RUNPATH":
                        runpaths.append(getattr(tag, "runpath", "?"))
                    elif t == "DT_TEXTREL":
                        textrel = True
        info["neededLibraries"] = needed
        info["runpaths"] = runpaths
        if runpaths:
            findings.append(_atom("BINARY.RPATH", ", ".join(runpaths)))
        if textrel:
            findings.append(_atom("BINARY.TEXTREL"))

        # imported (undefined) dynamic symbols
        imported = set()
        for sec in elf.iter_sections():
            if isinstance(sec, SymbolTableSection) and sec.name == ".dynsym":
                for sym in sec.iter_symbols():
                    if sym.name and sym["st_shndx"] == "SHN_UNDEF":
                        imported.add(sym.name)
        info["importedSymbols"] = sorted(imported)[:250]
        caps: dict = {}
        for name in sorted(imported):
            cap = classify(name)
            if cap:
                caps.setdefault(cap, []).append(name)
        for cap, names in caps.items():
            findings.append(_atom("BINARY.INTERESTING_IMPORT",
                                  f"{cap}: {', '.join(names[:6])}" + (" …" if len(names) > 6 else "")))
        info["capabilities"] = {k: v[:12] for k, v in caps.items()}

        # hardening
        has_nx = True  # default assume NX; PT_GNU_STACK with X flag disables it
        has_relro = False
        for seg in elf.iter_segments():
            pt = seg["p_type"]
            if pt == "PT_GNU_STACK":
                has_nx = not bool(seg["p_flags"] & 0x1)  # PF_X
            elif pt == "PT_GNU_RELRO":
                has_relro = True
        is_pie = etype == "ET_DYN"
        info["hardening"] = {"pie": is_pie, "nx": has_nx, "relro": has_relro}
        if etype == "ET_EXEC" and not is_pie:
            findings.append(_atom("BINARY.NO_PIE"))
        if not has_nx:
            findings.append(_atom("BINARY.EXEC_STACK"))

    return info, findings


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="elf-analyze")
    p.add_argument("input")
    p.add_argument("--format", choices=["text", "json"], default="text")
    args = p.parse_args(argv[1:])
    if not os.path.isfile(args.input):
        sys.stdout.write(json.dumps({"ok": False, "error": f"file not found: {args.input}"}) + "\n")
        return 2

    try:
        from elftools.common.exceptions import ELFError
        try:
            info, findings = analyze(args.input)
        except ELFError as exc:
            sys.stdout.write(json.dumps({"ok": False, "error": f"not a valid ELF: {exc}"}) + "\n")
            return 1
    except Exception as exc:  # pragma: no cover
        sys.stdout.write(json.dumps({"ok": False, "error": f"analyze failed: {exc}"}) + "\n")
        return 1

    result = {"ok": True, "path": os.path.abspath(args.input), **info,
              "atomCount": len(findings), "atoms": findings}

    if args.format == "json":
        sys.stdout.write(json.dumps(result) + "\n")
        return 0

    print(f"elf-analyze: {os.path.basename(args.input)}")
    print(f"  {info['class']} {info['endian']}-endian  {info['machine']}  {info['type']}  entry {info['entry']}")
    if info.get("neededLibraries"):
        print(f"  needs: {', '.join(info['neededLibraries'])}")
    if info.get("capabilities"):
        print(f"  capabilities: {', '.join(info['capabilities'])}")
    hard = info["hardening"]
    print(f"  hardening: PIE={hard['pie']} NX={hard['nx']} RELRO={hard['relro']}")
    print(f"\n  {len(findings)} atom(s):")
    for f in findings:
        print(f"    [{f['confidence']:.2f}] {f['atom']:24} {f['note']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

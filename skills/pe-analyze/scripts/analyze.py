#!/usr/bin/env python3
"""pe-analyze — static triage of Windows PE binaries (EXE/DLL) with pefile.

Parses structure only (headers, sections, imports/exports, directories) — never
loads or runs the binary. Reports a structured summary and emits BINARY.* atoms
for noteworthy signals (packed sections, suspicious imports, TLS callbacks,
overlay, missing signature).

    python3 analyze.py <pe-file> [--format text|json]
"""

from __future__ import annotations

import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "site"))

ATOMS = {
    "BINARY.HIGH_ENTROPY":      (0.6, "high-entropy section — likely packed/encrypted"),
    "BINARY.PACKED":            (0.65, "high entropy + very few imports — probable packer"),
    "BINARY.SUSPICIOUS_IMPORT": (0.5, "imports a sensitive API (inject/exec/network/anti-debug)"),
    "BINARY.TLS_CALLBACK":      (0.55, "TLS callback(s) — code runs before entry point (anti-debug / stealth exec)"),
    "BINARY.OVERLAY":           (0.4, "data appended after the last section (overlay)"),
    "BINARY.NO_SIGNATURE":      (0.2, "no Authenticode signature directory"),
    "BINARY.RWX_SECTION":       (0.55, "section is writable AND executable — unusual, self-modifying"),
}

# API-name substring -> capability category (curated, high-signal)
_CAP = {
    "inject":     ("VirtualAlloc", "VirtualProtect", "WriteProcessMemory", "ReadProcessMemory",
                   "CreateRemoteThread", "NtUnmapViewOfSection", "QueueUserAPC", "SetWindowsHookEx",
                   "VirtualAllocEx", "NtWriteVirtualMemory", "MapViewOfFile"),
    "load":       ("LoadLibrary", "GetProcAddress", "LdrLoadDll"),
    "exec":       ("WinExec", "CreateProcess", "ShellExecute", "system", "_wsystem"),
    "network":    ("WSAStartup", "socket", "connect", "InternetOpen", "HttpSendRequest",
                   "URLDownloadToFile", "WinHttp", "InternetReadFile", "send", "recv"),
    "anti_debug": ("IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
                   "OutputDebugString", "GetTickCount"),
    "persist":    ("RegSetValue", "RegCreateKey", "CreateService", "SetValueEx"),
    "crypto":     ("CryptAcquireContext", "CryptEncrypt", "CryptDecrypt", "BCryptEncrypt"),
}

_IMAGE_SCN_MEM_EXECUTE = 0x20000000
_IMAGE_SCN_MEM_WRITE = 0x80000000
_IMAGE_FILE_DLL = 0x2000


def classify(name: str) -> str | None:
    # Case-SENSITIVE on purpose: Windows APIs are PascalCase (GetSystemInfo) and the
    # CRT exec is lowercase (system/_wsystem), so matching case-sensitively keeps
    # "system" from falsely tagging GetSystemInfo/GetSystemTimeAsFileTime as exec.
    for cap, subs in _CAP.items():
        if any(s in name for s in subs):
            return cap
    return None


def _atom(atom, note_extra="", conf=None):
    base_conf, note = ATOMS[atom]
    return {"atom": atom, "confidence": conf or base_conf,
            "note": note + (f" — {note_extra}" if note_extra else "")}


def analyze(path: str):
    import pefile

    findings: list = []
    pe = pefile.PE(path)  # full parse (imports/dirs)
    try:
        fh, oh = pe.FILE_HEADER, pe.OPTIONAL_HEADER
        is_dll = bool(fh.Characteristics & _IMAGE_FILE_DLL)
        info = {
            "format": "PE",
            "machine": pefile.MACHINE_TYPE.get(fh.Machine, hex(fh.Machine)),
            "kind": "DLL" if is_dll else "EXE",
            "subsystem": pefile.SUBSYSTEM_TYPE.get(oh.Subsystem, oh.Subsystem),
            "entryPoint": hex(oh.AddressOfEntryPoint),
            "imageBase": hex(oh.ImageBase),
            "timestamp": fh.TimeDateStamp,
        }

        # sections + entropy + RWX
        sections = []
        for s in pe.sections:
            name = s.Name.rstrip(b"\x00").decode("utf-8", "replace")
            ent = round(s.get_entropy(), 2)
            rwx = bool(s.Characteristics & _IMAGE_SCN_MEM_EXECUTE) and bool(s.Characteristics & _IMAGE_SCN_MEM_WRITE)
            sections.append({"name": name, "vsize": s.Misc_VirtualSize,
                             "rawsize": s.SizeOfRawData, "entropy": ent, "rwx": rwx})
            if ent > 7.2 and s.SizeOfRawData > 2048:
                findings.append(_atom("BINARY.HIGH_ENTROPY", f"{name} ({ent}/8.0)"))
            if rwx:
                findings.append(_atom("BINARY.RWX_SECTION", name))
        info["sections"] = sections

        # imports + capability classification
        imports: dict = {}
        caps: dict = {}
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode("utf-8", "replace") if entry.dll else "?"
                funcs = [imp.name.decode("utf-8", "replace") for imp in entry.imports if imp.name]
                imports[dll] = funcs
                for fn in funcs:
                    cap = classify(fn)
                    if cap:
                        caps.setdefault(cap, []).append(fn)
        total_imports = sum(len(v) for v in imports.values())
        info["importedDlls"] = list(imports.keys())
        info["importCount"] = total_imports
        info["capabilities"] = {k: sorted(set(v))[:12] for k, v in caps.items()}
        for cap, names in caps.items():
            uniq = sorted(set(names))
            findings.append(_atom("BINARY.SUSPICIOUS_IMPORT",
                                  f"{cap}: {', '.join(uniq[:6])}" + (" …" if len(uniq) > 6 else "")))

        # exports (DLL)
        exports = []
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            exports = [e.name.decode("utf-8", "replace") for e in pe.DIRECTORY_ENTRY_EXPORT.symbols
                       if e.name][:100]
        info["exports"] = exports

        # packer heuristic: high-entropy image + almost no imports
        max_ent = max((s["entropy"] for s in sections), default=0)
        if max_ent > 7.2 and total_imports <= 5:
            findings.append(_atom("BINARY.PACKED", f"max section entropy {max_ent}, {total_imports} import(s)"))

        # TLS callbacks
        if hasattr(pe, "DIRECTORY_ENTRY_TLS") and pe.DIRECTORY_ENTRY_TLS and \
                pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks:
            findings.append(_atom("BINARY.TLS_CALLBACK"))

        # overlay (appended data)
        try:
            ov = pe.get_overlay_data_start_offset()
            if ov is not None:
                size = os.path.getsize(path) - ov
                if size > 0:
                    findings.append(_atom("BINARY.OVERLAY", f"{size} bytes"))
                    info["overlayBytes"] = size
        except Exception:
            pass

        # Authenticode signature directory
        try:
            idx = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
            sd = oh.DATA_DIRECTORY[idx]
            signed = sd.VirtualAddress != 0 and sd.Size > 0
        except Exception:
            signed = False
        info["signed"] = signed
        if not signed:
            findings.append(_atom("BINARY.NO_SIGNATURE"))

        info["parseWarnings"] = len(pe.get_warnings())
        return info, findings
    finally:
        pe.close()


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="pe-analyze")
    p.add_argument("input")
    p.add_argument("--format", choices=["text", "json"], default="text")
    args = p.parse_args(argv[1:])
    if not os.path.isfile(args.input):
        sys.stdout.write(json.dumps({"ok": False, "error": f"file not found: {args.input}"}) + "\n")
        return 2

    import pefile
    try:
        info, findings = analyze(args.input)
    except pefile.PEFormatError as exc:
        sys.stdout.write(json.dumps({"ok": False, "error": f"not a valid PE: {exc}"}) + "\n")
        return 1
    except Exception as exc:  # pragma: no cover
        sys.stdout.write(json.dumps({"ok": False, "error": f"analyze failed: {exc}"}) + "\n")
        return 1

    result = {"ok": True, "path": os.path.abspath(args.input), **info,
              "atomCount": len(findings), "atoms": findings}
    if args.format == "json":
        sys.stdout.write(json.dumps(result) + "\n")
        return 0

    print(f"pe-analyze: {os.path.basename(args.input)}")
    print(f"  {info['machine']} {info['kind']}  subsystem={info['subsystem']}  "
          f"entry {info['entryPoint']}  imageBase {info['imageBase']}  signed={info['signed']}")
    print(f"  imports: {info['importCount']} from {', '.join(info['importedDlls'][:8])}")
    if info.get("capabilities"):
        print(f"  capabilities: {', '.join(info['capabilities'])}")
    print(f"\n  {len(findings)} atom(s):")
    for f in findings:
        print(f"    [{f['confidence']:.2f}] {f['atom']:24} {f['note']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

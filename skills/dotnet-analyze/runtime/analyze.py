#!/usr/bin/env python3
"""dotnet-analyze — static triage of .NET / CLR managed assemblies with dnfile.

Parses CLR metadata only (no execution, no assembly loading). Reports the managed
summary and emits DOTNET.* atoms. The high-signal item for .NET malware is the
**P/Invoke surface** — managed code reaching native APIs via DllImport — because
that's where a pure-IL sample actually touches the OS.

    python3 analyze.py <assembly.dll|exe> [--format text|json]

A native (non-.NET) PE returns ok:true with isDotNet:false and a pointer to
pe-analyze; a non-PE fails honestly.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "site"))

ATOMS = {
    "DOTNET.PINVOKE":         (0.55, "P/Invoke to a native API (managed code reaching the OS)"),
    "DOTNET.UNMANAGED_MODULE": (0.4, "references an unmanaged/native DLL"),
    "DOTNET.MIXED_MODE":      (0.5, "not IL-only — contains native code (mixed-mode assembly)"),
    "DOTNET.NO_STRONGNAME":   (0.2, "not strong-name signed"),
    "DOTNET.SUSPICIOUS_REF":  (0.4, "references dynamic-code / process / WMI capability"),
}

# native import-name substring -> capability (case-sensitive; Win32 APIs are PascalCase)
_CAP = {
    "inject":     ("VirtualAlloc", "VirtualProtect", "WriteProcessMemory", "CreateRemoteThread",
                   "NtUnmapViewOfSection", "QueueUserAPC", "SetWindowsHookEx", "MapViewOfFile"),
    "load":       ("LoadLibrary", "GetProcAddress", "LdrLoadDll"),
    "exec":       ("WinExec", "CreateProcess", "ShellExecute"),
    "network":    ("WSAStartup", "socket", "connect", "InternetOpen", "HttpSendRequest",
                   "URLDownloadToFile", "WinHttp", "send", "recv"),
    "anti_debug": ("IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess"),
    "crypto":     ("CryptAcquireContext", "CryptEncrypt", "BCryptEncrypt"),
}
# managed refs that signal dynamic/native capability
_SUSPICIOUS_REF = ("System.Reflection.Emit", "System.Management", "System.Diagnostics.Process",
                   "Microsoft.Win32", "System.Runtime.InteropServices")

_FLAG_ILONLY = 0x1
_FLAG_STRONGNAME = 0x8


def classify(name: str) -> str | None:
    for cap, subs in _CAP.items():
        if any(s in name for s in subs):
            return cap
    return None


def _atom(atom, extra="", conf=None):
    base, note = ATOMS[atom]
    return {"atom": atom, "confidence": conf or base, "note": note + (f" — {extra}" if extra else "")}


def _rows(mt, name):
    t = getattr(mt, name, None)
    return list(t.rows) if (t and getattr(t, "num_rows", 0)) else []


def _name_of(ref):
    """Best-effort resolve a dnfile coded reference to a .Name (as a plain str;
    dnfile returns HeapItemString objects that aren't hashable)."""
    for obj in (getattr(ref, "row", None), ref):
        n = getattr(obj, "Name", None)
        if n:
            return str(n)
    return None


def analyze(path: str):
    import dnfile

    pe = dnfile.dnPE(path, fast_load=False)
    net = getattr(pe, "net", None)
    if net is None:
        return {"format": "PE", "isDotNet": False,
                "note": "native PE with no CLR header — not a .NET assembly; use pe-analyze."}, []

    mt = net.mdtables
    findings: list = []

    version = bytes(net.metadata.struct.Version).rstrip(b"\x00").decode("utf-8", "replace")
    flags = int(getattr(net.struct, "Flags", 0))
    il_only = bool(flags & _FLAG_ILONLY)
    strong_named = bool(flags & _FLAG_STRONGNAME)

    asm = _rows(mt, "Assembly")
    asm_name = _name_of(asm[0]) if asm else None
    asm_refs = [{"name": _name_of(r),
                 "version": f"{r.MajorVersion}.{r.MinorVersion}.{r.BuildNumber}.{r.RevisionNumber}"}
                for r in _rows(mt, "AssemblyRef")]

    # P/Invoke surface (ImplMap: managed method -> native ImportName in a ModuleRef DLL)
    pinvokes = []
    caps: dict = {}
    for impl in _rows(mt, "ImplMap"):
        fn = getattr(impl, "ImportName", None)
        dll = _name_of(getattr(impl, "ImportScope", None))
        if not fn:
            continue
        pinvokes.append({"dll": dll, "function": fn})
        cap = classify(fn)
        if cap:
            caps.setdefault(cap, []).append(f"{dll or '?'}!{fn}")
    for cap, names in caps.items():
        findings.append(_atom("DOTNET.PINVOKE", f"{cap}: {', '.join(sorted(set(names))[:5])}"))

    unmanaged = [_name_of(r) for r in _rows(mt, "ModuleRef")]
    unmanaged = [u for u in unmanaged if u]
    if unmanaged and not caps:  # note native DLLs even when no API classified
        findings.append(_atom("DOTNET.UNMANAGED_MODULE", ", ".join(sorted(set(unmanaged))[:6])))

    if not il_only:
        findings.append(_atom("DOTNET.MIXED_MODE"))
    if not strong_named:
        findings.append(_atom("DOTNET.NO_STRONGNAME"))

    # suspicious managed references (dynamic code / process / WMI)
    ref_names: set = {r["name"] for r in asm_refs if r["name"]}
    for r in _rows(mt, "TypeRef"):
        ns = getattr(r, "TypeNamespace", None)
        if ns:
            ref_names.add(str(ns))
    hits = sorted({s for s in _SUSPICIOUS_REF for rn in ref_names if rn.startswith(s)})
    if hits:
        findings.append(_atom("DOTNET.SUSPICIOUS_REF", ", ".join(hits)))

    info = {
        "format": ".NET assembly", "isDotNet": True, "runtime": version,
        "assemblyName": asm_name, "ilOnly": il_only, "strongNamed": strong_named,
        "typeCount": len(_rows(mt, "TypeDef")), "methodCount": len(_rows(mt, "MethodDef")),
        "referencedAssemblies": asm_refs, "unmanagedModules": sorted(set(unmanaged)),
        "pinvokes": pinvokes[:100],
    }
    return info, findings


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="dotnet-analyze")
    p.add_argument("input")
    p.add_argument("--format", choices=["text", "json"], default="text")
    args = p.parse_args(argv[1:])
    if not os.path.isfile(args.input):
        sys.stdout.write(json.dumps({"ok": False, "error": f"file not found: {args.input}"}) + "\n")
        return 2

    import pefile  # dnfile's parser dependency; raises on non-PE input
    try:
        info, findings = analyze(args.input)
    except pefile.PEFormatError as exc:  # not a PE at all
        sys.stdout.write(json.dumps({"ok": False, "error": f"not a valid PE/.NET file: {exc}"}) + "\n")
        return 1
    except Exception as exc:  # pragma: no cover
        sys.stdout.write(json.dumps({"ok": False, "error": f"analyze failed: {exc}"}) + "\n")
        return 1

    result = {"ok": True, "path": os.path.abspath(args.input), **info,
              "atomCount": len(findings), "atoms": findings}
    if args.format == "json":
        sys.stdout.write(json.dumps(result) + "\n")
        return 0

    print(f"dotnet-analyze: {os.path.basename(args.input)}")
    if not info.get("isDotNet"):
        print(f"  {info['note']}")
        return 0
    print(f"  .NET assembly '{info['assemblyName']}'  runtime {info['runtime']}  "
          f"ILonly={info['ilOnly']} strongNamed={info['strongNamed']}")
    print(f"  types={info['typeCount']} methods={info['methodCount']}  "
          f"refs={len(info['referencedAssemblies'])}  pinvokes={len(info['pinvokes'])}")
    if info["unmanagedModules"]:
        print(f"  unmanaged: {', '.join(info['unmanagedModules'])}")
    print(f"\n  {len(findings)} atom(s):")
    for f in findings:
        print(f"    [{f['confidence']:.2f}] {f['atom']:24} {f['note']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

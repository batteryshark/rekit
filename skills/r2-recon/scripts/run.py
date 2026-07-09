#!/usr/bin/env python3
"""r2-recon — cross-format static recon of a native binary with radare2.

Drives `r2` headless (`-q -c`, JSON-emitting commands) in ONE session: binary
info, sections (+ per-section entropy computed from file bytes), imports,
exports, entries, analysed functions, and strings. Classifies imports by
capability (inject/exec/network/load/anti_debug/crypto/persist — Windows AND
POSIX) and surfaces interesting strings (urls/ips/paths/shell/exec-apis).

The differentiator over pe/elf/macho-analyze: r2 auto-detects the format
(ELF/PE/Mach-O/DEX/...) so one skill covers them all, and it reports the
*relational* view r2 is good at — analysed functions, entry points, decoded
strings (incl. UTF-16). Emits BINARY.* atoms. Static: r2 analyses structure;
it never runs or emulates the target.

Requires `r2` (radare2) on PATH. Prereq-gated; honest blind spot when absent.

    python3 run.py <binary> [--format text|json] [--analysis aaa|aa|none]
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import shutil
import subprocess
import sys

# --- atoms (shared vocabulary with pe/elf/macho-analyze + bin-triage) ---------
ATOMS = {
    "BINARY.HIGH_ENTROPY":       (0.6, "high-entropy section — likely packed/encrypted/compressed"),
    "BINARY.RWX_SECTION":        (0.55, "section is writable AND executable — unusual, self-modifying"),
    "BINARY.PACKED":             (0.65, "high section entropy + very few imports — probable packer"),
    "BINARY.SUSPICIOUS_IMPORT":  (0.5, "imports a sensitive symbol (inject/exec/network/anti-debug)"),
    "BINARY.INTERESTING_STRING": (0.4, "network/exec/path indicator in decoded strings"),
}

# symbol-name substring -> capability. Matched case-SENSITIVELY after stripping a
# single leading underscore (Mach-O mangling: _execve -> execve). Windows APIs are
# PascalCase; POSIX is lowercase — specific tokens avoid the "system" vs
# "GetSystemInfo" false positive pe-analyze guards against. Order = precedence.
_CAP = {
    "inject":     ("VirtualAlloc", "VirtualProtect", "VirtualAllocEx", "WriteProcessMemory",
                   "CreateRemoteThread", "NtWriteVirtualMemory", "NtUnmapViewOfSection",
                   "MapViewOfFile", "QueueUserAPC", "SetWindowsHookEx", "process_vm_writev",
                   "ptrace"),
    "exec":       ("execve", "execvp", "execl", "execv", "posix_spawn", "fork", "vfork",
                   "CreateProcess", "CreateProcessAsUser", "WinExec", "ShellExecute",
                   "system", "popen"),
    "network":    ("socket", "connect", "bind", "listen", "accept", "send", "recv",
                   "sendto", "recvfrom", "getaddrinfo", "gethostbyname", "WSAStartup",
                   "InternetOpen", "InternetReadFile", "HttpSendRequest", "WinHttpOpen",
                   "URLDownloadToFile", "curl_easy"),
    "anti_debug": ("IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
                   "OutputDebugString", "GetTickCount", "raise"),
    "load":       ("dlopen", "LoadLibrary", "GetProcAddress", "LdrLoadDll", "shmat"),
    "crypto":     ("EVP_", "CryptEncrypt", "CryptDecrypt", "BCrypt", "AES_", "RAND_bytes",
                   "gnutls_", "SSL_"),
    "persist":    ("RegSetValue", "RegCreateKey", "CreateService", "ChangeServiceConfig"),
}

# decoded-string indicators (same families as bin-triage, run over r2 strings)
_INTERESTING = [
    ("url",      re.compile(r"https?://[^\s\"'<>)\]]{4,200}")),
    ("onion",    re.compile(r"[a-z2-7]{16,56}\.onion")),
    ("ip",       re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    ("shell",    re.compile(r"/bin/(?:sh|bash)\b|cmd\.exe|powershell|WScript|cscript|/dev/tcp/")),
    # require a real backslash — r2 decodes long option strings ('M:ls', 'D:FGHI…')
    # that the zero-backslash form bin-triage uses would falsely tag as winpath.
    ("winpath",  re.compile(r"[A-Za-z]:\\(?:[\w .$-]+\\?)+")),
    ("exec_api", re.compile(r"VirtualAlloc|CreateProcess|WriteProcessMemory|LoadLibrary|WinExec|ShellExecute|CreateRemoteThread")),
]
_BENIGN_IP = {"0.0.0.0", "127.0.0.1", "255.255.255.255", "1.2.3.4", "8.8.8.8"}

_MAX_IMPORTS = 400      # cap stored import names (capabilities computed over ALL)
_MAX_CAP_NAMES = 12     # per-capability name cap in the result (like pe-analyze)
_MAX_FUNCS = 20         # top-N functions by size in the result
_MAX_STRINGS_CAT = 15   # per-category interesting-string cap


def _atom(atom, note_extra=""):
    base_conf, note = ATOMS[atom]
    return {"atom": atom, "confidence": base_conf,
            "note": note + (f" — {note_extra}" if note_extra else "")}


def _entropy(data: bytes) -> float:
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


def _classify(name: str) -> str | None:
    # strip ONE leading underscore (Mach-O); Windows imports are unmangled.
    n = name[1:] if name.startswith("_") else name
    for cap, subs in _CAP.items():
        if any(s in n for s in subs):
            return cap
    return None


def _r2_json(tool: str, path: str, analysis: str, timeout: int) -> dict:
    """Open ONE r2 session, run analysis + all JSON commands separated by
    `?e` echo markers, then split stdout on the markers and json.loads each
    chunk. Robust to r2 analysis chatter (it lands before the first marker) and
    to per-section JSON shape differences across r2 versions (a failed parse →
    that slice is None, never a whole-skill failure)."""
    seq = []
    if analysis != "none":
        seq.append(analysis)  # 'aaa' | 'aa'
    sections = ["info", "sections", "imports", "exports", "entries",
                "functions", "strings"]
    cmds = {"info": "ij", "sections": "iSj", "imports": "iij", "exports": "iEj",
            "entries": "iej", "functions": "aflj", "strings": "izj"}
    for name in sections:
        seq.append(f"?e __R2SEC:{name}__")
        seq.append(cmds[name])
    script = "; ".join(seq)
    proc = subprocess.run(
        [tool, "-q", "-e", "scr.color=0", "-c", script, path],
        capture_output=True, text=True, timeout=timeout)
    out = proc.stdout or ""
    tokens = re.split(r"__R2SEC:(\w+)__", out)
    parsed: dict = {}
    for i in range(1, len(tokens) - 1, 2):
        name = tokens[i]
        chunk = tokens[i + 1].strip()
        if not chunk:
            parsed[name] = None
            continue
        try:
            parsed[name] = json.loads(chunk)
        except json.JSONDecodeError:
            parsed[name] = None  # shape differs across r2 versions — degrade quietly
    parsed["_exit"] = proc.returncode
    parsed["_stderr"] = (proc.stderr or "").strip()[:1000]
    return parsed


def analyze(path: str, analysis: str, timeout: int):
    tool = shutil.which("r2")
    if not tool:
        return None, None
    raw = _r2_json(tool, path, analysis, timeout)

    info_blob = (raw.get("info") or {}).get("bin") or {}
    core_blob = (raw.get("info") or {}).get("core") or {}
    findings: list = []

    def bget(k, default=None):
        v = info_blob.get(k, default)
        return v if v not in ("", None) else default

    info = {
        "format": core_blob.get("format") or info_blob.get("bintype") or "unknown",
        "bintype": info_blob.get("bintype"),
        "arch": bget("arch"),
        "bits": bget("bits"),
        "endian": bget("endian"),
        "os": bget("os"),
        "machine": bget("machine"),
        "compiler": bget("compiler") or None,
        "lang": bget("lang") or None,
        "class": bget("class"),
        "baddr": info_blob.get("baddr"),
        "size": core_blob.get("size") or os.path.getsize(path),
        "stripped": bool(bget("stripped", False)),
        "canary": bool(bget("canary", False)),
        "nx": bool(bget("nx", False)),
        "pic": bool(bget("pic", False)),
        "static": bool(bget("static", False)),
    }

    # imports + capability classification (computed over the FULL import list)
    imports_raw = raw.get("imports") or []
    import_names = [str(imp.get("name", "")) for imp in imports_raw if imp.get("name")]
    caps: dict = {}
    for nm in import_names:
        cap = _classify(nm)
        if cap:
            caps.setdefault(cap, []).append(nm)
    info["importCount"] = len(import_names)
    info["imports"] = import_names[:_MAX_IMPORTS]
    info["capabilities"] = {k: sorted(set(v))[:_MAX_CAP_NAMES] for k, v in caps.items()}
    for cap, names in caps.items():
        uniq = sorted(set(names))
        findings.append(_atom("BINARY.SUSPICIOUS_IMPORT",
                              f"{cap}: {', '.join(uniq[:6])}" + (" …" if len(uniq) > 6 else "")))

    # sections + per-section entropy (from file bytes) + RWX
    secs_raw = raw.get("sections") or []
    with open(path, "rb") as fh:
        fdata = fh.read()
    sections = []
    max_ent = 0.0
    for s in secs_raw:
        name = s.get("name", "?")
        perm = (s.get("perm") or "").replace("-", "")
        paddr = s.get("paddr")
        sz = s.get("size") or s.get("vsize") or 0
        ent = round(_entropy(fdata[paddr:paddr + sz]), 2) if isinstance(paddr, int) and sz else None
        if ent is not None:
            max_ent = max(max_ent, ent)
        rwx = ("w" in perm) and ("x" in perm)
        sections.append({"name": name, "perm": s.get("perm"), "size": sz,
                         "entropy": ent, "rwx": rwx})
        if ent is not None and ent > 7.2 and (sz or 0) > 2048:
            findings.append(_atom("BINARY.HIGH_ENTROPY", f"{name} ({ent}/8.0)"))
        if rwx:
            findings.append(_atom("BINARY.RWX_SECTION", name))
    info["sections"] = sections
    info["sectionCount"] = len(sections)

    # packer heuristic: high-entropy section + almost no imports
    if max_ent > 7.2 and len(import_names) <= 5:
        findings.append(_atom("BINARY.PACKED",
                              f"max section entropy {max_ent}, {len(import_names)} import(s)"))

    # exports / entries / functions (counts + capped sample)
    info["exportCount"] = len(raw.get("exports") or [])
    info["entryCount"] = len(raw.get("entries") or [])
    funcs_raw = raw.get("functions") or []
    info["functionCount"] = len(funcs_raw)
    info["functions"] = sorted(
        ({"name": f.get("name"), "addr": f.get("addr"),
          "size": f.get("size") or f.get("realsz"), "nbbs": f.get("nbbs")}
         for f in funcs_raw if isinstance(f, dict)),
        key=lambda d: d.get("size") or 0, reverse=True)[:_MAX_FUNCS]

    # decoded strings → interesting indicators
    strings_raw = raw.get("strings") or []
    interesting: dict = {}
    for s in strings_raw:
        text = s.get("string") if isinstance(s, dict) else None
        if not text:
            continue
        for cat, rx in _INTERESTING:
            for m in rx.finditer(text):
                v = m.group()
                if cat == "ip" and (v in _BENIGN_IP or any(int(o) > 255 for o in v.split("."))):
                    continue
                interesting.setdefault(cat, [])
                if v not in interesting[cat]:
                    interesting[cat].append(v)
    interesting = {k: v[:_MAX_STRINGS_CAT] for k, v in interesting.items()}
    info["stringCount"] = len(strings_raw)
    info["interestingStrings"] = interesting
    for cat, vals in interesting.items():
        findings.append(_atom("BINARY.INTERESTING_STRING",
                              f"{cat}: " + ", ".join(vals[:4]) + (" …" if len(vals) > 4 else "")))

    info["r2Exit"] = raw.get("_exit")
    return info, findings


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="r2-recon")
    p.add_argument("input")
    p.add_argument("--format", choices=["text", "json"], default="text")
    p.add_argument("--analysis", choices=["aaa", "aa", "none"], default="aaa",
                   help="r2 analysis level (aaa = full; none = structural only, fast)")
    p.add_argument("--timeout", type=int, default=1800, help="r2 session timeout (seconds)")
    a = p.parse_args(argv[1:])
    if not os.path.isfile(a.input):
        sys.stdout.write(json.dumps({"ok": False, "error": f"file not found: {a.input}"}) + "\n")
        return 2

    info, findings = analyze(a.input, a.analysis, a.timeout)
    if info is None:
        sys.stdout.write(json.dumps({
            "ok": False, "error": "radare2 (r2) not on PATH",
            "hint": "install radare2 (https://radare.org) — `r2pm` or your package manager "
                    "(brew/apt install radare2)"}) + "\n")
        return 3

    result = {"ok": True, "tool": "radare2", "path": os.path.abspath(a.input),
              **info, "atomCount": len(findings or []), "atoms": findings or []}
    if a.format == "json":
        sys.stdout.write(json.dumps(result) + "\n")
        return 0

    print(f"r2-recon: {os.path.basename(a.input)}  ({info['size']} bytes)")
    print(f"  {info['format']}  arch={info['arch']} bits={info['bits']} "
          f"os={info['os']}  stripped={info['stripped']}  canary={info['canary']} nx={info['nx']}")
    print(f"  imports: {info['importCount']}  functions: {info['functionCount']}  "
          f"sections: {info['sectionCount']}  strings: {info['stringCount']}")
    if info.get("capabilities"):
        print(f"  capabilities: {', '.join(info['capabilities'])}")
    if info.get("interestingStrings"):
        print(f"  interesting: {', '.join(f'{c}({len(v)})' for c, v in info['interestingStrings'].items())}")
    print(f"\n  {len(findings)} atom(s):")
    for f in findings:
        print(f"    [{f['confidence']:.2f}] {f['atom']:24} {f['note']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

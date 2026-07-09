#!/usr/bin/env python3
"""py-covert-scan — detect covert/evasive tactics in Python. Pure stdlib, read-only.

The Python analog of js-covert-scan. Emits STEGO/OBF/EVADE atoms:

  STEGO — hidden in text (identical to the JS scanner; it's about the source bytes):
          invisible/zero-width/bidi chars, confusable-homoglyph punctuation/letters.
  OBF   — hidden code execution, the hallmark of Python malware: decode-then-exec
          (exec/eval/compile of base64/hex/zlib/marshal output), marshalled code,
          pickle deserialization, dynamic import, chr()/\\x string building.
  EVADE — environment-keyed / anti-analysis: platform checks, VM/sandbox/analyst
          detection (hostname/username), timezone/locale, debugger/tracer detection.

The strong signal is COMBINATION — decode-then-exec next to a sandbox check is the
shape of an evasive dropper. The scan reports atoms + a co-occurrence assessment;
never parses as code or executes the input.

    python3 scan.py <file-or-dir> [--format text|json]
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import unicodedata

_EXTS = {".py", ".pyw", ".pyi"}
_SKIP_DIRS = {"node_modules", ".git", "dist", "build", ".venv", "venv",
              "__pycache__", ".mypy_cache", ".tox", "site-packages"}
_MAX_BYTES = 32 * 1024 * 1024
_MAX_FINDINGS = 1000
_MAX_FILES = 4000

ATOMS = {
    "STEGO.INVISIBLE": ("STEGO", 0.9, "invisible/zero-width/format character in source"),
    "STEGO.BIDI":      ("STEGO", 0.9, "bidirectional control char (Trojan Source reordering)"),
    "STEGO.HOMOGLYPH": ("STEGO", 0.6, "confusable/homoglyph character where ASCII is expected"),
    "OBF.DECODE_EXEC": ("OBF",   0.78, "decode-then-execute (exec/eval/compile of base64/hex/zlib/marshal output)"),
    "OBF.EXEC":        ("OBF",   0.45, "dynamic code execution (exec/eval)"),
    "OBF.MARSHAL":     ("OBF",   0.6, "marshal.loads — marshalled code object"),
    "OBF.PICKLE":      ("OBF",   0.5, "pickle load — deserialization can execute code"),
    "OBF.DYNIMPORT":   ("OBF",   0.45, "dynamic import / getattr on __builtins__"),
    "OBF.CHARCODE":    ("OBF",   0.4, "string built from chr()/\\x escapes"),
    "EVADE.PLATFORM":  ("EVADE", 0.5, "platform/OS-conditional behavior"),
    "EVADE.SANDBOX":   ("EVADE", 0.6, "VM/sandbox/analyst detection (hostname/username/VM markers)"),
    "EVADE.TIMEZONE":  ("EVADE", 0.5, "timezone/locale-conditional behavior"),
    "EVADE.ANTIDEBUG": ("EVADE", 0.55, "debugger/tracer detection"),
}

# Internal tactic id -> the REAL judgment-free parallax atom emitted downstream.
# The ATOMS ids above stay as internal identifiers (they carry the per-tactic
# confidence + human note); at emission we translate to the parallax atom and tag
# method="covert-scan" so the consumer's lens re-derives the obfuscation/evasion
# judgment by provenance. Several tactics collapse onto one atom (e.g. exec/eval and
# decode-then-exec both -> LOAD.EVAL) — the per-tactic `note` keeps them distinct.
TACTIC_TO_ATOM = {
    "STEGO.INVISIBLE": "XFRM.UNICODE",
    "STEGO.BIDI":      "XFRM.UNICODE",
    "STEGO.HOMOGLYPH": "XFRM.UNICODE",
    "OBF.DECODE_EXEC": "LOAD.EVAL",
    "OBF.EXEC":        "LOAD.EVAL",
    "OBF.MARSHAL":     "LOAD.DESER",
    "OBF.PICKLE":      "LOAD.DESER",
    "OBF.DYNIMPORT":   "LOAD.REFLECT",
    "OBF.CHARCODE":    "XFRM.ENCODE",
    "EVADE.PLATFORM":  "ENVI.ENVCHECK",
    "EVADE.SANDBOX":   "ENVI.SANDBOX",
    "EVADE.TIMEZONE":  "ENVI.ENVCHECK",
    "EVADE.ANTIDEBUG": "ENVI.DEBUG",
}

_CONFUSABLE = {
    0x2018: "'", 0x2019: "'", 0x201B: "'", 0x02BC: "'", 0x02B9: "'", 0x2032: "'", 0x00B4: "'",
    0x201C: '"', 0x201D: '"', 0x2033: '"', 0x00A0: " ", 0x2007: " ", 0x2009: " ", 0x202F: " ",
    0x3000: " ", 0x2013: "-", 0x2014: "-", 0x2212: "-", 0x2044: "/",
}
_BIDI = set(range(0x202A, 0x202F)) | set(range(0x2066, 0x206A)) | {0x200E, 0x200F}


def _confusable_letter(cp: int) -> bool:
    return (0x0400 <= cp <= 0x04FF or 0x0370 <= cp <= 0x03FF or
            0x13A0 <= cp <= 0x13FF or 0xFF00 <= cp <= 0xFF5E)


_LINE_RX = [
    ("OBF.EXEC", re.compile(r"\b(?:exec|eval)\s*\(")),
    ("OBF.MARSHAL", re.compile(r"\bmarshal\s*\.\s*loads?\s*\(")),
    ("OBF.PICKLE", re.compile(r"\b(?:pickle|cPickle|_pickle)\s*\.\s*loads?\s*\(")),
    ("OBF.DYNIMPORT", re.compile(r"\b__import__\s*\(|getattr\s*\(\s*__builtins__|importlib\s*\.\s*import_module\s*\(")),
    ("OBF.CHARCODE", re.compile(r"(?:chr\(\s*\d+\s*\)\s*[+,]\s*){3,}|(?:\\x[0-9a-fA-F]{2}){8,}")),
    ("EVADE.PLATFORM", re.compile(r"\bsys\s*\.\s*platform\b|\bplatform\s*\.\s*(?:system|machine|release|node|uname)\s*\(")),
    ("EVADE.SANDBOX", re.compile(r"\bgethostname\s*\(|getpass\s*\.\s*getuser|os\s*\.\s*getlogin|/sys/class/dmi|/proc/self/status|\bVMware\b|\bVirtualBox\b|\bvbox\b|\bcuckoo\b|\bQEMU\b")),
    ("EVADE.TIMEZONE", re.compile(r"\btime\s*\.\s*tzname\b|locale\s*\.\s*getlocale|\bZoneInfo\s*\(|\btzinfo\b")),
    ("EVADE.ANTIDEBUG", re.compile(r"\bsys\s*\.\s*gettrace\s*\(|IsDebuggerPresent|\bptrace\b")),
]
_EXEC_SINK = re.compile(r"\b(?:exec|eval|compile)\s*\(|\bmarshal\s*\.\s*loads?\s*\(")
_DECODE_SRC = re.compile(r"\b(?:b(?:16|32|64|85)decode|a85decode|unhexlify|fromhex|decodebytes)\s*\("
                         r"|\b(?:zlib|gzip|lzma|bz2)\s*\.\s*decompress\s*\(|codecs\s*\.\s*decode\s*\("
                         r"|\bmarshal\s*\.\s*loads?\s*\(")


def _finding(atom, path, line_no, col, snippet, extra=None):
    # `atom` is the internal tactic id; look up its confidence + note, but emit the
    # real parallax atom/family and tag the provenance so the consumer can judge.
    _fam, conf, note = ATOMS[atom]
    real = TACTIC_TO_ATOM[atom]
    fam = real.split(".", 1)[0]
    f = {"atom": real, "family": fam, "confidence": conf, "file": path,
         "line": line_no, "col": col, "note": note, "snippet": snippet[:160],
         "method": "covert-scan"}
    if extra:
        f.update(extra)
    return f


def scan_text(text: str, path: str, findings: list) -> None:
    has_sink = has_decode = False
    for line_no, line in enumerate(text.splitlines(), 1):
        for idx, ch in enumerate(line, 1):
            cp = ord(ch)
            if cp < 0x80:
                continue
            if cp in _BIDI:
                atom = "STEGO.BIDI"
            elif unicodedata.category(ch) in ("Cf", "Cc", "Co"):
                atom = "STEGO.INVISIBLE"
            elif cp in _CONFUSABLE:
                atom = "STEGO.HOMOGLYPH"
            elif _confusable_letter(cp) and unicodedata.category(ch).startswith("L"):
                atom = "STEGO.HOMOGLYPH"
            else:
                continue
            try:
                name = unicodedata.name(ch)
            except ValueError:
                name = "?"
            findings.append(_finding(atom, path, line_no, idx, line.strip(),
                                     {"codepoint": f"U+{cp:04X}", "charName": name}))
            if len(findings) >= _MAX_FINDINGS:
                return
        for atom, rx in _LINE_RX:
            m = rx.search(line)
            if m:
                findings.append(_finding(atom, path, line_no, m.start() + 1, line.strip()))
        if _EXEC_SINK.search(line):
            has_sink = True
        if _DECODE_SRC.search(line):
            has_decode = True
        if len(findings) >= _MAX_FINDINGS:
            return
    if has_sink and has_decode:
        findings.append(_finding("OBF.DECODE_EXEC", path, 0, 0,
                                 "exec/eval/compile sink + decode source co-occur in file"))


def iter_files(root: str):
    if os.path.isfile(root):
        yield root
        return
    count = 0
    for dp, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS and not d.startswith(".")]
        for fn in filenames:
            if os.path.splitext(fn)[1].lower() in _EXTS:
                yield os.path.join(dp, fn)
                count += 1
                if count >= _MAX_FILES:
                    return


def assess(findings: list) -> str:
    fams = {f["family"] for f in findings}
    if not findings:
        return "No covert-tactic atoms found."
    if len(fams) >= 2:
        return ("Multiple covert-tactic families co-occur (" + ", ".join(sorted(fams)) +
                "). Hidden code execution and/or hidden text next to environment-keyed "
                "branching is the shape of an evasive dropper — review the sites together.")
    fam = fams.pop()
    return (f"{fam} atoms present. Any one can be benign; confirm intent at the flagged "
            f"sites (strongest when decode-then-exec pairs with a sandbox/platform check).")


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="py-covert-scan")
    p.add_argument("input")
    p.add_argument("--format", choices=["text", "json"], default="json",
                   help="json is the machine default the RE provider consumes; text for humans")
    args = p.parse_args(argv[1:])
    if not os.path.exists(args.input):
        sys.stdout.write(json.dumps({"ok": False, "error": f"not found: {args.input}"}) + "\n")
        return 2

    findings: list = []
    files_scanned = 0
    for path in iter_files(args.input):
        try:
            with open(path, "rb") as fh:
                raw = fh.read(_MAX_BYTES + 1)
        except OSError:
            continue
        if len(raw) > _MAX_BYTES:
            # Scan the first _MAX_BYTES of an oversized file rather than skip it whole
            # (a minified/carved bundle can be many MB on one line; skipping blinds us).
            raw = raw[:_MAX_BYTES]
        text = raw.decode("utf-8", "replace")
        files_scanned += 1
        scan_text(text, path, findings)
        if len(findings) >= _MAX_FINDINGS:
            break

    summary: dict = {}
    for f in findings:
        summary[f["atom"]] = summary.get(f["atom"], 0) + 1
    families = sorted({f["family"] for f in findings})
    result = {"ok": True, "root": os.path.abspath(args.input), "filesScanned": files_scanned,
              "findingCount": len(findings), "summary": summary, "families": families,
              "assessment": assess(findings), "findings": findings}

    if args.format == "json":
        sys.stdout.write(json.dumps(result) + "\n")
        return 0

    print(f"py-covert-scan: {os.path.abspath(args.input)}")
    print(f"scanned {files_scanned} file(s); {len(findings)} atom(s)")
    if summary:
        print("  " + ", ".join(f"{k}={v}" for k, v in sorted(summary.items())))
    print(f"\n{result['assessment']}\n")
    for f in findings:
        loc = f"{os.path.basename(f['file'])}:{f['line']}:{f['col']}"
        cp = f" {f.get('codepoint', '')}".rstrip()
        print(f"  [{f['confidence']:.2f}] {f['atom']:16} {loc}{cp}")
        print(f"        > {f['snippet']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

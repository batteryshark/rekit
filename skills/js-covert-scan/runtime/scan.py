#!/usr/bin/env python3
"""js-covert-scan — detect covert/evasive tactics in JavaScript/TypeScript.

Pure stdlib, zero dependencies, read-only (never executes the input). Emits atoms
when known hiding tactics are present, grouped into three families:

  STEGO  — hidden signal in text the eye can't see or tell apart:
           invisible/zero-width/format chars, bidirectional controls (Trojan
           Source), and confusable/homoglyph punctuation & letters (e.g. a fancy
           apostrophe U+02B9 standing in for ASCII ').
  OBF    — machine-hidden strings/logic: XOR of char codes (to defeat `strings`),
           long \\x/\\u escape blobs, fromCharCode string building, dynamic eval.
  EVADE  — environment-keyed conditional behavior: timezone/locale/geo/proxy
           checks that let code act differently for specific victims.

Any single atom can be legitimate; the strong signal is COMBINATION — e.g. a
timezone check next to steganographic punctuation and an XOR decoder (the shape of
covert, targeted, conditional behavior). The scan reports atoms + a co-occurrence
assessment; the caller decides severity.

    python3 scan.py <file-or-dir> [--format text|json] [--max-bytes N]
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import unicodedata

_EXTS = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts"}
_SKIP_DIRS = {"node_modules", ".git", ".hg", "dist", "build", ".venv", "__pycache__",
              "vendor", ".next", ".turbo"}
_MAX_BYTES = 5 * 1024 * 1024
_MAX_FINDINGS = 1000
_MAX_FILES = 4000

# atom -> (family, confidence, human note)
ATOMS = {
    "STEGO.INVISIBLE": ("STEGO", 0.9, "invisible/zero-width/format character in source"),
    "STEGO.BIDI":      ("STEGO", 0.9, "bidirectional control char (Trojan Source reordering)"),
    "STEGO.HOMOGLYPH": ("STEGO", 0.6, "confusable/homoglyph character where ASCII is expected"),
    "OBF.XOR":         ("OBF",   0.7, "XOR of character codes (hides strings from a `strings` dump)"),
    "OBF.CHARCODE":    ("OBF",   0.5, "string assembled from character codes"),
    "OBF.ESCAPE":      ("OBF",   0.5, "long hex/unicode-escaped string blob"),
    "OBF.DYNEVAL":     ("OBF",   0.6, "dynamic code execution (eval / new Function)"),
    "EVADE.TIMEZONE":  ("EVADE", 0.65, "timezone-conditional behavior"),
    "EVADE.LOCALE":    ("EVADE", 0.6, "locale/language-conditional behavior"),
    "EVADE.GEO":       ("EVADE", 0.6, "geolocation/region check"),
    "EVADE.PROXY":     ("EVADE", 0.6, "proxy/env-conditional behavior"),
}

# Confusable punctuation/space/dash that stands in for an ASCII character. Heavily
# abused for steganography (the exact apostrophe variants in the wild belong here).
_CONFUSABLE = {
    0x2018: "'", 0x2019: "'", 0x201B: "'", 0x02BC: "'", 0x02B9: "'", 0x02BB: "'",
    0x2032: "'", 0x00B4: "'", 0x0060: None,  # backtick is ASCII, ignore
    0x201C: '"', 0x201D: '"', 0x201F: '"', 0x02BA: '"', 0x2033: '"', 0x3003: '"',
    0x00A0: " ", 0x1680: " ", 0x2000: " ", 0x2001: " ", 0x2002: " ", 0x2003: " ",
    0x2004: " ", 0x2005: " ", 0x2006: " ", 0x2007: " ", 0x2008: " ", 0x2009: " ",
    0x200A: " ", 0x202F: " ", 0x205F: " ", 0x3000: " ",
    0x2010: "-", 0x2011: "-", 0x2012: "-", 0x2013: "-", 0x2014: "-", 0x2015: "-",
    0x2212: "-", 0x2044: "/", 0x2215: "/",
}

# Homoglyph LETTER blocks (Latin-lookalikes from other scripts) — cheap identifier
# homoglyph-attack signal.
def _confusable_letter(cp: int) -> bool:
    return (
        0x0400 <= cp <= 0x04FF   # Cyrillic
        or 0x0370 <= cp <= 0x03FF  # Greek
        or 0x13A0 <= cp <= 0x13FF  # Cherokee
        or 0xFF00 <= cp <= 0xFF5E  # Fullwidth ASCII
    )

_BIDI = set(range(0x202A, 0x202F)) | set(range(0x2066, 0x206A)) | {0x200E, 0x200F}

_REGEXES = [
    ("OBF.CHARCODE", re.compile(r"String\.fromCharCode\(\s*(?:0x[0-9a-fA-F]+|\d+)"
                                r"(?:\s*,\s*(?:0x[0-9a-fA-F]+|\d+)){5,}")),
    ("OBF.ESCAPE",   re.compile(r"(?:\\x[0-9a-fA-F]{2}){8,}|(?:\\u[0-9a-fA-F]{4}){8,}")),
    ("OBF.DYNEVAL",  re.compile(r"\beval\s*\(|\bnew\s+Function\s*\(")),
    ("EVADE.TIMEZONE", re.compile(r"resolvedOptions\(\)\s*\.\s*timeZone|Intl\.DateTimeFormat\b"
                                  r"|[\"'](?:Asia|Europe|America|Africa|Australia|Pacific|Indian|Atlantic)"
                                  r"/[A-Za-z_]+[\"']")),
    ("EVADE.LOCALE", re.compile(r"navigator\.languages?\b|resolvedOptions\(\)\s*\.\s*locale")),
    ("EVADE.GEO",    re.compile(r"navigator\.geolocation\b|\bgeoip\b|ip-?api\b|ipinfo\b")),
    ("EVADE.PROXY",  re.compile(r"process\.env\.[A-Za-z_]*PROX[A-Za-z_]*|\b(?:HTTPS?_PROXY|ALL_PROXY|NO_PROXY)\b",
                                re.IGNORECASE)),
]


def _finding(atom, path, line_no, col, snippet, extra=None):
    fam, conf, note = ATOMS[atom]
    f = {"atom": atom, "family": fam, "confidence": conf, "file": path,
         "line": line_no, "col": col, "note": note, "snippet": snippet[:160]}
    if extra:
        f.update(extra)
    return f


def scan_text(text: str, path: str, findings: list) -> None:
    for line_no, line in enumerate(text.splitlines(), 1):
        # --- character-level: STEGO ---
        for idx, ch in enumerate(line, 1):
            cp = ord(ch)
            if cp < 0x80:
                continue
            if cp in _BIDI:
                atom = "STEGO.BIDI"
            elif unicodedata.category(ch) in ("Cf", "Cc", "Co"):
                atom = "STEGO.INVISIBLE"
            elif cp in _CONFUSABLE and _CONFUSABLE[cp] is not None:
                atom = "STEGO.HOMOGLYPH"
            elif _confusable_letter(cp) and unicodedata.category(ch).startswith("L"):
                atom = "STEGO.HOMOGLYPH"
            else:
                continue
            try:
                name = unicodedata.name(ch)
            except ValueError:
                name = "?"
            extra = {"codepoint": f"U+{cp:04X}", "charName": name}
            if atom == "STEGO.HOMOGLYPH":
                extra["looksLike"] = _CONFUSABLE.get(cp)
            findings.append(_finding(atom, path, line_no, idx, line.strip(), extra))
            if len(findings) >= _MAX_FINDINGS:
                return
        # --- line-level: OBF / EVADE regexes ---
        if "^" in line and ("fromCharCode" in line or "charCodeAt" in line):
            findings.append(_finding("OBF.XOR", path, line_no, line.index("^") + 1, line.strip()))
        for atom, rx in _REGEXES:
            m = rx.search(line)
            if m:
                findings.append(_finding(atom, path, line_no, m.start() + 1, line.strip()))
        if len(findings) >= _MAX_FINDINGS:
            return


def iter_files(root: str):
    if os.path.isfile(root):
        yield root
        return
    count = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS and not d.startswith(".")]
        for fn in filenames:
            if os.path.splitext(fn)[1].lower() in _EXTS:
                yield os.path.join(dirpath, fn)
                count += 1
                if count >= _MAX_FILES:
                    return


def assess(findings: list) -> str:
    fams = {f["family"] for f in findings}
    if not findings:
        return "No covert-tactic atoms found."
    if len(fams) >= 2:
        return ("Multiple covert-tactic families co-occur (" + ", ".join(sorted(fams)) +
                "). This combination — hidden text plus obfuscation and/or "
                "environment-keyed branching — is the shape of covert, targeted, "
                "conditional behavior. Review the flagged sites together, not in isolation.")
    fam = fams.pop()
    return (f"{fam} atoms present. Any one can be benign; confirm intent at the flagged "
            f"sites (especially if paired later with obfuscation or an environment check).")


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="js-covert-scan")
    p.add_argument("input")
    p.add_argument("--format", choices=["text", "json"], default="text")
    p.add_argument("--max-bytes", type=int, default=_MAX_BYTES)
    args = p.parse_args(argv[1:])
    if not os.path.exists(args.input):
        sys.stdout.write(json.dumps({"ok": False, "error": f"not found: {args.input}"}) + "\n")
        return 2

    findings: list = []
    files_scanned = 0
    skipped_large = []
    for path in iter_files(args.input):
        try:
            if os.path.getsize(path) > args.max_bytes:
                skipped_large.append(path)
                continue
            with open(path, "rb") as fh:
                text = fh.read().decode("utf-8", errors="replace")
        except OSError:
            continue
        files_scanned += 1
        scan_text(text, path, findings)
        if len(findings) >= _MAX_FINDINGS:
            break

    summary: dict = {}
    for f in findings:
        summary[f["atom"]] = summary.get(f["atom"], 0) + 1
    families = sorted({f["family"] for f in findings})
    result = {
        "ok": True, "root": os.path.abspath(args.input), "filesScanned": files_scanned,
        "findingCount": len(findings), "summary": summary, "families": families,
        "assessment": assess(findings), "findings": findings,
        "skippedLarge": skipped_large,
    }

    if args.format == "json":
        sys.stdout.write(json.dumps(result) + "\n")
        return 0

    # text mode
    print(f"js-covert-scan: {os.path.abspath(args.input)}")
    print(f"scanned {files_scanned} file(s); {len(findings)} atom(s)"
          f"{' [capped]' if len(findings) >= _MAX_FINDINGS else ''}")
    if summary:
        print("  " + ", ".join(f"{k}={v}" for k, v in sorted(summary.items())))
    print(f"\n{result['assessment']}\n")
    for f in findings:
        loc = f"{os.path.relpath(f['file'], args.input if os.path.isdir(args.input) else os.path.dirname(f['file']) or '.')}:{f['line']}:{f['col']}"
        cp = f" {f.get('codepoint','')} {f.get('charName','')}".rstrip()
        print(f"  [{f['confidence']:.2f}] {f['atom']:16} {loc}{cp}")
        print(f"        {f['note']}")
        print(f"        > {f['snippet']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

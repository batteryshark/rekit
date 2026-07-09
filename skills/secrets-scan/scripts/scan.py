#!/usr/bin/env python3
"""secrets-scan — find leaked credentials in files. Pure stdlib, read-only.

High-signal provider patterns (AWS/GitHub/Slack/Google/Stripe/OpenAI/JWT/private
keys, …) plus a generic "secret-looking assignment with a high-entropy value" catch.
Matches are REDACTED in output — the tool never echoes a full secret.

    python3 scan.py <file-or-dir> [--format text|json] [--min-entropy 3.2]
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import sys

_SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "site-packages",
              "dist", "build", ".mypy_cache", ".tox"}
_SKIP_EXT = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".gz", ".xz",
             ".7z", ".tar", ".so", ".dll", ".dylib", ".class", ".jar", ".woff", ".ttf",
             ".mp4", ".mp3", ".pyc", ".node", ".wasm"}
_MAX_BYTES = 5 * 1024 * 1024
_MAX_FINDINGS = 1000
_PLACEHOLDERS = {"changeme", "example", "your_key_here", "xxxxxxxx", "placeholder",
                 "none", "null", "true", "false", "test", "secret", "password"}

# (atom, confidence, regex). Group 1 (if present) is the sensitive value to redact.
_PATTERNS = [
    ("SECRET.PRIVATE_KEY", 0.9, re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("SECRET.AWS_ACCESS_KEY", 0.9, re.compile(r"\b((?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[0-9A-Z]{16})\b")),
    ("SECRET.GITHUB_TOKEN", 0.9, re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,255})\b")),
    ("SECRET.GITHUB_PAT", 0.9, re.compile(r"\b(github_pat_[A-Za-z0-9_]{60,})\b")),
    ("SECRET.SLACK_TOKEN", 0.9, re.compile(r"\b(xox[baprs]-[A-Za-z0-9-]{10,})\b")),
    ("SECRET.SLACK_WEBHOOK", 0.85, re.compile(r"(https://hooks\.slack\.com/services/T[A-Za-z0-9_/]+)")),
    ("SECRET.GOOGLE_API_KEY", 0.85, re.compile(r"\b(AIza[0-9A-Za-z_\-]{35})\b")),
    ("SECRET.STRIPE_KEY", 0.9, re.compile(r"\b((?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,})\b")),
    ("SECRET.OPENAI_KEY", 0.85, re.compile(r"\b(sk-(?:proj-)?[A-Za-z0-9]{20,})\b")),
    ("SECRET.NPM_TOKEN", 0.85, re.compile(r"\b(npm_[A-Za-z0-9]{36})\b")),
    ("SECRET.PYPI_TOKEN", 0.85, re.compile(r"\b(pypi-[A-Za-z0-9_\-]{16,})\b")),
    ("SECRET.SENDGRID_KEY", 0.9, re.compile(r"\b(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})\b")),
    ("SECRET.TWILIO_KEY", 0.8, re.compile(r"\b(SK[0-9a-fA-F]{32})\b")),
    ("SECRET.JWT", 0.7, re.compile(r"\b(eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,})\b")),
]
_GENERIC = re.compile(
    r"(?i)\b(api[_-]?key|secret|token|passwd|password|access[_-]?key|client[_-]?secret|auth)\b"
    r"\s*[:=]\s*['\"]([^'\"\s]{8,120})['\"]")


def shannon(s: str) -> float:
    if not s:
        return 0.0
    counts: dict = {}
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def redact(s: str) -> str:
    s = s.strip()
    if len(s) <= 8:
        return s[:2] + "***"
    return f"{s[:4]}…{s[-2:]} [{len(s)} chars]"


def _is_placeholder(v: str) -> bool:
    low = v.lower()
    return (low in _PLACEHOLDERS or low.startswith(("${", "<", "os.", "process.env", "{{"))
            or "example" in low or "your" in low or set(v) <= set("x*.-_ "))


def scan_text(text: str, path: str, findings: list, min_entropy: float) -> None:
    for line_no, line in enumerate(text.splitlines(), 1):
        if len(line) > 4000:
            continue
        for atom, conf, rx in _PATTERNS:
            m = rx.search(line)
            if m:
                val = m.group(1) if m.groups() else m.group(0)
                findings.append({"atom": atom, "confidence": conf, "file": path,
                                 "line": line_no, "match": redact(val) if m.groups() else atom})
                if len(findings) >= _MAX_FINDINGS:
                    return
        gm = _GENERIC.search(line)
        if gm:
            val = gm.group(2)
            if not _is_placeholder(val) and shannon(val) >= min_entropy:
                findings.append({"atom": "SECRET.GENERIC_HIGH_ENTROPY", "confidence": 0.5,
                                 "file": path, "line": line_no,
                                 "match": f"{gm.group(1)}={redact(val)} (entropy {shannon(val):.1f})"})
        if len(findings) >= _MAX_FINDINGS:
            return


def _looks_binary(data: bytes) -> bool:
    if b"\x00" in data[:4096]:
        return True
    sample = data[:4096]
    if not sample:
        return False
    nonprint = sum(1 for b in sample if b < 9 or (13 < b < 32))
    return nonprint / len(sample) > 0.1


def iter_files(root: str):
    if os.path.isfile(root):
        yield root
        return
    count = 0
    for dp, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for fn in filenames:
            if os.path.splitext(fn)[1].lower() in _SKIP_EXT:
                continue
            yield os.path.join(dp, fn)
            count += 1
            if count >= 20000:
                return


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="secrets-scan")
    p.add_argument("input")
    p.add_argument("--format", choices=["text", "json"], default="text")
    p.add_argument("--min-entropy", type=float, default=3.2)
    args = p.parse_args(argv[1:])
    if not os.path.exists(args.input):
        sys.stdout.write(json.dumps({"ok": False, "error": f"not found: {args.input}"}) + "\n")
        return 2

    findings: list = []
    files_scanned = 0
    for path in iter_files(args.input):
        try:
            if os.path.getsize(path) > _MAX_BYTES:
                continue
            data = open(path, "rb").read()
        except OSError:
            continue
        if _looks_binary(data):
            continue
        files_scanned += 1
        scan_text(data.decode("utf-8", "replace"), path, findings, args.min_entropy)
        if len(findings) >= _MAX_FINDINGS:
            break

    summary: dict = {}
    for f in findings:
        summary[f["atom"]] = summary.get(f["atom"], 0) + 1
    result = {"ok": True, "root": os.path.abspath(args.input), "filesScanned": files_scanned,
              "findingCount": len(findings), "summary": summary, "findings": findings}

    if args.format == "json":
        sys.stdout.write(json.dumps(result) + "\n")
        return 0

    print(f"secrets-scan: {os.path.abspath(args.input)}  ({files_scanned} file(s))")
    if not findings:
        print("  no secrets found.")
        return 0
    print(f"  {len(findings)} candidate secret(s): " + ", ".join(f"{k}={v}" for k, v in sorted(summary.items())))
    for f in findings:
        print(f"  [{f['confidence']:.2f}] {f['atom']:28} {os.path.basename(f['file'])}:{f['line']}  {f['match']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

#!/usr/bin/env python3
"""ioc-extract — pull indicators of compromise from a file/dir, defanged. Pure stdlib.

Extracts URLs, IPs, domains, emails, file hashes (md5/sha1/sha256), .onion addresses,
CVEs, crypto addresses (BTC/ETH), and registry keys — from text OR binaries (it also
scans extracted ASCII/UTF-16 strings). Every value is **defanged** in output
(`hxxp://evil[.]com`, `1[.]2[.]3[.]4`) so a report can't accidentally ship a live IOC.

Read-only; never fetches or resolves anything.

    python3 extract.py <file-or-dir> [--format text|json]
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys

_SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "site-packages",
              "dist", "build"}
_MAX_BYTES = 16 * 1024 * 1024
_MAX_PER_TYPE = 1000
# last labels that mean "this is a filename, not a domain"
_NOT_TLD = {"js", "mjs", "cjs", "ts", "tsx", "jsx", "py", "pyc", "rb", "go", "rs", "c",
            "h", "cc", "cpp", "hpp", "html", "htm", "css", "scss", "json", "xml", "yaml",
            "yml", "toml", "ini", "cfg", "md", "txt", "png", "jpg", "jpeg", "gif", "svg",
            "ico", "webp", "exe", "dll", "so", "dylib", "class", "jar", "zip", "tar",
            "gz", "xz", "bz2", "7z", "pdf", "doc", "docx", "xls", "xlsx", "ppt", "map",
            "lock", "sh", "ps1", "bat", "php", "java", "kt", "swift", "sql", "log", "csv",
            "node", "wasm", "bin", "dat", "db", "sqlite", "woff", "woff2", "ttf", "eot"}
_BENIGN_IP = {"0.0.0.0", "127.0.0.1", "255.255.255.255", "1.1.1.1", "8.8.8.8", "8.8.4.4"}

_PATTERNS = [
    ("url", re.compile(r"\b(?:https?|ftp|hxxps?|fxp)://[^\s\"'<>)\]}]{4,400}", re.I)),
    ("email", re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,24}\b")),
    ("onion", re.compile(r"\b[a-z2-7]{16,56}\.onion\b")),
    ("sha256", re.compile(r"\b[a-fA-F0-9]{64}\b")),
    ("sha1", re.compile(r"\b[a-fA-F0-9]{40}\b")),
    ("md5", re.compile(r"\b[a-fA-F0-9]{32}\b")),
    ("cve", re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)),
    ("eth", re.compile(r"\b0x[a-fA-F0-9]{40}\b")),
    ("btc", re.compile(r"\b(?:bc1[ac-hj-np-z02-9]{11,71}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")),
    ("registry", re.compile(r"\bHK(?:EY_[A-Z_]+|LM|CU|CR|CC|U)\\[^\s\"'<>]{2,200}")),
    ("ipv4", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    ("domain", re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}\b")),
]


def defang(typ: str, val: str) -> str:
    v = val
    if typ == "url":
        v = re.sub(r"(?i)^http", "hxxp", v)
        v = re.sub(r"(?i)^ftp", "fxp", v)
    if typ == "email":
        v = v.replace("@", "[@]")
    if typ in ("url", "email", "ipv4", "domain", "onion"):
        v = v.replace(".", "[.]")
    return v


def _utf16_strings(data: bytes) -> str:
    return "\n".join(m.group().decode("utf-16-le", "replace")
                     for m in re.finditer(rb"(?:[\x20-\x7e]\x00){4,}", data))


def _accept(typ: str, val: str) -> bool:
    if typ == "ipv4":
        if val in _BENIGN_IP:
            return False
        return all(o.isdigit() and int(o) <= 255 for o in val.split("."))
    if typ == "domain":
        tld = val.rsplit(".", 1)[-1].lower()
        return tld not in _NOT_TLD and not val[0].isdigit()
    return True


def scan_text(text: str, found: dict) -> None:
    for typ, rx in _PATTERNS:
        bucket = found.setdefault(typ, {})
        if len(bucket) >= _MAX_PER_TYPE:
            continue
        for m in rx.finditer(text):
            val = m.group()
            if val in bucket or not _accept(typ, val):
                continue
            bucket[val] = defang(typ, val)
            if len(bucket) >= _MAX_PER_TYPE:
                break


def iter_files(root: str):
    if os.path.isfile(root):
        yield root
        return
    for dp, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS and not d.startswith(".")]
        for fn in filenames:
            yield os.path.join(dp, fn)


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="ioc-extract")
    p.add_argument("input")
    p.add_argument("--format", choices=["text", "json"], default="text")
    a = p.parse_args(argv[1:])
    if not os.path.exists(a.input):
        print(json.dumps({"ok": False, "error": f"not found: {a.input}"}))
        return 2

    found: dict = {}
    files_scanned = 0
    for path in iter_files(a.input):
        try:
            if os.path.getsize(path) > _MAX_BYTES:
                continue
            data = open(path, "rb").read()
        except OSError:
            continue
        files_scanned += 1
        text = data.decode("utf-8", "replace")
        if b"\x00" in data[:4096]:  # binary: also mine UTF-16LE strings
            text += "\n" + _utf16_strings(data)
        scan_text(text, found)

    iocs = []
    for typ in [t for t, _ in _PATTERNS]:
        for raw, dfa in sorted(found.get(typ, {}).items()):
            iocs.append({"type": typ, "value": raw, "defanged": dfa})
    summary = {t: len(found.get(t, {})) for t, _ in _PATTERNS if found.get(t)}
    result = {"ok": True, "root": os.path.abspath(a.input), "filesScanned": files_scanned,
              "iocCount": len(iocs), "summary": summary, "iocs": iocs}

    if a.format == "json":
        print(json.dumps(result))
        return 0
    print(f"ioc-extract: {os.path.abspath(a.input)}  ({files_scanned} file(s))")
    if not iocs:
        print("  no indicators found.")
        return 0
    print(f"  {len(iocs)} indicator(s): " + ", ".join(f"{k}={v}" for k, v in summary.items()))
    print("  (defanged — safe to paste)")
    for typ in [t for t, _ in _PATTERNS]:
        vals = sorted(found.get(typ, {}).values())
        for v in vals[:25]:
            print(f"    {typ:9} {v}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

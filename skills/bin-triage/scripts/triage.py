#!/usr/bin/env python3
"""bin-triage — format-agnostic first look at any file. Pure stdlib, read-only.

Four things, fast, with no external tools:
  1. identify the format from magic bytes (and route to the right analyzer skill);
  2. Shannon entropy, chunked, to flag packed/encrypted/compressed regions;
  3. extract strings (ASCII + UTF-16LE) and surface interesting ones (URLs, IPs,
     onion addresses, shell/exec cues, paths);
  4. scan for EMBEDDED file signatures at non-zero offsets (a mini-binwalk: an
     embedded ZIP/gzip/ELF/PDF inside a blob) — for real carving use binwalk-carve.

Emits BINARY.* atoms. Never parses as code or executes the input.

    python3 triage.py <file> [--format text|json] [--max-bytes N]
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import sys

_MAX_BYTES = 64 * 1024 * 1024
_CHUNK = 4096

ATOMS = {
    "BINARY.HIGH_ENTROPY":      (0.55, "high-entropy region(s) — packed/encrypted/compressed"),
    "BINARY.EMBEDDED":          (0.5, "known file signature found at a non-zero offset (embedded content)"),
    "BINARY.INTERESTING_STRING": (0.4, "network/exec/path indicator in strings"),
}

# (offset, signature, label, category). Most at offset 0; TAR checked at 257.
_MAGICS = [
    (0, b"\x7fELF", "ELF", "executable", "elf-analyze"),
    (0, b"MZ", "PE / DOS (MZ)", "executable", "pe-analyze / dotnet-analyze"),
    (0, b"\xfe\xed\xfa\xce", "Mach-O 32 (BE)", "executable", "macho-analyze"),
    (0, b"\xfe\xed\xfa\xcf", "Mach-O 64 (BE)", "executable", "macho-analyze"),
    (0, b"\xce\xfa\xed\xfe", "Mach-O 32 (LE)", "executable", "macho-analyze"),
    (0, b"\xcf\xfa\xed\xfe", "Mach-O 64 (LE)", "executable", "macho-analyze"),
    (0, b"\xca\xfe\xba\xbe", "Java class OR Mach-O universal (0xCAFEBABE)", "executable", "macho-analyze"),
    (0, b"\xca\xfe\xba\xbf", "Mach-O universal 64", "executable", "macho-analyze"),
    (0, b"dex\n", "Android DEX", "executable", None),
    (0, b"PK\x03\x04", "ZIP / JAR / APK / OOXML / nupkg", "archive", "unpack"),
    (0, b"PK\x05\x06", "ZIP (empty)", "archive", "unpack"),
    (0, b"\x1f\x8b", "gzip", "archive", "unpack"),
    (0, b"BZh", "bzip2", "archive", "unpack"),
    (0, b"\xfd7zXZ\x00", "xz", "archive", "unpack"),
    (0, b"7z\xbc\xaf\x27\x1c", "7-Zip", "archive", "unpack"),
    (0, b"Rar!\x1a\x07", "RAR", "archive", "unpack"),
    (0, b"MSCF", "CAB", "archive", "unpack"),
    (0, b"!<arch>", "ar / .deb", "archive", "unpack"),
    (0, b"\x04\x22\x4d\x18", "LZ4", "archive", "unpack"),
    (0, b"\x28\xb5\x2f\xfd", "zstd", "archive", "unpack"),
    (0, b"%PDF", "PDF", "document", None),
    (0, b"\x89PNG\r\n\x1a\n", "PNG", "image", None),
    (0, b"\xff\xd8\xff", "JPEG", "image", None),
    (0, b"\x00asm", "WebAssembly", "executable", None),
    (0, b"#!", "script (shebang)", "script", None),
]

# Distinctive multi-byte sigs worth scanning throughout the file (mini-binwalk).
_EMBEDDED = [
    (b"PK\x03\x04", "ZIP"),
    (b"\x1f\x8b\x08", "gzip"),
    (b"\xfd7zXZ\x00", "xz"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip"),
    (b"BZh9", "bzip2"),
    (b"\x7fELF", "ELF"),
    (b"%PDF-", "PDF"),
    (b"\x89PNG\r\n\x1a\n", "PNG"),
    (b"\x28\xb5\x2f\xfd", "zstd"),
]

_INTERESTING = [
    ("url", re.compile(rb"https?://[^\s\"'<>)\]]{4,200}")),
    ("onion", re.compile(rb"[a-z2-7]{16,56}\.onion")),
    ("ip", re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    ("shell", re.compile(rb"/bin/(?:sh|bash)\b|cmd\.exe|powershell|WScript|cscript|/dev/tcp/")),
    ("winpath", re.compile(rb"[A-Za-z]:\\\\?(?:[\w .$-]+\\\\?){1,}")),
    ("exec_api", re.compile(rb"VirtualAlloc|CreateProcess|WriteProcessMemory|LoadLibrary|WinExec|ShellExecute|CreateRemoteThread")),
]
_BENIGN_IP = {"0.0.0.0", "127.0.0.1", "255.255.255.255", "1.2.3.4", "8.8.8.8"}


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


def identify(data: bytes) -> list[dict]:
    hits = []
    for off, sig, label, cat, route in _MAGICS:
        if data[off:off + len(sig)] == sig:
            hits.append({"format": label, "category": cat, "route": route})
    if data[257:262] == b"ustar":
        hits.append({"format": "TAR", "category": "archive", "route": "unpack"})
    return hits


def extract_strings(data: bytes, minlen: int = 5) -> list[str]:
    out = []
    for m in re.finditer(rb"[\x20-\x7e]{%d,}" % minlen, data):
        out.append(m.group().decode("ascii", "replace"))
    for m in re.finditer(rb"(?:[\x20-\x7e]\x00){%d,}" % minlen, data):
        out.append(m.group().decode("utf-16-le", "replace"))
    return out


def scan_interesting(data: bytes) -> dict:
    found: dict = {}
    for name, rx in _INTERESTING:
        vals = []
        for m in rx.finditer(data):
            v = m.group().decode("utf-8", "replace")
            if name == "ip" and (v in _BENIGN_IP or any(int(o) > 255 for o in v.split("."))):
                continue
            vals.append(v)
        if vals:
            # dedup preserve order, cap
            seen, uniq = set(), []
            for v in vals:
                if v not in seen:
                    seen.add(v)
                    uniq.append(v)
            found[name] = uniq[:15]
    return found


def scan_embedded(data: bytes) -> list[dict]:
    out = []
    for sig, label in _EMBEDDED:
        start = 0
        while True:
            idx = data.find(sig, start)
            if idx == -1:
                break
            if idx > 0:  # non-zero offset => embedded
                out.append({"offset": idx, "format": label})
            start = idx + 1
            if len(out) >= 50:
                return out
    return out


# --- embedded-source carving ------------------------------------------------
# Single-file executables (Bun, Deno, pkg, nexe, Node SEA) append their application
# code as (usually transpiled/minified) JavaScript *text* after the native runtime.
# Carving large contiguous printable-text runs recovers it format-agnostically — no
# packer parsing, so it survives version changes. Writing is not execution.
_CARVE_MIN_RUN = 4096                    # smallest printable-text run worth carving
_CARVE_LARGE = 64 * 1024                 # a run this big is carved even without code hints
_CARVE_MAX_TOTAL = 128 * 1024 * 1024     # cap total carved bytes
_CARVE_MAX_REGIONS = 64
_CARVE_COPY_CHUNK = 4 * 1024 * 1024
_TEXT_RUN_RE = re.compile(rb"[\x09\x0a\x0d\x20-\x7e]{%d,}" % _CARVE_MIN_RUN)
_JS_HINTS = (b"function", b"require(", b"module.exports", b"__commonJS", b"__esm",
             b"=>", b"const ", b"var ", b"import ", b"export ", b"//", b"/*")


def _guess_source_ext(sample: bytes) -> str | None:
    s = sample[:8192]
    if any(h in s for h in _JS_HINTS):
        return ".js"
    if s.lstrip()[:1] in (b"{", b"["):
        return ".json"
    return None  # not obviously source


def carve_embedded_source(path: str, outdir: str) -> list[dict]:
    """Carve large printable-text runs (embedded scripts/config) into ``outdir`` for
    rescanning. Streams via mmap so a multi-hundred-MB executable stays memory-light.

    Regions are carved LARGEST-first, not file-order: a single-file executable's app
    bundle is a big text run at the tail, and it must not be starved by the many small
    runtime strings up front (which would exhaust the region/byte budget before we reach
    it)."""
    import mmap
    if os.path.getsize(path) == 0:
        return []
    carved: list[dict] = []
    total = 0
    with open(path, "rb") as fh:
        mm = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
        try:
            # Pass 1: locate candidate runs (offsets only, no copy) — a run is a candidate
            # if it looks like source or is large enough to matter on its own.
            candidates: list[tuple[int, int, int, str]] = []
            for m in _TEXT_RUN_RE.finditer(mm):
                start, end = m.start(), m.end()
                ext = _guess_source_ext(mm[start:start + 8192])
                if ext is None and (end - start) < _CARVE_LARGE:
                    continue
                candidates.append((end - start, start, end, ext or ".txt"))
            # Pass 2: carve biggest-first, within the region/byte budget.
            candidates.sort(reverse=True)
            for size, start, end, ext in candidates:
                if len(carved) >= _CARVE_MAX_REGIONS or total >= _CARVE_MAX_TOTAL:
                    break
                end = min(end, start + (_CARVE_MAX_TOTAL - total))
                name = f"carved-{len(carved):03d}-off{start:012d}{ext}"
                with open(os.path.join(outdir, name), "wb") as out:
                    off = start
                    while off < end:
                        n = min(_CARVE_COPY_CHUNK, end - off)
                        out.write(mm[off:off + n])
                        off += n
                carved.append({"file": name, "offset": start, "size": end - start, "ext": ext})
                total += end - start
        finally:
            mm.close()
    return carved


def analyze(path: str, max_bytes: int):
    size = os.path.getsize(path)
    with open(path, "rb") as fh:
        data = fh.read(max_bytes)
    truncated = size > len(data)
    findings: list = []

    formats = identify(data)

    # chunked entropy
    high = []
    for i in range(0, len(data), _CHUNK):
        e = entropy(data[i:i + _CHUNK])
        if e > 7.4:
            high.append(i)
    whole_ent = round(entropy(data[: 1 << 20]), 2)  # entropy of first 1 MiB as a summary
    if high:
        pct = round(min(100.0, 100 * len(high) * _CHUNK / max(len(data), 1)), 1)
        findings.append({**_atom("BINARY.HIGH_ENTROPY"),
                         "note": ATOMS["BINARY.HIGH_ENTROPY"][1]
                                 + f" — ~{pct}% of file, first at 0x{high[0]:x}"})

    interesting = scan_interesting(data)
    for cat, vals in interesting.items():
        findings.append({**_atom("BINARY.INTERESTING_STRING"),
                         "note": f"{cat}: " + ", ".join(vals[:4]) + (" …" if len(vals) > 4 else "")})

    embedded = scan_embedded(data)
    for e in embedded[:12]:
        findings.append({**_atom("BINARY.EMBEDDED"),
                         "note": f"{e['format']} signature at offset 0x{e['offset']:x}"})

    info = {
        "size": size, "truncated": truncated,
        "formats": formats or [{"format": "unknown", "category": "unknown", "route": None}],
        "entropyFirstMiB": whole_ent,
        "highEntropyChunks": len(high),
        "interestingStrings": interesting,
        "embeddedSignatures": embedded[:50],
    }
    return info, findings


def _atom(atom):
    base, note = ATOMS[atom]
    return {"atom": atom, "confidence": base, "note": note}


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="bin-triage")
    p.add_argument("input")
    p.add_argument("outdir", nargs="?", default=None,
                   help="if given, carve embedded readable source here for rescanning")
    p.add_argument("--format", choices=["text", "json"], default="json",
                   help="json is the machine default the RE provider consumes; text for humans")
    p.add_argument("--max-bytes", type=int, default=_MAX_BYTES)
    args = p.parse_args(argv[1:])
    if not os.path.isfile(args.input):
        sys.stdout.write(json.dumps({"ok": False, "error": f"file not found: {args.input}"}) + "\n")
        return 2

    info, findings = analyze(args.input, args.max_bytes)
    carved: list[dict] = []
    if args.outdir:  # atom analysis reads the head; carving scans the whole file (mmap)
        os.makedirs(args.outdir, exist_ok=True)
        carved = carve_embedded_source(args.input, args.outdir)
        if carved:
            findings.append({**_atom("BINARY.EMBEDDED"),
                             "note": f"carved {len(carved)} embedded text region(s) "
                                     f"({sum(c['size'] for c in carved)} bytes) for rescanning"})
    result = {"ok": True, "path": os.path.abspath(args.input), **info,
              "atomCount": len(findings), "atoms": findings, "carved": carved[:50]}
    if carved:  # surfaces to the provider as DerivedSource → the fold rescans it
        result["outputDir"] = os.path.abspath(args.outdir)
    if args.format == "json":
        sys.stdout.write(json.dumps(result) + "\n")
        return 0

    print(f"bin-triage: {os.path.basename(args.input)}  ({info['size']} bytes"
          f"{', truncated' if info['truncated'] else ''})")
    for f in info["formats"]:
        route = f"  → {f['route']}" if f["route"] else ""
        print(f"  format: {f['format']}  [{f['category']}]{route}")
    print(f"  entropy(1MiB)={info['entropyFirstMiB']}/8.0  high-entropy chunks={info['highEntropyChunks']}")
    print(f"\n  {len(findings)} atom(s):")
    for f in findings:
        print(f"    [{f['confidence']:.2f}] {f['atom']:24} {f['note']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

#!/usr/bin/env python3
r"""js-string-decode — statically decode constant-key XOR / charCode string
obfuscation in JavaScript. Pure stdlib, READ-ONLY, never executes the input.

Malware routinely keeps its telltale strings (C2 URLs, victim domains, timezone
names, shell commands) out of a plain `strings` dump by XORing each character with
a constant byte and reassembling them with `String.fromCharCode`. This tool finds
those decode sites with regex/heuristics, resolves the constant key (an inline
literal OR a variable assigned a small int nearby — best-effort constant
propagation), applies the XOR statically, and writes the recovered plaintext to
`<outdir>/decoded-strings.js` so a downstream scanner can rescan it as source.

It handles four real-world shapes:
  * decoder FUNCTION over a parameter, called with encoded data (the canonical
    single-file-malware shape) — including a `Buffer.from(p,"base64")` / `atob(p)`
    front transform, so the encoded data can be a base64 blob;
  * `arr.map(c=>c^KEY)` over an inline int array;
  * `s.split('').map((c,i)=>String.fromCharCode(c.charCodeAt(0)^KEY))` over a string;
  * `for(const K of DATA) ...fromCharCode(K^KEY)` over an inline array or string,
    plus `\xNN` / `\uNNNN` escape blobs (unescaped before the XOR).

Strictly static: it reads bytes and applies arithmetic. It does not parse the file
as code, import it, or execute any part of it.

    python3 decode.py <input.js> [outdir] [--format json|text] [--max-bytes N]
"""

from __future__ import annotations

import argparse
import base64
import json
import mmap
import os
import re
import sys

# ---- bounds (a huge minified file must not blow up memory/time) --------------
_MAX_READ = 64 * 1024 * 1024          # cap bytes read from the input
_MAX_SITES = 20000                    # cap decode sites examined
_MAX_STRINGS = 50000                  # cap recovered strings
_MAX_DECODED_TOTAL = 16 * 1024 * 1024 # cap total decoded output bytes
_PER_STRING_CAP = 1024 * 1024         # cap a single decoded string
_ARG_SCAN_CAP = 4 * 1024 * 1024       # cap size of an encoded literal we decode
_BODY_MAX = 4000                      # cap on a decoder body we scan (balanced braces)
_MIN_LEN = 3                          # ignore trivially short decodes
_PRINTABLE_MIN = 0.80                 # decoded text must be mostly printable

_IDENT = r"[A-Za-z_$][\w$]*"
_INT = r"0[xX][0-9a-fA-F]+|\d{1,7}"
_TOKEN = r"0[xX][0-9a-fA-F]+|\d{1,7}|[A-Za-z_$][\w$]*"   # key: literal or variable
_STR = r'"(?:[^"\\\n]|\\.)*"|\'(?:[^\'\\\n]|\\.)*\''
_ARR = r"\[[0-9xXa-fA-F,\s]{0,500000}\]"

# One pass builds a table of simple constant assignments so we can resolve a key
# variable (`kk5=91`) or a payload variable (`Nk5="<base64>"`) by nearest site.
_ASSIGN_RE = re.compile(
    r"(?<![\w.$])(?:(?:var|let|const)\s+)?(" + _IDENT + r")\s*=\s*("
    + _INT + r"|" + _STR + r"|" + _ARR + r")"
)

# A function decoder: `function NAME(PARAM ...){` — body inspected separately.
_FUNC_RE = re.compile(r"function\s+(" + _IDENT + r")\s*\(\s*(" + _IDENT + r")[^)]*\)\s*\{")
# Arrow decoder assigned to a name: `const NAME = (PARAM) => {` / `NAME=PARAM=>{`
_ARROW_RE = re.compile(
    r"(?<![\w.$])(?:(?:var|let|const)\s+)?(" + _IDENT + r")\s*=\s*"
    r"(?:function\s*)?\(?\s*(" + _IDENT + r")\s*\)?\s*=>\s*\{")

# Inside a decoder body: the XOR-charCode signature and the key token.
_BODY_KEY_RE = re.compile(
    r"(?:String\.)?fromCharCode\(\s*" + _IDENT + r"(?:\.charCodeAt\([^)]*\))?\s*\^\s*(" + _TOKEN + r")\)"
    r"|" + _IDENT + r"\.charCodeAt\([^)]*\)\s*\^\s*(" + _TOKEN + r")")
_B64_RE = re.compile(r"Buffer\.from\(\s*" + _IDENT + r"\s*,\s*[\"']base64[\"']|atob\(")
_CHARCODEAT_RE = re.compile(r"\.charCodeAt\(")

# Inline decode sites (data literal adjacent to the XOR).
_INLINE_ARR_FOROF = re.compile(
    r"for\s*\(\s*(?:let|const|var)\s+(" + _IDENT + r")\s+of\s+(" + _ARR + r")\s*\)"
    r"[^;{}]{0,60}?(?:String\.)?fromCharCode\(\s*\1\s*\^\s*(" + _TOKEN + r")\)")
_INLINE_STR_FOROF = re.compile(
    r"for\s*\(\s*(?:let|const|var)\s+(" + _IDENT + r")\s+of\s+(" + _STR + r")\s*\)"
    r"[^;{}]{0,60}?(?:String\.)?fromCharCode\(\s*\1(?:\.charCodeAt\([^)]*\))?\s*\^\s*(" + _TOKEN + r")\)")
_INLINE_ARR_MAP = re.compile(
    r"(" + _ARR + r")\s*\.map\(\s*(?:function\s*)?\(?\s*(" + _IDENT + r")\b[^)]*\)?\s*=>"
    r"[^;]{0,80}?\2\s*\^\s*(" + _TOKEN + r")")
_INLINE_STR_MAP = re.compile(
    r"(" + _STR + r")\s*\.split\([^)]*\)\s*\.map\(\s*(?:function\s*)?\([^)]*\)\s*=>"
    r"[^;]{0,80}?\.charCodeAt\([^)]*\)\s*\^\s*(" + _TOKEN + r")")

_JS_ESCAPE_RE = re.compile(r"\\(?:x[0-9a-fA-F]{2}|u\{[0-9a-fA-F]{1,6}\}|u[0-9a-fA-F]{4}|[^xu])")
_SIMPLE_ESC = {"n": "\n", "t": "\t", "r": "\r", "b": "\b", "f": "\f", "v": "\v",
               "0": "\0", "\\": "\\", "'": "'", '"': '"', "`": "`", "/": "/", "\n": ""}


def _read_text(path: str, max_bytes: int) -> str:
    """Bounded read via mmap; latin-1 keeps byte==codepoint so char offsets are byte
    offsets and decoding never raises. Escapes stay as literal text for the unescaper."""
    size = os.path.getsize(path)
    if size == 0:
        return ""
    n = min(size, max_bytes)
    with open(path, "rb") as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        try:
            return mm[:n].decode("latin-1")
        finally:
            mm.close()


def _parse_int(tok: str):
    try:
        return int(tok, 16) if tok[:2].lower() == "0x" else int(tok)
    except ValueError:
        return None


def _unescape(inner: str) -> str:
    """Decode JS string-literal escapes (\\xNN \\uNNNN \\u{..} \\n …) without eval."""
    def repl(m):
        e = m.group(0)[1:]
        if e[0] == "x":
            return chr(int(e[1:3], 16))
        if e[0] == "u":
            if e[1] == "{":
                return chr(int(e[2:-1], 16))
            return chr(int(e[1:5], 16))
        return _SIMPLE_ESC.get(e, e)
    return _JS_ESCAPE_RE.sub(repl, inner)


def _strlit_inner(lit: str) -> str:
    return _unescape(lit[1:-1]) if len(lit) >= 2 else ""


def _printable_ratio(s: str) -> float:
    if not s:
        return 0.0
    ok = sum(1 for c in s if c in "\t\n\r" or 32 <= ord(c) <= 126 or ord(c) >= 160)
    return ok / len(s)


class Assignments:
    """name -> sorted [(offset, kind, value)] for nearest-preceding resolution.
    kind: 'int' -> int; 'str' -> unescaped str; 'arr' -> raw array text."""

    def __init__(self, text: str):
        self.table: dict[str, list[tuple[int, str, object]]] = {}
        for m in _ASSIGN_RE.finditer(text):
            name, raw = m.group(1), m.group(2)
            if raw[0] in "0123456789":
                v = _parse_int(raw)
                if v is None:
                    continue
                self.table.setdefault(name, []).append((m.start(), "int", v))
            elif raw[0] in "\"'":
                self.table.setdefault(name, []).append((m.start(), "str", _strlit_inner(raw)))
            elif raw[0] == "[":
                self.table.setdefault(name, []).append((m.start(), "arr", raw))
        for v in self.table.values():
            v.sort()

    def _nearest(self, name: str, off: int):
        entries = self.table.get(name)
        if not entries:
            return None
        best = None
        for e in entries:
            if e[0] <= off:
                best = e
            else:
                break
        return best or entries[0]  # fall back to closest following if none precede

    def resolve_int(self, tok: str, off: int):
        v = _parse_int(tok)
        if v is not None:
            return v
        e = self._nearest(tok, off)
        return e[2] if e and e[1] == "int" else None

    def resolve_data(self, arg: str, off: int):
        """arg is a raw string literal, raw array literal, or an identifier.
        Returns ('str', text) | ('arr', text) | None."""
        arg = arg.strip()
        if arg[:1] in "\"'":
            return ("str", _strlit_inner(arg))
        if arg[:1] == "[":
            return ("arr", arg)
        e = self._nearest(arg, off)
        if not e:
            return None
        if e[1] == "str":
            return ("str", e[2])
        if e[1] == "arr":
            return ("arr", e[2])
        return None


def _parse_int_array(text: str):
    out = []
    for tok in text[1:-1].split(","):
        tok = tok.strip()
        if not tok:
            continue
        v = _parse_int(tok)
        if v is None:
            return None
        out.append(v)
        if len(out) > 500000:
            break
    return out


def _decode(mode: str, kind: str, data: str, key: int):
    """Apply the constant-key XOR. mode: base64|string|array. Returns decoded str or None."""
    try:
        if mode == "base64":
            b = base64.b64decode(data + "=" * (-len(data) % 4), validate=False)
            if len(b) > _ARG_SCAN_CAP:
                b = b[:_ARG_SCAN_CAP]
            codes = b
        elif kind == "arr":
            ints = _parse_int_array(data)
            if ints is None:
                return None
            codes = ints
        else:  # string mode: XOR each char code
            if len(data) > _ARG_SCAN_CAP:
                data = data[:_ARG_SCAN_CAP]
            codes = [ord(c) for c in data]
        out = "".join(chr(c ^ key) if 0 <= (c ^ key) <= 0x10FFFF and not 0xD800 <= (c ^ key) <= 0xDFFF
                      else "�" for c in codes)
    except (ValueError, TypeError):
        return None
    if len(out) > _PER_STRING_CAP:
        out = out[:_PER_STRING_CAP]
    return out


def _body_of(text: str, brace_idx: int) -> str:
    """Return the balanced `{...}` body starting at brace_idx (bounded), so mode
    detection is scoped to THIS function and never bleeds into the next one."""
    depth = 0
    cap = min(len(text), brace_idx + _BODY_MAX)
    i = brace_idx
    while i < cap:
        c = text[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return text[brace_idx:i + 1]
        i += 1
    return text[brace_idx:cap]


def find_decoders(text: str, assigns: Assignments):
    """Detect decoder functions: (name, key, mode, def_start)."""
    decoders = []
    for rx in (_FUNC_RE, _ARROW_RE):
        for m in rx.finditer(text):
            name, param = m.group(1), m.group(2)
            body = _body_of(text, m.end() - 1)  # m.end()-1 is the opening '{'
            km = _BODY_KEY_RE.search(body)
            if not km:
                continue
            keytok = km.group(1) or km.group(2)
            key = assigns.resolve_int(keytok, m.start())
            if key is None or not (1 <= key <= 255):
                continue
            if _B64_RE.search(body):
                mode = "base64"
            elif _CHARCODEAT_RE.search(body):
                mode = "string"
            else:
                mode = "array"
            decoders.append((name, param, key, mode, m.start()))
    # de-dup by name+offset
    uniq = {}
    for d in decoders:
        uniq[(d[0], d[4])] = d
    return list(uniq.values())


def run(path: str, outdir: str | None, max_bytes: int) -> dict:
    text = _read_text(path, max_bytes)
    if not text:
        return {"ok": True, "outputDir": os.path.abspath(outdir) if outdir else None,
                "decoded": [], "siteCount": 0}

    assigns = Assignments(text)
    # results: list of (key, offset, mode, decoded_str, how)
    results = []
    seen_strings = set()
    total_bytes = 0
    site_count = 0

    def add(key, off, mode, decoded, how):
        nonlocal total_bytes, site_count
        if decoded is None or len(decoded) < _MIN_LEN:
            return
        if _printable_ratio(decoded) < _PRINTABLE_MIN:
            return
        site_count += 1
        dedup = (key, decoded)
        if dedup in seen_strings:
            return
        if len(results) >= _MAX_STRINGS or total_bytes >= _MAX_DECODED_TOTAL:
            return
        seen_strings.add(dedup)
        results.append((key, off, mode, decoded, how))
        total_bytes += len(decoded)

    # -- Phase 1: decoder functions + their call sites -------------------------
    decoders = find_decoders(text, assigns)
    for name, param, key, mode, def_start in decoders:
        call_rx = re.compile(r"(?<![\w.$])" + re.escape(name) + r"\s*\(\s*(" + _STR + r"|" + _ARR + r"|" + _IDENT + r")\s*\)")
        for cm in call_rx.finditer(text):
            if site_count >= _MAX_SITES:
                break
            # skip the definition itself (arg is the bare param, right after `function NAME(`)
            pre = text[max(0, cm.start() - 12):cm.start()]
            if pre.rstrip().endswith("function"):
                continue
            arg = cm.group(1)
            resolved = assigns.resolve_data(arg, cm.start())
            if not resolved:
                continue
            kind, data = resolved
            if len(data) > _ARG_SCAN_CAP:
                continue
            decoded = _decode(mode, kind, data, key)
            add(key, cm.start(), mode + "/fn:" + name, decoded, "decoder-fn")

    # -- Phase 2: inline sites -------------------------------------------------
    for rx, mode, di, ki in ((_INLINE_ARR_FOROF, "array", 2, 3),
                             (_INLINE_STR_FOROF, "string", 2, 3),
                             (_INLINE_ARR_MAP, "array", 1, 3),
                             (_INLINE_STR_MAP, "string", 1, 2)):
        for m in rx.finditer(text):
            if site_count >= _MAX_SITES:
                break
            keytok = m.group(ki)
            key = assigns.resolve_int(keytok, m.start())
            if key is None or not (1 <= key <= 255):
                continue
            raw = m.group(di)
            if len(raw) > _ARG_SCAN_CAP:
                continue
            if raw[:1] in "\"'":
                kind, data = "str", _strlit_inner(raw)
            else:
                kind, data = "arr", raw
            decoded = _decode("array" if kind == "arr" else "string", kind, data, key)
            add(key, m.start(), mode + "/inline", decoded, "inline")

    # -- aggregate by key ------------------------------------------------------
    by_key: dict[int, list] = {}
    for key, off, mode, decoded, how in results:
        by_key.setdefault(key, []).append(decoded)
    decoded_summary = []
    for key in sorted(by_key):
        strings = by_key[key]
        sample = strings[0]
        decoded_summary.append({"key": key, "count": len(strings),
                                "sample": sample[:200] + ("…" if len(sample) > 200 else "")})

    out_dir_abs = os.path.abspath(outdir) if outdir else None
    if outdir and results:
        os.makedirs(outdir, exist_ok=True)
        out_file = os.path.join(outdir, "decoded-strings.js")
        with open(out_file, "w", encoding="utf-8") as fh:
            fh.write("// decoded from " + os.path.abspath(path) + "\n")
            fh.write("// %d string(s) statically recovered by js-string-decode "
                     "(constant-key XOR / charCode)\n" % len(results))
            for key, off, mode, decoded, how in results:
                lit = json.dumps(decoded, ensure_ascii=False)
                fh.write("/* key=%d %s off=%d */ %s\n" % (key, mode, off, lit))

    # Emit an atom per decode site so the recovered plaintext SURFACES as evidence in a
    # finding (BP-OBFUSCATION composes OBF.XOR) — not just written to decoded-strings.js.
    # No file/line: the ingest prefixes the artifact's origin (logical) path.
    atoms = []
    for key, off, mode, decoded, how in results[:50]:
        sample = decoded[:200] + ("…" if len(decoded) > 200 else "")
        atoms.append({
            "atom": "OBF.XOR", "confidence": 0.85,
            "note": "recovered concealed string via constant-key XOR (key=%d): %s" % (key, sample),
        })

    return {"ok": True, "outputDir": out_dir_abs, "decoded": decoded_summary,
            "siteCount": len(results), "atoms": atoms}


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="js-string-decode")
    p.add_argument("input")
    p.add_argument("outdir", nargs="?", default=None,
                   help="if given, write recovered plaintext to <outdir>/decoded-strings.js")
    p.add_argument("--format", choices=["json", "text"], default="json",
                   help="json is the machine default the RE provider consumes; text for humans")
    p.add_argument("--max-bytes", type=int, default=_MAX_READ)
    args = p.parse_args(argv[1:])

    if not os.path.isfile(args.input):
        sys.stdout.write(json.dumps({"ok": False, "error": "file not found: " + args.input}) + "\n")
        return 2
    try:
        result = run(args.input, args.outdir, args.max_bytes)
    except (OSError, ValueError, re.error) as e:
        sys.stdout.write(json.dumps({"ok": False, "error": "%s: %s" % (type(e).__name__, e)}) + "\n")
        return 1

    if args.format == "json":
        sys.stdout.write(json.dumps(result) + "\n")
        return 0

    # text (human) mode
    print("js-string-decode: %s" % os.path.basename(args.input))
    print("  sites decoded: %d" % result["siteCount"])
    if result["outputDir"] and result["siteCount"]:
        print("  wrote: %s" % os.path.join(result["outputDir"], "decoded-strings.js"))
    for d in result["decoded"]:
        print("  [key=%d] %d string(s); sample: %s" % (d["key"], d["count"], d["sample"]))
    if not result["decoded"]:
        print("  (no constant-key XOR/charCode decode sites resolved)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

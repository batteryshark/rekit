#!/usr/bin/env python3
"""js-sourcemap-extract — recover original sources from a JavaScript source map.

Minified/bundled JS often ships (or leaks) a source map whose `sourcesContent`
holds the ORIGINAL, un-minified source of every input file. This reconstructs that
tree — turning an unreadable bundle back into readable files you can scan with
js-covert-scan / js-deobfuscate.

Input is a `.map` (JSON) OR a `.js` that references one via `//# sourceMappingURL=`
(an inline `data:` map or a sibling `.map` file). Pure stdlib, read-only.

    python3 extract.py <file.js|.map> <outdir> [--format text|json]
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import sys

_SMURL = re.compile(rb"//[#@]\s*sourceMappingURL=([^\s'\"]+)")
_PER_FILE = 64 * 1024 * 1024


def _clean_source_path(src: str) -> str:
    # strip scheme/protocol (webpack://, http://, file://) and any authority
    src = re.sub(r"^[a-zA-Z][\w.+-]*://", "", src)
    src = src.split("?", 1)[0].split("#", 1)[0]
    src = src.replace("\\", "/").replace("\x00", "")
    # drop leading ../ and / and ~ so everything lands under outdir
    parts = [p for p in src.split("/") if p not in ("", ".", "..", "~")]
    return "/".join(parts) or "unnamed.js"


def load_map(path: str) -> dict | None:
    with open(path, "rb") as f:
        data = f.read()
    stripped = data.lstrip()
    if stripped[:1] in (b"{", b"["):
        return json.loads(data.decode("utf-8", "replace"))
    # a .js — find the sourceMappingURL
    m = _SMURL.search(data)
    if not m:
        return None
    url = m.group(1).decode("utf-8", "replace")
    if url.startswith("data:"):
        b64 = url.split(",", 1)[1] if "," in url else ""
        if ";base64" in url.split(",", 1)[0]:
            return json.loads(base64.b64decode(b64).decode("utf-8", "replace"))
        from urllib.parse import unquote
        return json.loads(unquote(b64))
    # external map file, resolved next to the .js
    cand = os.path.join(os.path.dirname(path), _clean_source_path(url))
    if os.path.isfile(cand):
        return load_map(cand)
    cand2 = path + ".map"
    if os.path.isfile(cand2):
        return load_map(cand2)
    return None


def _safe(outdir: str, name: str) -> str | None:
    target = os.path.realpath(os.path.join(outdir, name))
    root = os.path.realpath(outdir)
    return target if (target == root or target.startswith(root + os.sep)) else None


def analyze(path: str, outdir: str):
    sm = load_map(path)
    if not isinstance(sm, dict) or "sources" not in sm:
        return {"hasSourceMap": False, "note": "no source map found (need a .map or a "
                "//# sourceMappingURL in the .js)"}, 0, 0

    sources = sm.get("sources") or []
    contents = sm.get("sourcesContent") or []
    os.makedirs(outdir, exist_ok=True)
    recovered = no_content = 0
    for i, src in enumerate(sources):
        content = contents[i] if i < len(contents) else None
        if content is None:
            no_content += 1
            continue
        rel = _clean_source_path(str(src))
        target = _safe(outdir, rel)
        if target is None or len(content) > _PER_FILE:
            continue
        os.makedirs(os.path.dirname(target) or outdir, exist_ok=True)
        with open(target, "w", encoding="utf-8") as f:
            f.write(content)
        recovered += 1
    return {"hasSourceMap": True, "sourceCount": len(sources),
            "recovered": recovered, "withoutContent": no_content,
            "extractedTo": os.path.abspath(outdir)}, recovered, no_content


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="js-sourcemap-extract")
    p.add_argument("input")
    p.add_argument("outdir")
    p.add_argument("--format", choices=["text", "json"], default="text")
    args = p.parse_args(argv[1:])
    if not os.path.isfile(args.input):
        sys.stdout.write(json.dumps({"ok": False, "error": f"file not found: {args.input}"}) + "\n")
        return 2
    try:
        info, recovered, _ = analyze(args.input, args.outdir)
    except (ValueError, OSError) as exc:
        sys.stdout.write(json.dumps({"ok": False, "error": f"parse failed: {exc}"}) + "\n")
        return 1

    result = {"ok": True, "path": os.path.abspath(args.input), **info}
    if args.format == "json":
        sys.stdout.write(json.dumps(result) + "\n")
        return 0
    if not info.get("hasSourceMap"):
        print(f"js-sourcemap-extract: {info['note']}")
        return 1
    extra = f" ({info['withoutContent']} had no embedded content)" if info["withoutContent"] else ""
    print(f"js-sourcemap-extract: {os.path.basename(args.input)}")
    print(f"  {info['recovered']}/{info['sourceCount']} original source(s) recovered{extra}")
    print(f"  → {info['extractedTo']}  (scan with js-covert-scan / js-deobfuscate)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

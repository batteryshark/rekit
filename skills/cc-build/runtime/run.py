"""cc-build — compile C / C++ / ObjC source to a native artifact. CONSTRUCT.

The first of rekit's *construct* skills: it doesn't read a sample, it PRODUCES one —
a PoC, a test harness, a stub, a shared lib. Thin, honest wrapper over clang (falling
back to cc/gcc): pick a compiler, build the argv, run it, report the artifact + the
compiler diagnostics. It compiles; it does NOT run the result (that would be the
dynamic tier's job — feed the output to exec-observe/emulate-code yourself).

    python3 run.py <source...> [--out P] [--emit exe|obj|asm|ir] [--std ..] [--opt N]
                   [--arch A] [--target TRIPLE] [--shared] [--static] [--cflags "…"]
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import shutil
import subprocess
import sys

_COMPILERS = ["clang", "cc", "gcc"]
_EMIT_FLAGS = {"exe": [], "obj": ["-c"], "asm": ["-S"], "ir": ["-S", "-emit-llvm"]}
_EMIT_EXT = {"obj": ".o", "asm": ".s", "ir": ".ll"}


def _pick_compiler(explicit: str | None) -> str | None:
    if explicit:
        return shutil.which(explicit) or explicit  # honor a bogus name → fails honestly
    for c in _COMPILERS:
        found = shutil.which(c)
        if found:
            return found
    return None


def _default_out(source0: str, emit: str, shared: bool) -> str:
    stem = os.path.splitext(os.path.basename(source0))[0] or "a"
    if emit != "exe":
        return stem + _EMIT_EXT[emit]
    if shared:
        return stem + (".dylib" if sys.platform == "darwin" else ".so")
    return stem


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="cc-build")
    p.add_argument("source", nargs="+", help="source file(s) to compile")
    p.add_argument("--out", help="output path (default: derived from first source + emit)")
    p.add_argument("--compiler", help="force a specific compiler (default: clang|cc|gcc)")
    p.add_argument("--std", help="language standard, e.g. c11, gnu17, c++20")
    p.add_argument("--opt", default="2", help="optimization level 0|1|2|3|s|z (default 2)")
    p.add_argument("--arch", help="target arch via -arch (clang/darwin), e.g. x86_64, arm64")
    p.add_argument("--target", help="cross-compile target triple (clang -target)")
    p.add_argument("--emit", choices=list(_EMIT_FLAGS), default="exe",
                   help="exe (link) | obj (.o) | asm (.s) | ir (LLVM .ll, clang only)")
    p.add_argument("--shared", action="store_true", help="build a shared library")
    p.add_argument("--static", action="store_true", help="static-link (-static)")
    p.add_argument("--cflags", default="", help="extra flags passed verbatim (shell-split)")
    p.add_argument("--format", choices=["text", "json"], default="text")
    a = p.parse_args(argv[1:])

    missing = [s for s in a.source if not os.path.isfile(s)]
    if missing:
        print(json.dumps({"ok": False, "error": f"source not found: {', '.join(missing)}"}))
        return 2
    cc = _pick_compiler(a.compiler)
    if not cc:
        print(json.dumps({"ok": False, "error": "no C compiler on PATH",
                          "hint": "install clang (macOS: xcode-select --install; or LLVM) or gcc"}))
        return 3
    if a.emit == "ir" and "clang" not in os.path.basename(cc):
        print(json.dumps({"ok": False, "error": "emit=ir (LLVM IR) requires clang",
                          "hint": "pass --compiler clang, or use --emit asm"}))
        return 2

    out = os.path.abspath(a.out) if a.out else os.path.abspath(_default_out(a.source[0], a.emit, a.shared))
    cmd = [cc, f"-O{a.opt}"]
    if a.std:
        cmd.append(f"-std={a.std}")
    if a.target:
        cmd += ["-target", a.target]
    if a.arch:
        cmd += ["-arch", a.arch]
    if a.shared:
        cmd.append("-shared")
    if a.static:
        cmd.append("-static")
    cmd += _EMIT_FLAGS[a.emit]
    if a.cflags:
        cmd += shlex.split(a.cflags)
    cmd += list(a.source) + ["-o", out]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    except (OSError, subprocess.SubprocessError) as exc:
        print(json.dumps({"ok": False, "error": f"compiler invocation failed: {exc}"}))
        return 1

    ok = proc.returncode == 0 and os.path.exists(out)
    res = {"ok": ok, "compiler": cc, "emit": a.emit, "out": out if ok else None,
           "size": os.path.getsize(out) if os.path.exists(out) else None,
           "returncode": proc.returncode, "diagnostics": (proc.stderr or "").strip()[:4000],
           "argv": cmd}
    if a.format == "json":
        print(json.dumps(res))
        return 0 if ok else 1
    if ok:
        print(f"cc-build: {os.path.basename(out)}  ({res['size']} bytes · {a.emit} · {os.path.basename(cc)})")
        if res["diagnostics"]:
            print(res["diagnostics"])
    else:
        print(f"cc-build: FAILED (exit {proc.returncode})")
        print(res["diagnostics"] or "(no diagnostics)")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

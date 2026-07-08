"""shellcode-stub — wrap a raw shellcode blob into a runnable native PoC. CONSTRUCT.

The last link in the write-side chain: asm-assemble makes bytes, this drops them into a
tiny C loader (mmap RW → memcpy → mprotect RX → call as int(void)) and compiles a native
executable whose exit code is the shellcode's return value. Run it under exec-observe
(matching host arch) or emulate it cross-arch under qiling-emulate.

    python3 run.py <shellcode.bin> | --hex "48c7c0…"  [--emit exe|c] [--out P]
                   [--arch A] [--target TRIPLE] [--format text|json]

⚠️ The produced exe RUNS the shellcode when *you* run it — that's the dynamic tier's job,
not this skill's. shellcode-stub only BUILDS it (executes_input: no).
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile

_STUB = """/* rekit shellcode-stub — mmap RW, copy, mprotect RX, call as int(void).
   Exit code = the shellcode's return value. POSIX (Linux / macOS). */
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static unsigned char sc[] = {
%s
};

int main(void) {
    size_t n = sizeof(sc);
    long ps = sysconf(_SC_PAGESIZE);
    size_t sz = ((n + (size_t)ps - 1) / (size_t)ps) * (size_t)ps;
    void *m = mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (m == MAP_FAILED) { perror("mmap"); return 127; }
    memcpy(m, sc, n);
    if (mprotect(m, sz, PROT_READ | PROT_EXEC) != 0) { perror("mprotect"); return 126; }
    int (*fn)(void) = (int (*)(void))m;
    return fn();
}
"""


def _c_array(data: bytes) -> str:
    rows = []
    for i in range(0, len(data), 12):
        rows.append("    " + ", ".join(f"0x{b:02x}" for b in data[i:i + 12]) + ",")
    return "\n".join(rows)


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="shellcode-stub")
    p.add_argument("shellcode", nargs="?", help="raw shellcode blob (or use --hex)")
    p.add_argument("--hex", dest="hexs", help="shellcode as a hex string instead of a file")
    p.add_argument("--emit", choices=["exe", "c"], default="exe",
                   help="exe = compiled PoC (needs clang) | c = the loader source only")
    p.add_argument("--out", help="output path (default: derived)")
    p.add_argument("--arch", help="-arch for the stub compile (clang/darwin), e.g. x86_64, arm64")
    p.add_argument("--target", help="cross-compile triple (clang -target) — needs a cross sysroot (see --cflags)")
    p.add_argument("--cflags", default="", help="extra clang flags (shell-split), e.g. '--sysroot=… -fuse-ld=lld' for cross builds")
    p.add_argument("--format", choices=["text", "json"], default="text")
    a = p.parse_args(argv[1:])

    if a.hexs:
        try:
            data = bytes.fromhex(a.hexs.replace("0x", "").replace(" ", "").replace(",", ""))
        except ValueError as exc:
            print(json.dumps({"ok": False, "error": f"bad --hex: {exc}"}))
            return 2
    elif a.shellcode and os.path.isfile(a.shellcode):
        with open(a.shellcode, "rb") as fh:
            data = fh.read()
    else:
        print(json.dumps({"ok": False, "error": "no input: pass a shellcode file or --hex '…'"}))
        return 2
    if not data:
        print(json.dumps({"ok": False, "error": "empty shellcode"}))
        return 2

    src = _STUB % _c_array(data)
    base = os.path.splitext(os.path.basename(a.shellcode))[0] if a.shellcode else "shellcode"

    if a.emit == "c":
        out = os.path.abspath(a.out or (base + "_stub.c"))
        with open(out, "w", encoding="utf-8") as fh:
            fh.write(src)
        res = {"ok": True, "emit": "c", "out": out, "shellcodeLen": len(data)}
        print(json.dumps(res) if a.format == "json" else
              f"shellcode-stub: wrote loader source → {out} ({len(data)} bytes embedded)")
        return 0

    clang = shutil.which("clang")
    if not clang:
        print(json.dumps({"ok": False, "error": "clang not on PATH (needed for --emit exe)",
                          "hint": "install clang/LLVM, or use --emit c and compile with cc-build"}))
        return 3
    out = os.path.abspath(a.out or base)
    with tempfile.TemporaryDirectory() as td:
        spath = os.path.join(td, "stub.c")
        with open(spath, "w", encoding="utf-8") as fh:
            fh.write(src)
        cmd = [clang, "-O2"]
        if a.target:
            cmd += ["-target", a.target]
        if a.arch:
            cmd += ["-arch", a.arch]
        if a.cflags:
            cmd += shlex.split(a.cflags)
        cmd += [spath, "-o", out]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    ok = proc.returncode == 0 and os.path.exists(out)
    res = {"ok": ok, "emit": "exe", "out": out if ok else None,
           "size": os.path.getsize(out) if os.path.exists(out) else None,
           "shellcodeLen": len(data), "diagnostics": (proc.stderr or "").strip()[:2000]}
    if a.format == "json":
        print(json.dumps(res))
        return 0 if ok else 1
    if ok:
        print(f"shellcode-stub: {os.path.basename(out)}  "
              f"({res['size']} bytes exe · {len(data)} bytes shellcode)")
        print(f"  run it (matching host arch): rekit run --allow-dynamic exec-observe {out}")
        print(f"  or emulate cross-arch:       rekit run qiling-emulate {out} --rootfs <dir>")
    else:
        print(f"shellcode-stub: FAILED (exit {proc.returncode})")
        print(res["diagnostics"] or "(no diagnostics)")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

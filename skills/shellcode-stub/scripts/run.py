"""shellcode-stub — wrap a raw shellcode blob into a runnable native PoC. CONSTRUCT.

The last link in the write-side chain: asm-assemble makes bytes, this drops them into a
tiny C loader and compiles a native executable whose exit code is the shellcode's return
value. Run it under exec-observe (matching host arch) or emulate it cross-arch/cross-OS
under qiling-emulate.

    python3 run.py <shellcode.bin> | --hex "48c7c0…"  [--emit exe|c] [--out P]
                   [--os posix|windows] [--arch A] [--target TRIPLE] [--cflags F]
                   [--format text|json]

Two loader templates, picked by --os:
  posix    (default) mmap RW → memcpy → mprotect RX → call.      POSIX (Linux/macOS).
  windows  VirtualAlloc RWX → memcpy → call → ExitProcess(r).    Windows PE (mingw).

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

_STUB_POSIX = """/* rekit shellcode-stub — POSIX loader. mmap RW, copy, mprotect RX, call as int(void).
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

_STUB_WINDOWS = """/* rekit shellcode-stub — Windows loader. VirtualAlloc RWX, copy, call as int(void),
   ExitProcess(result). Exit code = the shellcode's return value. Windows PE (mingw). */
#include <windows.h>
#include <string.h>

static unsigned char sc[] = {
%s
};

int main(void) {
    SIZE_T n = (SIZE_T)sizeof(sc);
    void *m = VirtualAlloc(NULL, n, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (m == NULL) return 127;
    memcpy(m, sc, (size_t)n);
    int (*fn)(void) = (int (*)(void))m;
    int r = fn();
    ExitProcess((DWORD)(unsigned int)r);
    return r;  /* not reached; satisfies the compiler */
}
"""

# Default cross-compile triple per OS when --target is not given.
_DEFAULT_TARGET = {"posix": None, "windows": "x86_64-w64-mingw32"}


def _looks_like_mingw_missing(diag: str) -> bool:
    """Honest-failure sniffer: did a windows build fail because no mingw sysroot/headers?"""
    d = (diag or "").lower()
    return any(s in d for s in (
        "'windows.h' file not found", "windows.h: no such file",
        "cannot find -lkernel32", "library not found for -lkernel32",
        "unable to find a visual studio", "unknown file type",
    ))


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
    p.add_argument("--os", choices=["posix", "windows"], default="posix",
                   help="loader template: posix (mmap/mprotect, default) | windows (VirtualAlloc+ExitProcess)")
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

    src = (_STUB_POSIX if a.os == "posix" else _STUB_WINDOWS) % _c_array(data)
    base = os.path.splitext(os.path.basename(a.shellcode))[0] if a.shellcode else "shellcode"

    if a.emit == "c":
        out = os.path.abspath(a.out or (base + "_stub.c"))
        with open(out, "w", encoding="utf-8") as fh:
            fh.write(src)
        res = {"ok": True, "emit": "c", "os": a.os, "out": out, "shellcodeLen": len(data)}
        print(json.dumps(res) if a.format == "json" else
              f"shellcode-stub: wrote {a.os} loader source → {out} ({len(data)} bytes embedded)")
        return 0

    clang = shutil.which("clang")
    if not clang:
        print(json.dumps({"ok": False, "error": "clang not on PATH (needed for --emit exe)",
                          "hint": "install clang/LLVM, or use --emit c and compile with cc-build"}))
        return 3
    if a.out:
        out = os.path.abspath(a.out)
    else:
        out = os.path.abspath(base + (".exe" if a.os == "windows" else ""))
    with tempfile.TemporaryDirectory() as td:
        spath = os.path.join(td, "stub.c")
        with open(spath, "w", encoding="utf-8") as fh:
            fh.write(src)
        cmd = [clang, "-O2"]
        target = a.target if a.target else _DEFAULT_TARGET[a.os]
        if target:
            cmd += ["-target", target]
        if a.arch:
            cmd += ["-arch", a.arch]
        if a.os == "windows":
            cmd += ["-lkernel32"]  # VirtualAlloc/ExitProcess live in kernel32.dll
        if a.cflags:
            cmd += shlex.split(a.cflags)
        cmd += [spath, "-o", out]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    ok = proc.returncode == 0 and os.path.exists(out)
    diag = (proc.stderr or "").strip()[:2000]
    hint = None
    if not ok and a.os == "windows" and _looks_like_mingw_missing(diag):
        hint = ("Windows build needs the mingw-w64 headers + sysroot (not shipped on macOS/Linux). "
                "Install with `brew install mingw-w64` (macOS) or your distro's mingw64 package, "
                "then pass the toolchain sysroot via --cflags, e.g. "
                '--cflags "--sysroot=/opt/homebrew/Cellar/mingw-w64/<ver>/toolchain-x86_64/x86_64-w64-mingw32 '
                '-fuse-ld=lld". Or hand the --emit c source to cc-build on a Windows/mingw host.')
    res = {"ok": ok, "emit": "exe", "os": a.os, "out": out if ok else None,
           "size": os.path.getsize(out) if os.path.exists(out) else None,
           "shellcodeLen": len(data), "diagnostics": diag}
    if hint:
        res["hint"] = hint
    if a.format == "json":
        print(json.dumps(res))
        return 0 if ok else 1
    if ok:
        print(f"shellcode-stub: {os.path.basename(out)}  "
              f"({res['size']} bytes {a.os} exe · {len(data)} bytes shellcode)")
        if a.os == "posix":
            print(f"  run it (matching host arch): rekit run --allow-dynamic exec-observe {out}")
        print(f"  emulate cross-arch/OS:        rekit run qiling-emulate {out} --rootfs <dir>")
    else:
        print(f"shellcode-stub: FAILED ({a.os} build, exit {proc.returncode})")
        print(diag or "(no diagnostics)")
        if hint:
            print(hint)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

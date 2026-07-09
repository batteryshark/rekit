"""asm-assemble — assemble asm text into machine-code bytes via the LLVM/clang
integrated assembler. CONSTRUCT.

Backed by clang (not a fragile native python binding — keystone ships no arm64-mac
wheel, so we lean on the LLVM assembler rekit already uses for cc-build). Assembles a
snippet to an object with `clang -c`, then extracts the raw `.text` bytes (otool on
macOS; objcopy/llvm-objcopy/objdump on ELF). The write-side partner of emulate-code:
assemble here, run it there — no host execution at any point.

    python3 run.py <asm-file> | --code "mov rax,1; ret"  [--arch x64|x86|arm64|arm]
                   [--att] [--out blob.bin] [--format hex|c|raw|json]
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile

# arch → clang target triple, per host OS (instruction *encoding* is OS-independent, so
# we assemble to the host's object format and extract from that).
_ARCH = {
    "darwin": {"x64": "x86_64-apple-darwin", "arm64": "arm64-apple-darwin",
               "x86": "i386-apple-darwin", "arm": "armv7-apple-darwin"},
    "linux": {"x64": "x86_64-linux-gnu", "arm64": "aarch64-linux-gnu",
              "x86": "i386-linux-gnu", "arm": "arm-linux-gnueabihf"},
}


def _triple(arch: str) -> str | None:
    host = "darwin" if sys.platform == "darwin" else "linux"
    return _ARCH.get(host, _ARCH["linux"]).get(arch)


def _extract_text(obj: str) -> tuple[bytes | None, str | None]:
    """Pull the raw bytes of the code section out of an object file, honestly."""
    if shutil.which("otool"):  # macOS Mach-O
        p = subprocess.run(["otool", "-s", "__TEXT", "__text", obj], capture_output=True, text=True)
        if p.returncode == 0 and "(__TEXT,__text)" in p.stdout:
            # Data lines are "<addr> <tok> <tok> …". otool byte-dumps some arches (x86:
            # "48 c7 …") and 4-byte-word-dumps others (arm64: "d28266e0"); the words are
            # shown big-endian, so any multi-byte token is byte-reversed back to LE.
            data = bytearray()
            for line in p.stdout.splitlines():
                toks = line.split()
                if len(toks) < 2 or not re.fullmatch(r"[0-9a-fA-F]{8,}", toks[0]):
                    continue  # skip header/filename lines; toks[0] is the address column
                body = toks[1:]
                if not all(re.fullmatch(r"(?:[0-9a-fA-F]{2})+", t) for t in body):
                    continue
                for t in body:
                    b = bytes.fromhex(t)
                    data += b[::-1] if len(b) > 1 else b
            if data:
                return bytes(data), None
    for oc in ("objcopy", "llvm-objcopy", "gobjcopy"):  # ELF via objcopy family
        if shutil.which(oc):
            out = obj + ".bin"
            p = subprocess.run([oc, "-O", "binary", "--only-section=.text", obj, out],
                               capture_output=True, text=True)
            if p.returncode == 0 and os.path.exists(out):
                with open(out, "rb") as fh:
                    b = fh.read()
                os.remove(out)
                if b:
                    return b, None
    if shutil.which("objdump"):  # last resort: parse a disassembly dump
        p = subprocess.run(["objdump", "-d", "--section=.text", obj], capture_output=True, text=True)
        data = bytearray()
        for line in p.stdout.splitlines():
            m = re.match(r"\s*[0-9a-f]+:\s+((?:[0-9a-f]{2} )+)", line)
            if m:
                data += bytes(int(x, 16) for x in m.group(1).split())
        if data:
            return bytes(data), None
    return None, "no section extractor found (need otool on macOS, or objcopy/llvm-objcopy/objdump)"


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="asm-assemble")
    p.add_argument("source", nargs="?", help="file of asm text (or use --code)")
    p.add_argument("--code", help="inline asm, e.g. 'mov rax, 1; ret' (';' splits statements)")
    p.add_argument("--arch", choices=["x64", "x86", "arm64", "arm"], default="x64")
    p.add_argument("--att", action="store_true", help="x86: use AT&T/GAS syntax (default: Intel)")
    p.add_argument("--out", help="write the raw bytes to this path")
    p.add_argument("--format", choices=["hex", "c", "raw", "json"], default="hex")
    a = p.parse_args(argv[1:])

    if a.code:
        asm = a.code.replace(";", "\n")
    elif a.source and os.path.isfile(a.source):
        with open(a.source, "r", encoding="utf-8", errors="replace") as fh:
            asm = fh.read()
    else:
        print(json.dumps({"ok": False, "error": "no input: pass an asm file or --code '…'"}))
        return 2

    clang = shutil.which("clang")
    if not clang:
        print(json.dumps({"ok": False, "error": "clang not on PATH",
                          "hint": "install clang/LLVM (macOS: xcode-select --install)"}))
        return 3
    triple = _triple(a.arch)
    if not triple:
        print(json.dumps({"ok": False, "error": f"no triple for arch {a.arch} on this host"}))
        return 2

    # Intel syntax for x86 unless --att (matches the keystone-style feel); GAS for ARM.
    prologue = ".text\n"
    if a.arch in ("x64", "x86") and not a.att:
        prologue = ".intel_syntax noprefix\n.text\n"
    src = prologue + asm + "\n"

    with tempfile.TemporaryDirectory() as td:
        spath = os.path.join(td, "in.s")
        opath = os.path.join(td, "out.o")
        with open(spath, "w", encoding="utf-8") as fh:
            fh.write(src)
        proc = subprocess.run([clang, "-c", "-target", triple, spath, "-o", opath],
                              capture_output=True, text=True)
        if proc.returncode != 0 or not os.path.exists(opath):
            print(json.dumps({"ok": False, "error": "assemble failed",
                              "diagnostics": (proc.stderr or "").strip()[:3000]}))
            return 1
        data, why = _extract_text(opath)
    if data is None:
        print(json.dumps({"ok": False, "error": why}))
        return 1

    hexs = data.hex()
    res = {"ok": True, "arch": a.arch, "triple": triple, "length": len(data), "hex": hexs}
    if a.out:
        with open(a.out, "wb") as fh:
            fh.write(data)
        res["out"] = os.path.abspath(a.out)

    if a.format == "json":
        print(json.dumps(res))
        return 0
    if a.format == "raw":
        if a.out:
            print(f"asm-assemble: wrote {len(data)} bytes → {res['out']}")
        else:
            sys.stdout.buffer.write(data)
        return 0
    if a.format == "c":
        arr = ", ".join(f"0x{b:02x}" for b in data)
        print(f"// {a.arch} ({triple}), {len(data)} bytes")
        print(f"unsigned char shellcode[] = {{ {arr} }};")
        return 0
    print(f"asm-assemble: {a.arch}  {len(data)} bytes  ({triple})")
    print(hexs)
    if a.out:
        print(f"→ {res['out']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

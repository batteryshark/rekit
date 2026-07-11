#!/usr/bin/env python3
"""Generate conservative minimal executables without compiling or running them."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import List


FORMAT_ARCHES = {
    "elf": ("x86_64", "i386"),
    "pe": ("x86_64", "i386"),
    "macho": ("arm64",),
}


class BuildError(ValueError):
    pass


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


def _elf_code(arch: str, exit_code: int) -> bytes:
    if arch == "x86_64":
        return b"\xb8\x3c\x00\x00\x00\xbf" + struct.pack("<I", exit_code) + b"\x0f\x05"
    if arch == "i386":
        return b"\xb8\x01\x00\x00\x00\xbb" + struct.pack("<I", exit_code) + b"\xcd\x80"
    raise BuildError("ELF supports x86_64 and i386")


def build_elf(arch: str, exit_code: int) -> bytes:
    code = _elf_code(arch, exit_code)
    if arch == "x86_64":
        ehsize, phsize, machine, base = 64, 56, 62, 0x400000
        code_offset = ehsize + phsize
        total = code_offset + len(code)
        ident = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8
        header = struct.pack(
            "<16sHHIQQQIHHHHHH",
            ident, 2, machine, 1, base + code_offset, ehsize, 0, 0,
            ehsize, phsize, 1, 0, 0, 0,
        )
        program = struct.pack(
            "<IIQQQQQQ", 1, 5, 0, base, base, total, total, 0x1000
        )
    else:
        ehsize, phsize, machine, base = 52, 32, 3, 0x08048000
        code_offset = ehsize + phsize
        total = code_offset + len(code)
        ident = b"\x7fELF\x01\x01\x01\x00" + b"\x00" * 8
        header = struct.pack(
            "<16sHHIIIIIHHHHHH",
            ident, 2, machine, 1, base + code_offset, ehsize, 0, 0,
            ehsize, phsize, 1, 0, 0, 0,
        )
        program = struct.pack(
            "<IIIIIIII", 1, 0, base, base, total, total, 5, 0x1000
        )
    return header + program + code


def build_pe(arch: str, exit_code: int) -> bytes:
    if arch not in ("x86_64", "i386"):
        raise BuildError("PE supports x86_64 and i386")
    is64 = arch == "x86_64"
    optional_size = 240 if is64 else 224
    machine = 0x8664 if is64 else 0x14C
    characteristics = 0x0023 if is64 else 0x0103
    image_base = 0x140000000 if is64 else 0x00400000

    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)
    coff = b"PE\x00\x00" + struct.pack(
        "<HHIIIHH", machine, 1, 0, 0, 0, optional_size, characteristics
    )
    opt = bytearray(optional_size)
    struct.pack_into("<HBBIIII", opt, 0, 0x20B if is64 else 0x10B, 0, 0,
                     0x200, 0, 0, 0x1000)
    struct.pack_into("<I", opt, 20, 0x1000)  # BaseOfCode
    if is64:
        struct.pack_into("<Q", opt, 24, image_base)
    else:
        struct.pack_into("<I", opt, 24, 0)  # BaseOfData
        struct.pack_into("<I", opt, 28, image_base)
    struct.pack_into("<II", opt, 32, 0x1000, 0x200)
    struct.pack_into("<HHHHHH", opt, 40, 6, 0, 0, 0, 6, 0)
    struct.pack_into("<III", opt, 52, 0, 0x2000, 0x200)
    struct.pack_into("<IHH", opt, 64, 0, 3, 0x0100)
    if is64:
        struct.pack_into("<QQQQII", opt, 72, 0x100000, 0x1000,
                         0x100000, 0x1000, 0, 16)
    else:
        struct.pack_into("<IIIIII", opt, 72, 0x100000, 0x1000,
                         0x100000, 0x1000, 0, 16)

    code = b"\xb8" + struct.pack("<I", exit_code) + b"\xc3"
    section = struct.pack(
        "<8sIIIIIIHHI", b".text\x00\x00\x00", len(code), 0x1000,
        0x200, 0x200, 0, 0, 0, 0, 0x60000020,
    )
    headers = bytes(dos) + coff + bytes(opt) + section
    if len(headers) > 0x200:
        raise BuildError("internal PE headers exceed file alignment")
    return headers.ljust(0x200, b"\x00") + code.ljust(0x200, b"\x00")


def _segment(name: bytes, vmaddr: int, vmsize: int, fileoff: int,
             filesize: int, maxprot: int, initprot: int) -> bytes:
    return struct.pack(
        "<II16sQQQQiiII", 0x19, 72, name.ljust(16, b"\x00"), vmaddr,
        vmsize, fileoff, filesize, maxprot, initprot, 0, 0,
    )


def build_macho(arch: str, exit_code: int) -> bytes:
    if arch != "arm64":
        raise BuildError("Mach-O currently supports arm64 research artifacts only")
    base = 0x100000000
    thread_size = 16 + (68 * 4)
    command_size = 72 + 72 + thread_size
    code_offset = 32 + command_size
    code_words = (
        0xD2800000 | ((exit_code & 0xFFFF) << 5),  # mov x0, #exit_code
        0xD2800030,                                # mov x16, #1 (SYS_exit)
        0xD4001001,                                # svc #0x80
    )
    code = struct.pack("<III", *code_words)
    total = code_offset + len(code)
    header = struct.pack(
        "<IiiIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 3, command_size, 1, 0
    )
    pagezero = _segment(b"__PAGEZERO", 0, base, 0, 0, 0, 0)
    text = _segment(b"__TEXT", base, _align(total, 0x4000), 0, total, 7, 5)
    state = [0] * 33
    state[32] = base + code_offset  # pc
    state_blob = struct.pack("<" + ("Q" * 33) + "II", *state, 0, 0)
    thread = struct.pack("<IIII", 5, thread_size, 6, 68) + state_blob
    return header + pagezero + text + thread + code


def build_artifact(fmt: str, arch: str, exit_code: int) -> bytes:
    if arch not in FORMAT_ARCHES.get(fmt, ()):
        supported = ", ".join(FORMAT_ARCHES.get(fmt, ())) or "none"
        raise BuildError(f"{fmt} does not support {arch}; choose {supported}")
    if fmt == "elf":
        return build_elf(arch, exit_code)
    if fmt == "pe":
        return build_pe(arch, exit_code)
    if fmt == "macho":
        return build_macho(arch, exit_code)
    raise BuildError(f"unknown format: {fmt}")


def validate_artifact(data: bytes, fmt: str, arch: str) -> dict:
    checks = []

    def check(name: str, condition: bool) -> None:
        checks.append({"name": name, "ok": bool(condition)})

    if fmt == "elf":
        check("elf magic", data[:4] == b"\x7fELF")
        check("ELF class", data[4] == (2 if arch == "x86_64" else 1))
        machine = struct.unpack_from("<H", data, 18)[0]
        check("ELF machine", machine == (62 if arch == "x86_64" else 3))
        if arch == "x86_64":
            entry = struct.unpack_from("<Q", data, 24)[0]
            phoff = struct.unpack_from("<Q", data, 32)[0]
            phnum = struct.unpack_from("<H", data, 56)[0]
            ptype, flags, offset, vaddr, _paddr, filesz, memsz, _align_to = \
                struct.unpack_from("<IIQQQQQQ", data, phoff)
        else:
            entry = struct.unpack_from("<I", data, 24)[0]
            phoff = struct.unpack_from("<I", data, 28)[0]
            phnum = struct.unpack_from("<H", data, 44)[0]
            ptype, offset, vaddr, _paddr, filesz, memsz, flags, _align_to = \
                struct.unpack_from("<IIIIIIII", data, phoff)
        check("program header offset", phoff == (64 if arch == "x86_64" else 52))
        check("single program header", phnum == 1)
        check("single RX load region", ptype == 1 and flags == 5 and offset == 0)
        check("load region covers file", filesz == len(data) and memsz == len(data))
        check("entry inside load region", vaddr <= entry < vaddr + filesz)
    elif fmt == "pe":
        check("DOS magic", data[:2] == b"MZ")
        peoff = struct.unpack_from("<I", data, 0x3C)[0]
        check("PE signature", data[peoff:peoff + 4] == b"PE\x00\x00")
        machine = struct.unpack_from("<H", data, peoff + 4)[0]
        check("COFF machine", machine == (0x8664 if arch == "x86_64" else 0x14C))
        check("single section", struct.unpack_from("<H", data, peoff + 6)[0] == 1)
        optional_size = struct.unpack_from("<H", data, peoff + 20)[0]
        magic = struct.unpack_from("<H", data, peoff + 24)[0]
        check("optional-header flavor", magic == (0x20B if arch == "x86_64" else 0x10B))
        entry = struct.unpack_from("<I", data, peoff + 24 + 16)[0]
        check("entry point in .text", entry == 0x1000)
        size_image, size_headers = struct.unpack_from("<II", data, peoff + 24 + 56)
        check("aligned image/header sizes", size_image == 0x2000 and size_headers == 0x200)
        section_offset = peoff + 24 + optional_size
        name, virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from(
            "<8sIIII", data, section_offset
        )
        check("RX .text section", name.rstrip(b"\x00") == b".text" and
              virtual_size > 0 and virtual_address == 0x1000)
        check("section bytes fit", raw_offset == 0x200 and raw_size == 0x200 and
              raw_offset + raw_size == len(data))
        check("exit stub present", data[raw_offset] == 0xB8 and data[raw_offset + 5] == 0xC3)
    else:
        check("Mach-O 64 magic", data[:4] == struct.pack("<I", 0xFEEDFACF))
        cputype = struct.unpack_from("<i", data, 4)[0]
        check("Mach-O arm64 CPU", cputype == 0x0100000C)
        ncmds, sizeofcmds = struct.unpack_from("<II", data, 16)
        check("three load commands", ncmds == 3)
        check("load commands fit", 32 + sizeofcmds <= len(data))
        offset = 32
        commands = []
        commands_fit = True
        for _index in range(ncmds):
            if offset + 8 > len(data):
                commands_fit = False
                break
            command, command_size = struct.unpack_from("<II", data, offset)
            if command_size < 8 or offset + command_size > 32 + sizeofcmds:
                commands_fit = False
                break
            commands.append((command, offset, command_size))
            offset += command_size
        check("load-command boundaries", commands_fit and offset == 32 + sizeofcmds)
        check("PAGEZERO, TEXT, UNIXTHREAD commands",
              [command for command, _offset, _size in commands] == [0x19, 0x19, 5])
        if len(commands) == 3:
            _command, thread_offset, thread_size = commands[2]
            flavor, count = struct.unpack_from("<II", data, thread_offset + 8)
            pc = struct.unpack_from("<Q", data, thread_offset + 16 + (32 * 8))[0]
            check("arm64 thread state", flavor == 6 and count == 68 and thread_size == 288)
            check("entry PC inside TEXT file bytes", 0x100000000 <= pc < 0x100000000 + len(data))
    return {"ok": all(item["ok"] for item in checks), "checks": checks}


def inspect_with_file(path: Path) -> dict:
    tool = shutil.which("file")
    if not tool:
        return {"available": False, "recognized": None, "output": None}
    try:
        proc = subprocess.run([tool, "-b", str(path)], capture_output=True, text=True,
                              timeout=10, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        return {"available": True, "recognized": False, "output": str(exc)}
    output = (proc.stdout or proc.stderr or "").strip()
    rejected = any(word in output.lower() for word in ("data", "corrupt", "cannot read"))
    return {"available": True, "recognized": proc.returncode == 0 and not rejected,
            "output": output[:1000]}


def _default_output(fmt: str, arch: str) -> str:
    suffix = ".exe" if fmt == "pe" else ""
    return f"tiny-{fmt}-{arch}{suffix}"


def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(prog="minimal-executable")
    parser.add_argument("format", choices=sorted(FORMAT_ARCHES))
    parser.add_argument("--arch", choices=("x86_64", "i386", "arm64"))
    parser.add_argument("--exit-code", type=int, default=0)
    parser.add_argument("--out")
    parser.add_argument("--report", choices=("text", "json"), default="text")
    args = parser.parse_args(argv[1:])

    if not 0 <= args.exit_code <= 255:
        print(json.dumps({"ok": False, "error": "--exit-code must be between 0 and 255"}))
        return 2
    arch = args.arch or ("arm64" if args.format == "macho" else "x86_64")
    try:
        data = build_artifact(args.format, arch, args.exit_code)
    except BuildError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}))
        return 2

    validation = validate_artifact(data, args.format, arch)
    if not validation["ok"]:
        print(json.dumps({"ok": False, "error": "internal structural validation failed",
                          "validation": validation}))
        return 1

    out = Path(args.out or _default_output(args.format, arch)).expanduser().resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{out.name}.", dir=str(out.parent))
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        if args.format != "pe":
            os.chmod(temporary, 0o755)
        os.replace(temporary, out)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)

    file_result = inspect_with_file(out)
    proof = ["structural"]
    if file_result["recognized"]:
        proof.append("tool-readable")
    caveats = []
    artifact_kind = "conservative-executable"
    if args.format == "macho":
        artifact_kind = "static-research-artifact"
        caveats.append(
            "Modern release macOS arm64 can reject static MH_EXECUTE before entry; "
            "use dyld plus an ad-hoc signature for a runnable modern binary."
        )
    caveats.append("Loader acceptance and native execution were not tested by this construct skill.")
    result = {
        "ok": True,
        "format": args.format,
        "arch": arch,
        "artifactKind": artifact_kind,
        "out": str(out),
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "exitCode": args.exit_code,
        "proof": proof,
        "validation": validation,
        "inspection": {"file": file_result},
        "caveats": caveats,
    }
    if args.report == "json":
        print(json.dumps(result, sort_keys=True))
    else:
        print(f"minimal-executable: {out.name} ({len(data)} bytes · {args.format}/{arch})")
        print(f"  proof: {', '.join(proof)}")
        if file_result["output"]:
            print(f"  file:  {file_result['output']}")
        for caveat in caveats:
            print(f"  note:  {caveat}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

#!/usr/bin/env python3
"""Check for an operator-supplied, architecture-matched libscylla DLL."""

from __future__ import annotations

import os
import struct
import sys
from pathlib import Path


def _candidate() -> Path | None:
    configured = os.environ.get("PYSCYLLA_DLL")
    if configured:
        path = Path(configured).expanduser()
        return path if path.is_file() else None

    suffix = "x64" if sys.maxsize > 2**32 else "x86"
    names = (f"libscylla-{suffix}.dll", "libscylla.dll")

    local_bin = Path(__file__).resolve().parent.parent / "bin"
    for name in names:
        path = local_bin / name
        if path.is_file():
            return path

    for directory in os.environ.get("PATH", "").split(os.pathsep):
        if not directory:
            continue
        for name in names:
            path = Path(directory) / name
            if path.is_file():
                return path
    return None


def _pe_machine(path: Path) -> int:
    with path.open("rb") as handle:
        if handle.read(2) != b"MZ":
            raise ValueError("not a PE file")
        handle.seek(0x3C)
        pe_offset_raw = handle.read(4)
        if len(pe_offset_raw) != 4:
            raise ValueError("truncated DOS header")
        handle.seek(struct.unpack("<I", pe_offset_raw)[0])
        if handle.read(4) != b"PE\0\0":
            raise ValueError("missing PE signature")
        machine_raw = handle.read(2)
        if len(machine_raw) != 2:
            raise ValueError("truncated PE header")
        return struct.unpack("<H", machine_raw)[0]


def main() -> int:
    if os.name != "nt":
        print("pyscylla requires Windows and an external libscylla DLL", file=sys.stderr)
        return 1

    path = _candidate()
    if path is None:
        print(
            "libscylla DLL not found; place a private copy in skills/pyscylla/bin "
            "or set PYSCYLLA_DLL to its absolute path",
            file=sys.stderr,
        )
        return 1

    try:
        machine = _pe_machine(path)
    except (OSError, ValueError) as exc:
        print(f"cannot validate {path}: {exc}", file=sys.stderr)
        return 1

    expected = 0x8664 if sys.maxsize > 2**32 else 0x014C
    if machine != expected:
        print(
            f"libscylla architecture does not match this Python "
            f"(PE machine 0x{machine:04x}, expected 0x{expected:04x})",
            file=sys.stderr,
        )
        return 1

    print(f"external libscylla DLL available: {path.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

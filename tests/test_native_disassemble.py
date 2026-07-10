from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "skills/native-disassemble/scripts/run.py"
SPEC = importlib.util.spec_from_file_location("native_disassemble", RUNNER)
assert SPEC and SPEC.loader
NATIVE_DISASSEMBLE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(NATIVE_DISASSEMBLE)


def write_elf(path: Path) -> None:
    path.write_bytes(b"\x7fELF" + b"\x00" * 60)


def write_pe(path: Path) -> None:
    image = bytearray(0x100)
    image[:2] = b"MZ"
    image[0x3C:0x40] = (0x80).to_bytes(4, "little")
    image[0x80:0x84] = b"PE\x00\x00"
    path.write_bytes(image)


def write_tool(path: Path, body: str) -> None:
    path.write_text("#!/bin/sh\n" + body, encoding="utf-8")
    path.chmod(0o755)


class NativeDisassembleTests(unittest.TestCase):
    def test_detects_elf_and_validated_pe(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            elf = root / "sample.elf"
            pe = root / "sample.exe"
            bad_mz = root / "bad.exe"
            write_elf(elf)
            write_pe(pe)
            bad_mz.write_bytes(b"MZ" + b"\x00" * 62)

            self.assertEqual(NATIVE_DISASSEMBLE.detect_format(elf), "ELF")
            self.assertEqual(NATIVE_DISASSEMBLE.detect_format(pe), "PE")
            self.assertIsNone(NATIVE_DISASSEMBLE.detect_format(bad_mz))

    def test_prefers_llvm_objdump_and_writes_atomic_listing(self) -> None:
        listing = (
            "0000000000401000 <main>:\n"
            "  401000: 55 pushq rbp\n"
            "  401001: c3 retq\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tools = root / "tools"
            tools.mkdir()
            write_tool(tools / "llvm-objdump", f"printf '{listing}'\n")
            sample = root / "sample.elf"
            outdir = root / "out"
            write_elf(sample)
            env = {**os.environ, "PATH": str(tools)}
            proc = subprocess.run(
                [sys.executable, str(RUNNER), str(sample), str(outdir), "--format", "json"],
                capture_output=True,
                text=True,
                env=env,
                check=False,
            )

            result = json.loads(proc.stdout)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertTrue(result["ok"])
            self.assertEqual(result["tool"], "llvm-objdump")
            self.assertEqual(result["format"], "ELF")
            self.assertEqual(result["functionLabels"], 1)
            self.assertEqual(result["instructionLines"], 2)
            self.assertEqual((outdir / "disassembly.txt").read_text(), listing)
            self.assertEqual(list(outdir.glob("*.part")), [])

    def test_falls_back_to_rizin_for_pe(self) -> None:
        listing = "┌ 2: sym.entry\n0x00401000  push rbp\n0x00401001  ret\n"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tools = root / "tools"
            tools.mkdir()
            write_tool(tools / "rizin", f"printf '{listing}'\n")
            sample = root / "sample.exe"
            outdir = root / "out"
            write_pe(sample)
            env = {**os.environ, "PATH": str(tools)}
            proc = subprocess.run(
                [sys.executable, str(RUNNER), str(sample), str(outdir), "--format", "json"],
                capture_output=True,
                text=True,
                env=env,
                check=False,
            )

            result = json.loads(proc.stdout)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(result["tool"], "rizin")
            self.assertEqual(result["format"], "PE")
            self.assertEqual(result["functionLabels"], 1)
            self.assertEqual(result["instructionLines"], 2)

    def test_auto_falls_through_when_objdump_cannot_decode_target(self) -> None:
        listing = "┌ 1: sym.entry\n0x00401000  ret\n"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tools = root / "tools"
            tools.mkdir()
            write_tool(tools / "llvm-objdump", "echo unsupported >&2\nexit 1\n")
            write_tool(tools / "rizin", f"printf '{listing}'\n")
            sample = root / "sample.elf"
            outdir = root / "out"
            write_elf(sample)
            env = {**os.environ, "PATH": str(tools)}
            proc = subprocess.run(
                [sys.executable, str(RUNNER), str(sample), str(outdir), "--format", "json"],
                capture_output=True,
                text=True,
                env=env,
                check=False,
            )

            result = json.loads(proc.stdout)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(result["tool"], "rizin")
            self.assertEqual(result["fallbacks"][0]["tool"], "llvm-objdump")
            self.assertEqual(result["instructionLines"], 1)

    def test_rejects_raw_or_malformed_input_before_invoking_tool(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sample = root / "raw.bin"
            sample.write_bytes(b"\x90\x90\xc3")
            proc = subprocess.run(
                [sys.executable, str(RUNNER), str(sample), str(root / "out")],
                capture_output=True,
                text=True,
                check=False,
            )

        result = json.loads(proc.stdout)
        self.assertEqual(proc.returncode, 2)
        self.assertFalse(result["ok"])
        self.assertIn("expected PE, ELF, or Mach-O", result["error"])


if __name__ == "__main__":
    unittest.main()

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
SCRIPT = ROOT / "skills/emulation-session/scripts/session.py"
SPEC = importlib.util.spec_from_file_location("rekit_emulation_session", SCRIPT)
assert SPEC and SPEC.loader
SESSION = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SESSION)

MCP_SPEC = importlib.util.spec_from_file_location("rekit_emulation_mcp", ROOT / "scripts/rekit_mcp.py")
assert MCP_SPEC and MCP_SPEC.loader
MCP = importlib.util.module_from_spec(MCP_SPEC)
MCP_SPEC.loader.exec_module(MCP)


def runtime_ready() -> bool:
    site = SCRIPT.parent / "site"
    return (site / "unicorn").exists() and (site / "capstone").exists()


QILING_ROOTFS = Path(os.environ.get("QILING_TEST_ROOTFS", ""))
QILING_BINARY = QILING_ROOTFS / "bin/x8664_hello_static"


def invoke(*args: str) -> tuple[int, dict]:
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), *args, "--format", "json"],
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.returncode, json.loads(proc.stdout)


class EmulationSessionUnitTests(unittest.TestCase):
    def test_integer_parsing_does_not_treat_decimal_as_hex(self) -> None:
        self.assertEqual(SESSION.parse_int("100"), 100)
        self.assertEqual(SESSION.parse_int("0x100"), 256)
        self.assertEqual(SESSION.parse_int("deadbeef"), 0xDEADBEEF)

    def test_permissions_and_hex_validation(self) -> None:
        self.assertEqual(SESSION.permissions("rx"), (5, "rx"))
        self.assertEqual(SESSION.parse_hex("41 42 43"), b"ABC")
        with self.assertRaises(SESSION.SessionError):
            SESSION.parse_hex("xyz")

    def test_missing_session_fails_as_structured_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            code, result = invoke(str(Path(directory) / "missing"), "info")
        self.assertEqual(code, 1)
        self.assertFalse(result["ok"])
        self.assertIn("run create first", result["error"])

    def test_rekit_mcp_exports_stateful_actions_and_reconstructs_cli_call(self) -> None:
        registry = json.loads((ROOT / "registry.json").read_text(encoding="utf-8"))
        skill = {"id": "emulation-session", **registry["emulation-session"]}
        tool = MCP.skill_to_tool(skill, "", {"ready": True}, False)
        self.assertIn("restore-snapshot", tool["inputSchema"]["properties"]["action"]["enum"])
        call = MCP.build_call_args(
            skill,
            {
                "session": ".rekit/emu/test",
                "action": "create",
                "engine": "unicorn",
                "input": "code.bin",
                "trace": True,
            },
        )
        self.assertEqual(call[:2], [".rekit/emu/test", "create"])
        self.assertIn("--engine", call)
        self.assertIn("--trace", call)
        self.assertEqual(call[-2:], ["--format", "json"])


@unittest.skipUnless(runtime_ready(), "build emulation-session runtime first")
class EmulationSessionIntegrationTests(unittest.TestCase):
    def test_unicorn_state_survives_calls_and_snapshot_restore(self) -> None:
        # mov rax, 1; add rax, 2; nop
        code_bytes = bytes.fromhex("48c7c0010000004883c00290")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            blob = root / "code.bin"
            session = root / "session"
            blob.write_bytes(code_bytes)

            status, created = invoke(
                str(session), "create", "--engine", "unicorn", "--input", str(blob),
                "--arch", "x64", "--trace",
            )
            self.assertEqual(status, 0, created)

            status, stepped = invoke(str(session), "step", "--count", "1")
            self.assertEqual(status, 0, stepped)
            self.assertEqual(stepped["instructions"], 1)

            status, registers = invoke(str(session), "read-registers", "--name", "rax,rip")
            self.assertEqual(status, 0, registers)
            self.assertEqual(registers["registers"]["rax"], "0x1")

            status, snapshot = invoke(str(session), "save-snapshot", "--label", "after-mov")
            self.assertEqual(status, 0, snapshot)
            snap_id = snapshot["snapshot"]["id"]

            status, _ = invoke(str(session), "write-register", "--name", "rax", "--value", "99")
            self.assertEqual(status, 0)
            status, restored = invoke(str(session), "restore-snapshot", "--snapshot", snap_id)
            self.assertEqual(status, 0, restored)
            status, registers = invoke(str(session), "read-registers", "--name", "rax")
            self.assertEqual(registers["registers"]["rax"], "0x1")

    def test_address_hook_persists_and_stops_execution(self) -> None:
        code_bytes = bytes.fromhex("90909090")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            blob, session = root / "code.bin", root / "session"
            blob.write_bytes(code_bytes)
            self.assertEqual(invoke(str(session), "create", "--engine", "unicorn", "--input", str(blob), "--arch", "x64")[0], 0)
            self.assertEqual(invoke(str(session), "add-hook", "--address", "0x1000002", "--stop", "--label", "third-nop")[0], 0)
            status, result = invoke(str(session), "run")
            self.assertEqual(status, 0, result)
            self.assertEqual(result["stopReason"], "breakpoint")
            self.assertEqual(result["pc"], "0x1000002")


@unittest.skipUnless(
    QILING_ROOTFS.is_dir() and QILING_BINARY.is_file(),
    "set QILING_TEST_ROOTFS to the official x8664_linux fixture",
)
class QilingSessionIntegrationTests(unittest.TestCase):
    def test_qiling_snapshot_restores_pc_across_processes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            session = Path(directory) / "session"
            status, created = invoke(
                str(session), "create", "--engine", "qiling",
                "--input", str(QILING_BINARY), "--rootfs", str(QILING_ROOTFS), "--trace",
            )
            self.assertEqual(status, 0, created)
            self.assertEqual(created["arch"], "x8664")

            status, first = invoke(str(session), "step", "--count", "3", "--timeout", "10")
            self.assertEqual(status, 0, first)
            first_pc = first["pc"]
            status, registers = invoke(str(session), "read-registers", "--name", "rip,rsp,rax")
            self.assertEqual(status, 0, registers)
            self.assertIn("rip", registers["registers"])

            status, snapshot = invoke(str(session), "save-snapshot", "--label", "after-three")
            self.assertEqual(status, 0, snapshot)
            status, second = invoke(str(session), "step", "--count", "2", "--timeout", "10")
            self.assertEqual(status, 0, second)
            self.assertNotEqual(second["pc"], first_pc)

            status, restored = invoke(
                str(session), "restore-snapshot", "--snapshot", snapshot["snapshot"]["id"]
            )
            self.assertEqual(status, 0, restored)
            status, info = invoke(str(session), "info")
            self.assertEqual(status, 0, info)
            self.assertEqual(info["pc"], first_pc)


if __name__ == "__main__":
    unittest.main()

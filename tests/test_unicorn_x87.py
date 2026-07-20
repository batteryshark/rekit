from __future__ import annotations

import importlib.util
import json
import os
import signal
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PROBE = ROOT / "scripts/unicorn_x87_probe.py"
EMULATE = ROOT / "skills/emulate-code/scripts/emulate.py"
NATIVE_SITE = EMULATE.parent / "site"
ROSETTA_SITE = EMULATE.parent / "site-x86_64"
SPEC = importlib.util.spec_from_file_location("rekit_unicorn_x87_probe", PROBE)
assert SPEC and SPEC.loader
X87 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(X87)


def runtime_ready() -> bool:
    return (NATIVE_SITE / "unicorn").is_dir()


class UnicornX87ProbeUnitTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "posix", "signal return-code semantics are POSIX-specific")
    def test_sigill_is_a_tooling_result_with_the_exact_operation(self) -> None:
        child = (
            "import json,os,signal; "
            "print(json.dumps({'event':'operation','name':'uc_mem_map(code)'}),flush=True); "
            "os.kill(os.getpid(), signal.SIGILL)"
        )
        result = X87._attempt(
            [sys.executable, "-c", child], backend="fixture-native",
            capability="execution",
        )
        self.assertFalse(result["ok"])
        self.assertEqual(result["signal"], "SIGILL")
        self.assertEqual(result["crashedOperation"], "uc_mem_map(code)")
        self.assertNotIn("mismatch", json.dumps(result).lower())

    def test_binding_free_core_reproducer_is_committed(self) -> None:
        source = (ROOT / "tests/reproducers/unicorn_x87_sigill.c").read_text(encoding="utf-8")
        self.assertIn("uc_open(UC_ARCH_X86, UC_MODE_32", source)
        self.assertIn("uc_reg_write(uc, UC_X86_REG_FPCW", source)
        self.assertIn("uc_emu_start", source)


@unittest.skipUnless(runtime_ready(), "build emulate-code runtime first")
class UnicornX87ProbeIntegrationTests(unittest.TestCase):
    def test_execution_and_register_access_are_probed_separately(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(PROBE), "--site", str(NATIVE_SITE),
             "--rosetta-site", str(ROSETTA_SITE), "--capability", "all",
             "--format", "json"],
            capture_output=True, text=True, check=False,
        )
        report = json.loads(completed.stdout)
        self.assertEqual(completed.returncode, 0, report)
        self.assertTrue(report["capabilities"]["execution"]["ok"])
        self.assertTrue(report["capabilities"]["register-access"]["ok"])
        self.assertIn(report["selectedBackend"], {"unicorn-native", "unicorn-rosetta-x86_64"})
        self.assertEqual(report["provenance"]["emulatorVersion"], "2.1.4")
        self.assertEqual(report["provenance"]["hostArchitecture"], report["environment"]["hostArchitecture"])

    def test_one_shot_x87_run_records_backend_provenance(self) -> None:
        # fld1; fstp qword ptr [0x01001000]
        code = bytes.fromhex("d9e8dd1d00100001")
        with tempfile.TemporaryDirectory() as directory:
            blob = Path(directory) / "x87.bin"
            blob.write_bytes(code)
            completed = subprocess.run(
                [sys.executable, str(EMULATE), str(blob), "--arch", "x86",
                 "--max-insn", "2", "--format", "json"],
                capture_output=True, text=True, check=False,
            )
        result = json.loads(completed.stdout)
        self.assertEqual(completed.returncode, 0, result)
        self.assertTrue(result["ok"])
        self.assertEqual(result["backend"]["emulator"], "unicorn")
        self.assertIn(result["backend"]["hostArchitecture"], {"arm64", "x86_64"})
        self.assertIn(result["backend"]["translation"], {"native", "rosetta"})
        self.assertTrue(any(write["addr"] == "0x1001000" for write in result["memWrites"]))


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import types
import unittest
from collections import Counter
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def load_script(name: str, relative_path: str):
    path = ROOT / relative_path
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


MINIMAL = load_script(
    "rekit_minimal_executable", "skills/minimal-executable/scripts/run.py"
)
PROTECTION = load_script(
    "rekit_protection_survey", "skills/protection-survey/scripts/run.py"
)
FRIDA_API = load_script(
    "rekit_frida_api_trace", "skills/frida-api-trace/scripts/run.py"
)


class MinimalExecutableTests(unittest.TestCase):
    def test_all_supported_shapes_are_deterministic_and_structurally_valid(self) -> None:
        cases = (
            ("elf", "x86_64"),
            ("elf", "i386"),
            ("pe", "x86_64"),
            ("pe", "i386"),
            ("macho", "arm64"),
        )
        for fmt, arch in cases:
            with self.subTest(format=fmt, arch=arch):
                first = MINIMAL.build_artifact(fmt, arch, 42)
                second = MINIMAL.build_artifact(fmt, arch, 42)
                self.assertEqual(first, second)
                self.assertTrue(MINIMAL.validate_artifact(first, fmt, arch)["ok"])

    def test_cli_writes_but_does_not_run_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "tiny"
            proc = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "skills/minimal-executable/scripts/run.py"),
                    "elf",
                    "--arch",
                    "x86_64",
                    "--exit-code",
                    "17",
                    "--out",
                    str(output),
                    "--report",
                    "json",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            result = json.loads(proc.stdout)

        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertTrue(result["ok"])
        self.assertEqual(result["proof"][0], "structural")
        self.assertNotIn("loader-accepted", result["proof"])
        self.assertNotIn("native-proven", result["proof"])

    def test_incompatible_format_arch_is_rejected(self) -> None:
        with self.assertRaises(MINIMAL.BuildError):
            MINIMAL.build_artifact("pe", "arm64", 0)


class ProtectionSurveyTests(unittest.TestCase):
    def test_multilanguage_indicators_emit_explainable_atoms(self) -> None:
        source = """
        if (IsDebuggerPresent()) return;
        void *p = VirtualAlloc(0, n, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        auto fn = GetProcAddress(module, name);
        __asm { nop }
        """
        findings = []
        counts = Counter()
        PROTECTION.scan_text(source, "fixture.cpp", findings, counts, 100)

        self.assertIn("PROT.ANTI_DEBUG", counts)
        self.assertIn("PROT.EXEC_MEMORY", counts)
        self.assertIn("PROT.RUNTIME_RESOLVE", counts)
        self.assertIn("PROT.INLINE_ASM", counts)
        self.assertTrue(all(item["method"] == "protection-survey" for item in findings))

    def test_rust_and_build_files_are_candidates(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "main.rs").write_text(
                '#[unsafe(link_section = ".probe")]\nstatic X: u8 = 0;\n'
                'fn f() { unsafe { core::arch::asm!("nop"); } }\n',
                encoding="utf-8",
            )
            (root / "CMakeLists.txt").write_text(
                'add_compile_options(-mllvm -fla)\n', encoding="utf-8"
            )
            paths = list(PROTECTION.iter_files(root, False, 20))
            findings = []
            counts = Counter()
            for path in paths:
                PROTECTION.scan_text(
                    path.read_text(encoding="utf-8"), path.name, findings, counts, 100
                )

        self.assertEqual({path.name for path in paths}, {"main.rs", "CMakeLists.txt"})
        self.assertIn("PROT.CUSTOM_SECTION", counts)
        self.assertIn("PROT.INLINE_ASM", counts)
        self.assertIn("PROT.BUILD_OBFUSCATION", counts)

    def test_generic_image_hash_is_not_self_integrity(self) -> None:
        findings = []
        counts = Counter()
        PROTECTION.scan_text(
            "let digest = sha256::digest(&image);", "image.rs", findings, counts, 10
        )
        self.assertNotIn("PROT.SELF_INTEGRITY", counts)


class FridaApiTraceTests(unittest.TestCase):
    def test_api_monitor_charset_expansion_and_duplicate_selection(self) -> None:
        rich = """<ApiMonitor><Module Name="Kernel32.dll">
          <Category Name="Files" />
          <Api Name="CreateFile" BothCharset="True">
            <Param Type="LPCTSTR" Name="lpFileName" />
            <Param Type="DWORD" Name="dwDesiredAccess" />
            <Return Type="HANDLE" />
          </Api>
        </Module></ApiMonitor>"""
        forwarded = """<ApiMonitor><Module Name="KernelBase.dll">
          <Api Name="CreateFileW" />
        </Module></ApiMonitor>"""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "kernel32.xml").write_text(rich, encoding="utf-8")
            # Some released definition sets contain one stray leading byte. The
            # parser accepts a tiny prefix without masking arbitrary corruption.
            (root / "kernelbase.xml").write_text("c" + forwarded, encoding="utf-8")
            signatures, warnings = FRIDA_API.load_signatures(root)
            selected, omitted = FRIDA_API.select_signatures(
                signatures, ["CreateFileW"], [], 10
            )

        self.assertEqual(warnings, [])
        self.assertEqual(omitted, 0)
        self.assertEqual(len(selected), 1)
        self.assertEqual(selected[0].module, "Kernel32.dll")
        self.assertEqual(selected[0].params[0].type, "LPCWSTR")
        self.assertEqual(selected[0].category, "Files")

    def test_generated_agent_contains_only_selected_signatures(self) -> None:
        signature = FRIDA_API.ApiSignature(
            "Kernel32.dll",
            "CreateFileW",
            (FRIDA_API.Parameter("lpFileName", "LPCWSTR"),),
            "HANDLE",
            "Files",
            "fixture.xml",
        )
        source = FRIDA_API.generate_agent([signature], 128)
        self.assertIn("CreateFileW", source)
        self.assertIn("Interceptor.attach", source)
        self.assertIn("Process.attachModuleObserver", source)
        self.assertIn("const maxString = 128", source)

    def test_direct_runner_requires_dynamic_consent(self) -> None:
        proc = subprocess.run(
            [
                sys.executable,
                str(ROOT / "skills/frida-api-trace/scripts/run.py"),
                str(ROOT / "README.md"),
                "--format",
                "json",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        result = json.loads(proc.stdout)
        self.assertEqual(proc.returncode, 4)
        self.assertFalse(result["ok"])

    def test_host_wrapper_tracks_hook_coverage_and_event_truncation(self) -> None:
        class FakeScript:
            def __init__(self):
                self.handler = None

            def on(self, event, handler):
                self.handler = handler

            def load(self):
                self.handler({"type": "send", "payload": {
                    "kind": "hook", "installed": True,
                    "module": "Kernel32.dll", "api": "CreateFileW",
                }}, None)
                for value in ("one", "two"):
                    self.handler({"type": "send", "payload": {
                        "kind": "call", "module": "Kernel32.dll",
                        "api": "CreateFileW", "args": [], "returnValue": value,
                    }}, None)

        class FakeSession:
            def __init__(self):
                self.detached = None

            def on(self, event, handler):
                self.detached = handler

            def create_script(self, source):
                return FakeScript()

            def detach(self):
                pass

        class FakeDevice:
            def __init__(self):
                self.session = FakeSession()

            def spawn(self, argv):
                return 123

            def attach(self, pid):
                return self.session

            def resume(self, pid):
                self.session.detached("process-terminated")

            def kill(self, pid):
                raise AssertionError("finished target should not be killed")

        fake_frida = types.SimpleNamespace(get_local_device=lambda: FakeDevice())
        with mock.patch.dict(sys.modules, {"frida": fake_frida}):
            hooks, events, errors, dropped = FRIDA_API.trace_target(
                ROOT / "README.md", "", "// fixture", 1, 1
            )

        self.assertEqual(len(hooks), 1)
        self.assertEqual(len(events), 1)
        self.assertEqual(dropped, 1)
        self.assertEqual(errors, [])

    def test_local_definition_corpus_is_gitignored(self) -> None:
        ignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
        self.assertIn("skills/frida-api-trace/assets/apimonitor/", ignore)


if __name__ == "__main__":
    unittest.main()

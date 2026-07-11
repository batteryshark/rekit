from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "skills/frida-android-instrument/scripts/run.py"


def load_runner():
    spec = importlib.util.spec_from_file_location("rekit_frida_android", RUNNER)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


RUN = load_runner()


class FridaAndroidInstrumentTests(unittest.TestCase):
    def test_class_agent_uses_current_synchronous_enumerator(self) -> None:
        source = RUN.build_agent("classes", match="com.example")
        self.assertIn("Java.enumerateLoadedClassesSync()", source)
        self.assertIn("com.example", source)

    def test_method_agent_uses_signature_query(self) -> None:
        source = RUN.build_agent(
            "methods", class_name="com.example.Login", match="verify*"
        )
        self.assertIn("Java.enumerateMethods", source)
        self.assertIn("com.example.Login!verify*/s", source)

    def test_hook_agent_calls_original_overload(self) -> None:
        source = RUN.build_agent(
            "hook", class_name="com.example.Login", method="verify"
        )
        self.assertIn("overload.apply(this, arguments)", source)
        self.assertIn("return result", source)

    def test_event_parser_ignores_cli_noise(self) -> None:
        events, errors = RUN._parse_events(
            "noise\n" + RUN.EVENT_PREFIX + '{"kind":"class","name":"A"}\n'
        )
        self.assertEqual(errors, [])
        self.assertEqual(events, [{"kind": "class", "name": "A"}])

    def test_direct_runner_requires_dynamic_consent(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(RUNNER), "com.example.app", "--format", "json"],
            capture_output=True,
            text=True,
            check=False,
        )
        result = json.loads(proc.stdout)
        self.assertEqual(proc.returncode, 4)
        self.assertFalse(result["ok"])


if __name__ == "__main__":
    unittest.main()

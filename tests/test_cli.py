from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REKIT = ROOT / "bin" / "rekit"
REGISTRY = ROOT / "registry.json"

MODULE_SPEC = importlib.util.spec_from_file_location(
    "rekit_cli", ROOT / "scripts" / "rekit.py"
)
assert MODULE_SPEC and MODULE_SPEC.loader
REKIT_MODULE = importlib.util.module_from_spec(MODULE_SPEC)
MODULE_SPEC.loader.exec_module(REKIT_MODULE)


def run_rekit(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [str(REKIT), *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


class RekitCliTests(unittest.TestCase):
    def test_catalog_matches_registry_and_skill_directories(self) -> None:
        registry = json.loads(REGISTRY.read_text(encoding="utf-8"))
        skill_directories = {
            path.parent.name for path in (ROOT / "skills").glob("*/SKILL.md")
        }

        listed = run_rekit("list", "--json")
        self.assertEqual(listed.returncode, 0, listed.stderr)
        listed_ids = {entry["id"] for entry in json.loads(listed.stdout)}

        self.assertEqual(set(registry), skill_directories)
        self.assertEqual(set(registry), listed_ids)

    def test_skill_frontmatter_is_synced(self) -> None:
        result = run_rekit("sync-docs", "--check")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_static_skill_runs_through_dispatcher(self) -> None:
        payload = b"REKIT\x00"
        with tempfile.TemporaryDirectory() as directory:
            sample = Path(directory) / "sample.bin"
            sample.write_bytes(payload)
            result = run_rekit("run", "hex-view", str(sample), "--format", "json")

        self.assertEqual(result.returncode, 0, result.stderr)
        output = json.loads(result.stdout)
        self.assertTrue(output["ok"])
        self.assertEqual(output["length"], len(payload))
        self.assertEqual(output["sha256"], hashlib.sha256(payload).hexdigest())

    def test_static_asset_is_resolved_from_standard_layout(self) -> None:
        result = run_rekit(
            "run", "ord-lookup", "ws2_32", "1", "--format", "json"
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        output = json.loads(result.stdout)
        self.assertEqual(output["name"], "accept")
        self.assertTrue(output["known"])

    def test_registry_script_entrypoints_exist(self) -> None:
        registry = json.loads(REGISTRY.read_text(encoding="utf-8"))
        for skill_id, skill in registry.items():
            command = skill.get("entry", {}).get("command", [])
            referenced_files = [part for part in command[1:] if "/" in part]
            for relative_path in referenced_files:
                with self.subTest(skill=skill_id, path=relative_path):
                    self.assertTrue((ROOT / "skills" / skill_id / relative_path).is_file())

        self.assertTrue(
            (ROOT / "skills" / "ord-lookup" / "assets" / "ordinals.json").is_file()
        )
        pyscylla = ROOT / "skills" / "pyscylla"
        self.assertTrue((pyscylla / "scripts" / "check-runtime.py").is_file())
        self.assertIn(
            "skills/pyscylla/bin/", (ROOT / ".gitignore").read_text(encoding="utf-8")
        )

        dex_dump = ROOT / "skills" / "dex-dump"
        self.assertTrue((dex_dump / "scripts" / "build.sh").is_file())
        self.assertTrue((dex_dump / "scripts" / "dex-dumper" / "Cargo.lock").is_file())
        self.assertFalse((dex_dump / "bin" / "panda-dex-dumper").exists())

    def test_doctor_runs_skill_local_checks_from_the_skill_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            skill_dir = Path(directory)
            scripts = skill_dir / "scripts"
            scripts.mkdir()
            (scripts / "check.py").write_text(
                "print('fixture runtime available')\n", encoding="utf-8"
            )
            skill = {
                "id": "fixture-skill",
                "_dir": skill_dir,
                "prerequisites": [
                    {"tool": "fixture runtime", "check": ["python3", "scripts/check.py"]}
                ],
            }
            report = REKIT_MODULE.doctor_skill(skill)

        self.assertTrue(report["ready"])
        self.assertTrue(report["prerequisites"][0]["present"])

    def test_doctor_reports_an_unbuilt_local_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            scripts = Path(directory) / "scripts"
            scripts.mkdir()
            (scripts / "build.sh").write_text("#!/usr/bin/env bash\n", encoding="utf-8")
            skill = {
                "id": "fixture-skill",
                "_dir": Path(directory),
                "prerequisites": [],
                "payload": {"vendored": "scripts/site"},
            }
            report = REKIT_MODULE.doctor_skill(skill)

        self.assertFalse(report["ready"])
        self.assertEqual(report["prerequisites"][0]["tool"], "local payload")
        self.assertIn(
            "bin/rekit install fixture-skill",
            report["prerequisites"][0]["install_hint"],
        )

    def test_dynamic_skill_requires_explicit_consent(self) -> None:
        result = run_rekit(
            "run", "exec-observe", sys.executable, "--format", "json"
        )

        self.assertEqual(result.returncode, 4)
        output = json.loads(result.stdout)
        self.assertFalse(output["ok"])
        self.assertEqual(output["error"], "dynamic skill requires consent")


if __name__ == "__main__":
    unittest.main()

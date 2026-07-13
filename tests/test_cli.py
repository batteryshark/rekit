from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


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
            path.parent.relative_to(ROOT / "skills").as_posix()
            for path in (ROOT / "skills").rglob("SKILL.md")
        }
        registered_directories = {
            skill.get("path", skill_id) for skill_id, skill in registry.items()
        }

        listed = run_rekit("list", "--json")
        self.assertEqual(listed.returncode, 0, listed.stderr)
        listed_ids = {entry["id"] for entry in json.loads(listed.stdout)}

        self.assertEqual(registered_directories, skill_directories)
        self.assertEqual(set(registry), listed_ids)

    def test_nested_skill_path_is_discovered_and_synced(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            skills = root / "skills"
            nested = skills / "frida" / "frida-workflow"
            nested.mkdir(parents=True)
            (nested / "SKILL.md").write_text("# Workflow\n", encoding="utf-8")
            registry_file = root / "registry.json"
            registry_file.write_text(json.dumps({
                "frida-workflow": {
                    "path": "frida/frida-workflow",
                    "description": "Plan Frida instrumentation.",
                }
            }), encoding="utf-8")

            with mock.patch.object(REKIT_MODULE, "SKILLS_DIR", skills), \
                    mock.patch.object(REKIT_MODULE, "REGISTRY_FILE", registry_file):
                found = REKIT_MODULE.discover()
                self.assertEqual(found[0]["id"], "frida-workflow")
                self.assertEqual(found[0]["_dir"], nested)
                self.assertEqual(REKIT_MODULE._registry_drift(), ([], []))
                self.assertEqual(
                    REKIT_MODULE.cmd_sync_docs(SimpleNamespace(check=False)), 0
                )

            text = (nested / "SKILL.md").read_text(encoding="utf-8")
            self.assertIn("name: frida-workflow", text)

    def test_nested_skill_path_cannot_escape_skills(self) -> None:
        directory, error = REKIT_MODULE._skill_dir(
            "frida-workflow", {"path": "../frida-workflow"}
        )
        self.assertEqual(directory, ROOT / "skills" / "frida-workflow")
        self.assertIsNotNone(error)

    def test_two_ids_cannot_claim_one_skill_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            skills = root / "skills"
            skills.mkdir()
            registry_file = root / "registry.json"
            registry_file.write_text(json.dumps({
                "one": {"path": "group/shared/one"},
                "two": {"path": "group/shared/two"},
            }), encoding="utf-8")
            # Simulate a symlink alias resolving both registry paths to one directory.
            target = skills / "actual"
            target.mkdir()
            (skills / "group" / "shared").mkdir(parents=True)
            (skills / "group" / "shared" / "one").symlink_to(target, target_is_directory=True)
            (skills / "group" / "shared" / "two").symlink_to(target, target_is_directory=True)

            with mock.patch.object(REKIT_MODULE, "SKILLS_DIR", skills), \
                    mock.patch.object(REKIT_MODULE, "REGISTRY_FILE", registry_file):
                found = REKIT_MODULE.discover()

            self.assertTrue(all("multiple registry ids" in s["_error"] for s in found))

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
            skill_dir = ROOT / "skills" / skill.get("path", skill_id)
            command = skill.get("entry", {}).get("command", [])
            referenced_files = [part for part in command[1:] if "/" in part]
            for relative_path in referenced_files:
                with self.subTest(skill=skill_id, path=relative_path):
                    self.assertTrue((skill_dir / relative_path).is_file())

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
                "safety": {"executes_input": "no", "network": "none", "tier": 0},
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
                "safety": {"executes_input": "no", "network": "none", "tier": 0},
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

    def test_all_catalog_entries_have_valid_least_authority_contracts(self) -> None:
        registry = json.loads(REGISTRY.read_text(encoding="utf-8"))
        self.assertEqual(len(registry), 45)
        for skill_id, entry in registry.items():
            with self.subTest(skill=skill_id):
                effective, error = REKIT_MODULE.effective_manifest({"id": skill_id, **entry})
                self.assertIsNone(error)
                self.assertIsNotNone(effective)
                self.assertFalse(effective["authority"]["legacy"])
                self.assertRegex(effective["digest"], r"^[0-9a-f]{64}$")
        self.assertEqual(
            registry["gitops"]["authority"],
            {"version": 1, "actions": [
                "read_local_target", "modify_target", "network_access", "destructive",
            ], "credential_use": True},
        )
        self.assertTrue(registry["ios-dump"]["authority"]["credential_use"])

    def test_authority_validation_is_fail_closed_and_legacy_is_conservative(self) -> None:
        static = {"id": "legacy", "version": "1", "safety": {
            "tier": 0, "executes_input": "no", "network": "none",
        }}
        effective, error = REKIT_MODULE.effective_manifest(static)
        self.assertIsNone(error)
        self.assertTrue(effective["authority"]["legacy"])
        self.assertEqual(effective["authority"]["actions"], ["read_local_target"])

        for unsafe in (
            {**static, "safety": {"tier": 1, "executes_input": "full", "network": "none"}},
            {**static, "safety": {"tier": 1, "executes_input": "no", "network": "optional"}},
            {**static, "authority": {"version": 1,
                "actions": ["read_local_target", "network_access"], "credential_use": False}},
        ):
            with self.subTest(skill=unsafe):
                effective, error = REKIT_MODULE.effective_manifest(unsafe)
                self.assertIsNone(effective)
                self.assertIsNotNone(error)

    def test_public_catalog_projection_has_authorities_digest_and_no_source_path(self) -> None:
        listed = run_rekit("list", "--json")
        self.assertEqual(listed.returncode, 0, listed.stderr)
        entries = json.loads(listed.stdout)
        self.assertTrue(entries)
        for entry in entries:
            self.assertNotIn("path", entry)
            self.assertNotIn("authorityError", entry)
            self.assertEqual(entry["effectiveManifest"]["toolId"], entry["id"])
            self.assertRegex(entry["effectiveManifest"]["digest"], r"^[0-9a-f]{64}$")


if __name__ == "__main__":
    unittest.main()

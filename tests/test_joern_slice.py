from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "skills" / "joern-slice" / "scripts" / "run.py"
DIGEST_REF = "ghcr.io/example/joern@sha256:" + ("2" * 64)


def fake_docker(directory: Path) -> tuple[Path, Path]:
    executable = directory / "docker"
    log = directory / "docker.log"
    executable.write_text(
        textwrap.dedent(
            f"""\
            #!{sys.executable}
            import json
            import os
            import pathlib
            import sys

            args = sys.argv[1:]
            pathlib.Path(os.environ["FAKE_DOCKER_LOG"]).open("a").write(" ".join(args) + "\\n")
            if args and args[0] == "version":
                print("29.2.1")
                raise SystemExit(0)
            if args and args[0] == "info":
                print(os.environ.get("FAKE_DOCKER_PLATFORM", "linux/arm64"))
                raise SystemExit(0)
            if args[:2] == ["image", "inspect"]:
                print("[]")
                raise SystemExit(0)

            entrypoint = args[args.index("--entrypoint") + 1] if "--entrypoint" in args else ""
            if entrypoint == "joern-parse" and "--list-languages" in args:
                print("Available languages (case insensitive):")
                for language in ("c", "javasrc", "jssrc", "pythonsrc"):
                    print("- " + language)
                raise SystemExit(0)

            output = None
            for index, arg in enumerate(args):
                if arg == "--mount" and "dst=/output" in args[index + 1]:
                    fields = dict(item.split("=", 1) for item in args[index + 1].split(",") if "=" in item)
                    output = pathlib.Path(fields["src"])
            if output is None:
                raise SystemExit("missing output mount")
            if entrypoint == "joern-parse":
                (output / "cpg.bin").write_bytes(b"fixture-cpg")
                raise SystemExit(0)
            if entrypoint != "joern-slice":
                raise SystemExit("unexpected entrypoint")
            if os.environ.get("FAKE_JOERN_BAD_SUCCESS"):
                print("Error: option parsing failed")
                raise SystemExit(0)
            if os.environ.get("FAKE_JOERN_EMPTY"):
                print("Empty slice, no file generated.")
                raise SystemExit(0)
            if "usages" in args:
                raw = {{
                    "$type": "ProgramUsageSlice",
                    "objectSlices": [{{
                        "fileName": "app.c",
                        "fullName": "launch",
                        "lineNumber": 3,
                        "columnNumber": 1,
                        "code": "",
                        "slices": [{{
                            "targetObj": json.dumps({{"name": "payload", "typeFullName": "char*", "lineNumber": 4}}),
                            "definedBy": json.dumps({{"name": "download", "typeFullName": "char*", "lineNumber": 4}}),
                            "argToCalls": [{{"callName": "system", "lineNumber": [5], "columnNumber": [3], "returnType": "ANY"}}],
                            "invokedCalls": [],
                        }}],
                    }}],
                    "userDefinedTypes": [],
                }}
            elif os.environ.get("FAKE_JOERN_NEGATIVE"):
                raw = {{
                    "$type": "DataFlowSlice",
                    "nodes": [{{"id": 1, "label": "LITERAL", "code": "fixed local", "parentFile": "app.py", "lineNumber": 3}}],
                    "edges": [],
                }}
            else:
                raw = {{
                    "$type": "DataFlowSlice",
                    "nodes": [
                        {{"id": 1, "label": "CALL", "name": "download", "code": "download(url)", "parentFile": "app.py", "parentMethod": "launch", "lineNumber": 4}},
                        {{"id": 2, "label": "IDENTIFIER", "name": "payload", "code": "payload", "parentFile": "app.py", "parentMethod": "launch", "lineNumber": 5}},
                    ],
                    "edges": [{{"src": 1, "dst": 2, "label": "REACHING_DEF"}}],
                }}
            (output / "slices.json").write_text(json.dumps(raw))
            print("Slices have been successfully generated and written to slices.json")
            raise SystemExit(0)
            """
        ),
        encoding="utf-8",
    )
    executable.chmod(0o755)
    return executable, log


class JoernSliceTests(unittest.TestCase):
    def run_slice(
        self, directory: Path, *arguments: str, env_overrides: dict[str, str] | None = None
    ) -> tuple[subprocess.CompletedProcess[str], Path]:
        _docker, log = fake_docker(directory)
        env = {
            **os.environ,
            "PATH": str(directory) + os.pathsep + os.environ.get("PATH", ""),
            "REKIT_JOERN_SLICE_IMAGE": DIGEST_REF,
            "FAKE_DOCKER_LOG": str(log),
        }
        if env_overrides:
            env.update(env_overrides)
        result = subprocess.run(
            [sys.executable, str(RUNNER), *arguments],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        return result, log

    def test_behavior_flow_publishes_normalized_evidence_in_hardened_container(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            target = directory / "source"
            output = directory / "out"
            target.mkdir()
            (target / "app.py").write_text("payload = download(url)\nexec(payload)\n")
            result, log_path = self.run_slice(
                directory, str(target), str(output), "--language", "pythonsrc", "--format", "json"
            )
            log = log_path.read_text(encoding="utf-8")
            evidence = json.loads((output / "evidence.json").read_text(encoding="utf-8"))

        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertGreater(payload["findings"], 0)
        self.assertEqual(evidence["analysis"]["proofDepth"], "interprocedural-cpg")
        self.assertEqual(evidence["graph"]["paths"][0]["relation"], "slice-selected-by-sink")
        self.assertIn("--network none", log)
        self.assertIn("--read-only", log)
        self.assertIn("--cap-drop ALL", log)
        self.assertIn("/tmp:rw,exec,nosuid,nodev,size=1g", log)
        self.assertNotIn("pull", log)

    def test_negative_control_has_no_behavior_finding(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            target = directory / "app.py"
            output = directory / "out"
            target.write_text("exec('fixed local')\n")
            result, _log = self.run_slice(
                directory,
                str(target),
                str(output),
                "--language", "pythonsrc",
                "--format", "json",
                env_overrides={"FAKE_JOERN_NEGATIVE": "1"},
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["findings"], 0)

    def test_verified_empty_slice_is_a_valid_zero_result(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            target = directory / "app.py"
            output = directory / "out"
            target.write_text("print('safe')\n")
            result, _log = self.run_slice(
                directory,
                str(target),
                str(output),
                "--language", "pythonsrc",
                "--format", "json",
                env_overrides={"FAKE_JOERN_EMPTY": "1"},
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["findings"], 0)

    def test_success_exit_without_artifact_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            target = directory / "app.py"
            output = directory / "out"
            target.write_text("exec(download(url))\n")
            result, _log = self.run_slice(
                directory,
                str(target),
                str(output),
                "--language", "pythonsrc",
                "--format", "json",
                env_overrides={"FAKE_JOERN_BAD_SUCCESS": "1"},
            )
            output_exists = output.exists()

        self.assertEqual(result.returncode, 1)
        self.assertFalse(output_exists)
        self.assertIn("did not produce slices.json", json.loads(result.stdout)["error"])

    def test_invalid_profile_is_rejected_before_docker(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            target = directory / "app.py"
            output = directory / "out"
            profile = directory / "profile.json"
            target.write_text("exec(download(url))\n")
            profile.write_text(json.dumps({
                "schemaVersion": 1,
                "id": "bad",
                "sources": [{"id": "source", "pattern": "["}],
                "sinks": [{"id": "sink", "pattern": "exec"}],
            }))
            result, log = self.run_slice(
                directory,
                str(target),
                str(output),
                "--profile", str(profile),
                "--format", "json",
            )
            log_exists = log.exists()

        self.assertEqual(result.returncode, 1)
        self.assertIn("invalid regex", json.loads(result.stdout)["error"])
        self.assertFalse(log_exists)

    def test_reused_cpg_requires_matching_evidence_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            target = directory / "app.py"
            output = directory / "out"
            cache = directory / "cache"
            cache.mkdir()
            target.write_text("exec(download(url))\n")
            (cache / "cpg.bin").write_bytes(b"fixture-cpg")
            (cache / "evidence.json").write_text(json.dumps({
                "target": {"manifestSha256": "wrong"},
                "analysis": {"language": "pythonsrc"},
                "producer": {"image": DIGEST_REF},
            }))
            result, _log = self.run_slice(
                directory,
                str(target),
                str(output),
                "--language", "pythonsrc",
                "--reuse-cpg", str(cache / "cpg.bin"),
                "--format", "json",
            )

        self.assertEqual(result.returncode, 1)
        self.assertIn("target manifest does not match", json.loads(result.stdout)["error"])

    def test_usages_mode_normalizes_program_usage_schema(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            target = directory / "app.c"
            output = directory / "out"
            target.write_text("void launch(void) {}\n")
            result, _log = self.run_slice(
                directory,
                str(target),
                str(output),
                "--language", "c",
                "--mode", "usages",
                "--format", "json",
            )
            evidence = json.loads((output / "evidence.json").read_text(encoding="utf-8"))

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(evidence["graph"]["graphType"], "ProgramUsageSlice")
        self.assertGreater(evidence["metrics"]["normalizedNodes"], 0)
        self.assertIn("ARGUMENT_TO_CALL", {edge["label"] for edge in evidence["graph"]["edges"]})

    def test_output_inside_target_is_rejected_before_docker(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            target = directory / "source"
            target.mkdir()
            (target / "app.py").write_text("print('safe')\n")
            result, log = self.run_slice(
                directory, str(target), str(target / "out"), "--format", "json"
            )

        self.assertEqual(result.returncode, 1)
        self.assertIn("must not be inside", json.loads(result.stdout)["error"])
        self.assertFalse(log.exists())


if __name__ == "__main__":
    unittest.main()

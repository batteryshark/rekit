from __future__ import annotations

import json
import importlib.util
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "skills" / "native-lift" / "scripts" / "run.py"
DIGEST_REF = "ghcr.io/example/native-lift@sha256:" + ("1" * 64)


def load_runner_module():
    sys.path.insert(0, str(RUNNER.parent))
    try:
        spec = importlib.util.spec_from_file_location("rekit_native_lift_runner", RUNNER)
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(module)
        return module
    finally:
        sys.path.pop(0)


def fake_docker(directory: Path) -> tuple[Path, Path]:
    executable = directory / "docker"
    log = directory / "docker.log"
    executable.write_text(
        textwrap.dedent(
            f"""\
            #!{sys.executable}
            import os
            import pathlib
            import sys
            import time

            args = sys.argv[1:]
            pathlib.Path(os.environ["FAKE_DOCKER_LOG"]).open("a").write(" ".join(args) + "\\n")
            if args and args[0] == "version":
                if os.environ.get("FAKE_DOCKER_DAEMON_DOWN"):
                    print("Cannot connect to the Docker daemon", file=sys.stderr)
                    raise SystemExit(1)
                print("29.2.1")
                raise SystemExit(0)
            if args and args[0] == "info":
                print(os.environ.get("FAKE_DOCKER_PLATFORM", "linux/aarch64"))
                raise SystemExit(0)
            if args[:2] == ["image", "inspect"]:
                if os.environ.get("FAKE_DOCKER_MISSING_IMAGE"):
                    print("No such image", file=sys.stderr)
                    raise SystemExit(1)
                print("[]")
                raise SystemExit(0)
            if args and args[0] == "run" and "--version" in args:
                if os.environ.get("FAKE_DOCKER_UNHEALTHY"):
                    print("runtime startup failed", file=sys.stderr)
                    raise SystemExit(9)
                print("native-lift remill=v6.0.1 commit=0e324aee llvm=21.1.0 binary=v6.0.1")
                raise SystemExit(0)
            if os.environ.get("FAKE_DOCKER_FAIL"):
                print("fixture Remill failure", file=sys.stderr)
                raise SystemExit(7)
            if os.environ.get("FAKE_DOCKER_SLEEP"):
                time.sleep(float(os.environ["FAKE_DOCKER_SLEEP"]))

            output = None
            for index, arg in enumerate(args):
                if arg == "--mount" and "dst=/output" in args[index + 1]:
                    fields = dict(item.split("=", 1) for item in args[index + 1].split(",") if "=" in item)
                    output = pathlib.Path(fields["src"])
            if output is None:
                raise SystemExit("missing output mount")
            if "--ir-out" in args:
                (output / "lifted.ll").write_text("; ModuleID = 'fixture'\\ndefine void @sub_0() {{ ret void }}\\n")
            if "--bc-out" in args:
                (output / "lifted.bc").write_bytes(b"BC\\xc0\\xdefixture")
            raise SystemExit(0)
            """
        ),
        encoding="utf-8",
    )
    executable.chmod(0o755)
    return executable, log


class NativeLiftTests(unittest.TestCase):
    def run_lift(
        self, directory: Path, *arguments: str, fail: bool = False,
        env_overrides: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        _docker, log = fake_docker(directory)
        env = {
            **os.environ,
            "PATH": str(directory) + os.pathsep + os.environ.get("PATH", ""),
            "REKIT_NATIVE_LIFT_IMAGE": DIGEST_REF,
            "FAKE_DOCKER_LOG": str(log),
        }
        if fail:
            env["FAKE_DOCKER_FAIL"] = "1"
        if env_overrides:
            env.update(env_overrides)
        return subprocess.run(
            [sys.executable, str(RUNNER), *arguments],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_lifts_ir_with_hardened_offline_container(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            sample = directory / "code.bin"
            output = directory / "out"
            sample.write_bytes(b"\x48\x89\xf8\xc3")
            result = self.run_lift(
                directory,
                str(sample), str(output),
                "--arch", "amd64",
                "--address", "0x401000",
                "--format", "json",
            )
            log = (directory / "docker.log").read_text(encoding="utf-8")

        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["entryAddress"], 0x401000)
        self.assertIn("lifted.ll", payload["artifacts"])
        self.assertIn("--network none", log)
        self.assertIn("--read-only", log)
        self.assertIn("--cap-drop ALL", log)
        self.assertIn("--pids-limit 256", log)
        self.assertNotIn("pull", log)

    def test_emits_ir_and_bitcode(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            sample = directory / "code.bin"
            output = directory / "out"
            sample.write_bytes(b"\xc3")
            result = self.run_lift(
                directory, str(sample), str(output),
                "--arch", "x86", "--emit", "both", "--format", "json",
            )
            names = sorted(path.name for path in output.iterdir())

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(names, ["lifted.bc", "lifted.ll"])

    def test_rejects_executable_container_before_docker(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            sample = directory / "sample.elf"
            sample.write_bytes(b"\x7fELF" + b"\0" * 32)
            result = self.run_lift(
                directory, str(sample), str(directory / "out"),
                "--arch", "amd64", "--format", "json",
            )
            log = (directory / "docker.log")
            log_exists = log.exists()

        self.assertEqual(result.returncode, 1)
        self.assertIn("extract one raw code region", json.loads(result.stdout)["error"])
        self.assertFalse(log_exists)

    def test_rejects_oversized_region(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            sample = directory / "code.bin"
            sample.write_bytes(b"\x90" * 65537)
            result = self.run_lift(
                directory, str(sample), str(directory / "out"),
                "--arch", "amd64", "--format", "json",
            )

        self.assertEqual(result.returncode, 1)
        self.assertIn("maximum byte region is 65536", result.stdout)

    def test_failure_does_not_publish_partial_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            sample = directory / "code.bin"
            output = directory / "out"
            sample.write_bytes(b"\xc3")
            result = self.run_lift(
                directory, str(sample), str(output),
                "--arch", "amd64", "--emit", "both", "--format", "json",
                fail=True,
            )
            output_exists = output.exists()

        self.assertEqual(result.returncode, 1)
        self.assertFalse(output_exists)
        self.assertIn("Remill exited 7", result.stdout)

    def test_publish_rolls_back_if_second_artifact_cannot_be_replaced(self) -> None:
        runner = load_runner_module()
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            stage = directory / "stage"
            output = directory / "out"
            stage.mkdir()
            (stage / "lifted.ll").write_text("new ir", encoding="utf-8")
            (stage / "lifted.bc").write_bytes(b"new bitcode")
            real_replace = os.replace

            def fail_bitcode(source, destination):
                if Path(destination).name == "lifted.bc":
                    raise OSError("fixture publish failure")
                return real_replace(source, destination)

            with mock.patch.object(runner.os, "replace", side_effect=fail_bitcode):
                with self.assertRaises(OSError):
                    runner.publish(stage, output, "both")

            names = list(output.iterdir())

        self.assertEqual(names, [])

    def test_entry_must_be_inside_region(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            sample = directory / "code.bin"
            sample.write_bytes(b"\x90\xc3")
            result = self.run_lift(
                directory, str(sample), str(directory / "out"),
                "--arch", "x86", "--address", "0x1000",
                "--entry-address", "0x2000", "--format", "json",
            )

        self.assertEqual(result.returncode, 1)
        self.assertIn("entry address must point inside", result.stdout)

    def test_timeout_does_not_publish_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            _docker, log = fake_docker(directory)
            sample = directory / "code.bin"
            output = directory / "out"
            sample.write_bytes(b"\xc3")
            env = {
                **os.environ,
                "PATH": str(directory) + os.pathsep + os.environ.get("PATH", ""),
                "REKIT_NATIVE_LIFT_IMAGE": DIGEST_REF,
                "FAKE_DOCKER_LOG": str(log),
                "FAKE_DOCKER_SLEEP": "2",
            }
            result = subprocess.run(
                [
                    sys.executable, str(RUNNER), str(sample), str(output),
                    "--arch", "amd64", "--timeout", "1", "--format", "json",
                ],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            output_exists = output.exists()

        self.assertEqual(result.returncode, 1)
        self.assertIn("lifting timed out after 1 seconds", result.stdout)
        self.assertFalse(output_exists)

    def test_mutable_image_override_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            _docker, log = fake_docker(directory)
            sample = directory / "code.bin"
            sample.write_bytes(b"\xc3")
            env = {
                **os.environ,
                "PATH": str(directory) + os.pathsep + os.environ.get("PATH", ""),
                "REKIT_NATIVE_LIFT_IMAGE": "ghcr.io/example/native-lift:latest",
                "FAKE_DOCKER_LOG": str(log),
            }
            result = subprocess.run(
                [
                    sys.executable, str(RUNNER), str(sample), str(directory / "out"),
                    "--arch", "amd64", "--format", "json",
                ],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            log_exists = log.exists()

        self.assertEqual(result.returncode, 1)
        self.assertIn("must be an immutable", result.stdout)
        self.assertFalse(log_exists)

    def test_unsupported_docker_platform_is_reported_before_image_use(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            _docker, log = fake_docker(directory)
            sample = directory / "code.bin"
            sample.write_bytes(b"\xc3")
            env = {
                **os.environ,
                "PATH": str(directory) + os.pathsep + os.environ.get("PATH", ""),
                "REKIT_NATIVE_LIFT_IMAGE": DIGEST_REF,
                "FAKE_DOCKER_LOG": str(log),
                "FAKE_DOCKER_PLATFORM": "linux/s390x",
            }
            result = subprocess.run(
                [
                    sys.executable, str(RUNNER), str(sample), str(directory / "out"),
                    "--arch", "amd64", "--format", "json",
                ],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            log_text = log.read_text(encoding="utf-8")

        self.assertEqual(result.returncode, 1)
        self.assertIn("unsupported Docker platform linux/s390x", result.stdout)
        self.assertNotIn("image inspect", log_text)

    def test_missing_docker_is_distinct(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            sample = directory / "code.bin"
            sample.write_bytes(b"\xc3")
            result = subprocess.run(
                [
                    sys.executable, str(RUNNER), str(sample), str(directory / "out"),
                    "--arch", "amd64", "--format", "json",
                ],
                cwd=ROOT,
                env={
                    **os.environ,
                    "PATH": str(directory),
                    "REKIT_NATIVE_LIFT_IMAGE": DIGEST_REF,
                },
                capture_output=True,
                text=True,
                check=False,
            )

        self.assertEqual(result.returncode, 1)
        self.assertIn("Docker is not installed or is not on PATH", result.stdout)

    def test_unavailable_daemon_is_distinct(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            sample = directory / "code.bin"
            sample.write_bytes(b"\xc3")
            result = self.run_lift(
                directory, str(sample), str(directory / "out"),
                "--arch", "amd64", "--format", "json",
                env_overrides={"FAKE_DOCKER_DAEMON_DOWN": "1"},
            )

        self.assertEqual(result.returncode, 1)
        self.assertIn("Cannot connect to the Docker daemon", result.stdout)

    def test_missing_immutable_image_is_distinct(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            sample = directory / "code.bin"
            sample.write_bytes(b"\xc3")
            result = self.run_lift(
                directory, str(sample), str(directory / "out"),
                "--arch", "amd64", "--format", "json",
                env_overrides={"FAKE_DOCKER_MISSING_IMAGE": "1"},
            )

        self.assertEqual(result.returncode, 1)
        self.assertIn("immutable image is missing", result.stdout)
        self.assertIn("install native-lift", result.stdout)

    def test_unhealthy_runtime_is_distinct(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            sample = directory / "code.bin"
            sample.write_bytes(b"\xc3")
            result = self.run_lift(
                directory, str(sample), str(directory / "out"),
                "--arch", "amd64", "--format", "json",
                env_overrides={"FAKE_DOCKER_UNHEALTHY": "1"},
            )

        self.assertEqual(result.returncode, 1)
        self.assertIn("image health check failed", result.stdout)
        self.assertIn("runtime startup failed", result.stdout)

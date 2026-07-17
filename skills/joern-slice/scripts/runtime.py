from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
IMAGE_FILE = SCRIPT_DIR / "image.json"
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class RuntimeUnavailable(RuntimeError):
    pass


def metadata() -> dict:
    data = json.loads(IMAGE_FILE.read_text(encoding="utf-8"))
    if data.get("schemaVersion") != 1:
        raise RuntimeUnavailable("unsupported joern-slice image metadata")
    return data


def image_ref() -> str:
    override = os.environ.get("REKIT_JOERN_SLICE_IMAGE")
    if override:
        if "@" not in override or not _DIGEST_RE.fullmatch(override.rsplit("@", 1)[1]):
            raise RuntimeUnavailable(
                "REKIT_JOERN_SLICE_IMAGE must be an immutable name@sha256:digest reference"
            )
        return override
    data = metadata()
    digest = data.get("digest")
    if not isinstance(digest, str) or not _DIGEST_RE.fullmatch(digest):
        raise RuntimeUnavailable("joern-slice image metadata has no immutable digest")
    return f"{data['repository']}@{digest}"


def run_checked(argv: list[str], timeout: int = 30) -> subprocess.CompletedProcess[str]:
    try:
        proc = subprocess.run(
            argv, capture_output=True, text=True, timeout=timeout, check=False
        )
    except FileNotFoundError as exc:
        raise RuntimeUnavailable("Docker is not installed or is not on PATH") from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeUnavailable(f"runtime check timed out after {timeout}s") from exc
    except OSError as exc:
        raise RuntimeUnavailable(f"could not start Docker: {exc}") from exc
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "unknown Docker error").strip()
        raise RuntimeUnavailable(detail)
    return proc


def container_base(ref: str) -> list[str]:
    return [
        "docker", "run", "--rm",
        "--network", "none",
        "--read-only",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--pids-limit", "512",
        "--memory", "6g",
        "--cpus", "4",
        # Joern's trusted zstd JNI library must be executable after extraction.
        "--tmpfs", "/tmp:rw,exec,nosuid,nodev,size=1g",
        ref,
    ]


def verify_runtime(*, healthcheck: bool = True) -> tuple[str, str | None]:
    ref = image_ref()
    data = metadata()
    server = run_checked(
        ["docker", "version", "--format", "{{.Server.Version}}"], timeout=15
    ).stdout.strip()
    if not server:
        raise RuntimeUnavailable("Docker daemon is not available")
    platform = run_checked(
        ["docker", "info", "--format", "{{.OSType}}/{{.Architecture}}"], timeout=15
    ).stdout.strip()
    os_name, separator, architecture = platform.partition("/")
    aliases = {"aarch64": "arm64", "x86_64": "amd64"}
    normalized = f"{os_name}/{aliases.get(architecture, architecture)}" if separator else platform
    if normalized not in data.get("platforms", []):
        raise RuntimeUnavailable(
            f"unsupported Docker platform {platform or 'unknown'}; "
            f"expected one of {', '.join(data.get('platforms', []))}"
        )
    try:
        run_checked(["docker", "image", "inspect", ref], timeout=15)
    except RuntimeUnavailable as exc:
        raise RuntimeUnavailable(
            f"immutable image is missing: {ref}; run `bin/rekit install joern-slice` ({exc})"
        ) from exc
    identity = None
    if healthcheck:
        command = container_base(ref)
        command[-1:-1] = ["--entrypoint", "joern-parse"]
        command.append("--list-languages")
        try:
            output = run_checked(command, timeout=60).stdout.strip()
        except RuntimeUnavailable as exc:
            raise RuntimeUnavailable(f"Joern image health check failed: {exc}") from exc
        expected = {"c", "javasrc", "jssrc", "pythonsrc"}
        present = set(re.findall(r"(?m)^- ([a-z0-9_]+)$", output))
        if not expected.issubset(present):
            raise RuntimeUnavailable(f"unexpected Joern frontend list: {output}")
        identity = f"joern={data['joernVersion']} revision={data['revision']}"
    return ref, identity

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
        raise RuntimeUnavailable("unsupported native-lift image metadata")
    return data


def image_ref() -> str:
    override = os.environ.get("REKIT_NATIVE_LIFT_IMAGE")
    if override:
        if "@" not in override or not _DIGEST_RE.fullmatch(override.rsplit("@", 1)[1]):
            raise RuntimeUnavailable(
                "REKIT_NATIVE_LIFT_IMAGE must be an immutable name@sha256:digest reference"
            )
        return override

    data = metadata()
    digest = data.get("digest")
    if not isinstance(digest, str) or not _DIGEST_RE.fullmatch(digest):
        raise RuntimeUnavailable(
            "the native-lift runtime has not been published; image.json has no immutable digest"
        )
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
            f"immutable image is missing: {ref}; run `bin/rekit install native-lift` ({exc})"
        ) from exc
    version = None
    if healthcheck:
        try:
            version = run_checked(
                [
                    "docker", "run", "--rm", "--network", "none", "--read-only",
                    "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                    ref, "--version",
                ],
                timeout=30,
            ).stdout.strip()
        except RuntimeUnavailable as exc:
            raise RuntimeUnavailable(f"native-lift image health check failed: {exc}") from exc
        if (
            "remill=v6.0.1" not in version
            or "llvm=21" not in version
            or "binary=" not in version
        ):
            raise RuntimeUnavailable(f"unexpected native-lift runtime identity: {version}")
    return ref, version

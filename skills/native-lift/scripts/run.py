#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from runtime import RuntimeUnavailable, metadata, verify_runtime


ARCHES = ("x86", "amd64", "aarch64")
OSES = ("linux", "macos", "windows", "solaris")
EMITS = ("ir", "bitcode", "both")
FORMATS = ("text", "json")
CONTAINER_MAGIC = (
    (b"MZ", "PE"),
    (b"\x7fELF", "ELF"),
    (b"\xfe\xed\xfa\xce", "Mach-O"),
    (b"\xce\xfa\xed\xfe", "Mach-O"),
    (b"\xfe\xed\xfa\xcf", "Mach-O"),
    (b"\xcf\xfa\xed\xfe", "Mach-O"),
    (b"\xca\xfe\xba\xbe", "fat Mach-O"),
    (b"\xbe\xba\xfe\xca", "fat Mach-O"),
)


class LiftError(RuntimeError):
    pass


def integer(value: str) -> int:
    try:
        parsed = int(value, 0)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid integer: {value}") from exc
    if parsed < 0 or parsed > 0xFFFFFFFFFFFFFFFF:
        raise argparse.ArgumentTypeError("address must fit in an unsigned 64-bit integer")
    return parsed


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Lift a bounded raw machine-code region to LLVM IR with Remill"
    )
    p.add_argument("input", type=Path, help="raw machine-code byte file")
    p.add_argument("outdir", type=Path, help="output directory")
    p.add_argument("--arch", required=True, choices=ARCHES)
    p.add_argument("--os", default="linux", choices=OSES)
    p.add_argument("--address", type=integer, default=0)
    p.add_argument("--entry-address", type=integer)
    p.add_argument("--emit", default="ir", choices=EMITS)
    p.add_argument("--timeout", type=int, default=300)
    p.add_argument("--format", default="text", choices=FORMATS)
    return p


def validate(args: argparse.Namespace) -> tuple[Path, bytes, int]:
    source = args.input.expanduser().resolve()
    if not source.is_file():
        raise LiftError(f"input is not a regular file: {source}")
    data = source.read_bytes()
    limit = int(metadata()["maxInputBytes"])
    if not data:
        raise LiftError("input is empty")
    if len(data) > limit:
        raise LiftError(f"input is {len(data)} bytes; maximum byte region is {limit}")
    for magic, name in CONTAINER_MAGIC:
        if data.startswith(magic):
            raise LiftError(
                f"input looks like a {name} container; extract one raw code region first"
            )
    if not 1 <= args.timeout <= 3600:
        raise LiftError("timeout must be between 1 and 3600 seconds")
    address_limit = 0xFFFFFFFF if args.arch == "x86" else 0xFFFFFFFFFFFFFFFF
    if args.address > address_limit:
        raise LiftError(f"address does not fit the {args.arch} address space")
    end = args.address + len(data)
    if end - 1 > address_limit:
        raise LiftError("input region overflows the target address space")
    entry = args.address if args.entry_address is None else args.entry_address
    if entry < args.address or entry >= end:
        raise LiftError("entry address must point inside the supplied byte region")
    return source, data, entry


def docker_command(
    ref: str, stage: Path, args: argparse.Namespace, entry: int
) -> list[str]:
    command = [
        "docker", "run", "--rm",
        "--network", "none",
        "--read-only",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--pids-limit", "256",
        "--memory", "2g",
        "--cpus", "2",
        "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=64m",
        "--mount", f"type=bind,src={stage / 'input'},dst=/input,readonly",
        "--mount", f"type=bind,src={stage / 'output'},dst=/output",
        ref,
        "--input", "/input/code.bin",
        "--arch", args.arch,
        "--os", args.os,
        "--address", str(args.address),
        "--entry-address", str(entry),
    ]
    if args.emit in ("ir", "both"):
        command.extend(["--ir-out", "/output/lifted.ll"])
    if args.emit in ("bitcode", "both"):
        command.extend(["--bc-out", "/output/lifted.bc"])
    return command


def publish(stage_output: Path, outdir: Path, emit: str) -> dict[str, str]:
    expected = []
    if emit in ("ir", "both"):
        expected.append("lifted.ll")
    if emit in ("bitcode", "both"):
        expected.append("lifted.bc")
    for name in expected:
        artifact = stage_output / name
        if not artifact.is_file() or artifact.stat().st_size == 0:
            raise LiftError(f"runtime did not produce {name}")

    outdir = outdir.expanduser().resolve()
    outdir.mkdir(parents=True, exist_ok=True)
    transaction = tempfile.mkdtemp(prefix=".native-lift-publish-", dir=outdir)
    transaction_dir = Path(transaction)
    staged = {}
    backups = {}
    replaced = []
    try:
        for name in expected:
            temporary = transaction_dir / name
            shutil.copyfile(stage_output / name, temporary)
            staged[name] = temporary

        for name in expected:
            destination = outdir / name
            if destination.exists():
                backup = transaction_dir / f"{name}.previous"
                os.replace(destination, backup)
                backups[name] = backup
            os.replace(staged[name], destination)
            replaced.append(name)
    except OSError:
        for name in reversed(replaced):
            (outdir / name).unlink(missing_ok=True)
        for name, backup in backups.items():
            if backup.exists():
                os.replace(backup, outdir / name)
        raise
    finally:
        shutil.rmtree(transaction_dir, ignore_errors=True)

    return {name: str(outdir / name) for name in expected}


def lift(args: argparse.Namespace) -> dict:
    source, data, entry = validate(args)
    try:
        ref, runtime_version = verify_runtime()
    except RuntimeUnavailable as exc:
        raise LiftError(str(exc)) from exc

    with tempfile.TemporaryDirectory(prefix="rekit-native-lift-") as directory:
        stage = Path(directory)
        stage_input = stage / "input"
        stage_output = stage / "output"
        stage_input.mkdir(mode=0o755)
        stage_output.mkdir(mode=0o777)
        stage_output.chmod(0o777)
        staged_sample = stage_input / "code.bin"
        staged_sample.write_bytes(data)
        staged_sample.chmod(0o444)
        command = docker_command(ref, stage, args, entry)
        try:
            proc = subprocess.run(
                command, capture_output=True, text=True, timeout=args.timeout, check=False
            )
        except subprocess.TimeoutExpired as exc:
            raise LiftError(f"lifting timed out after {args.timeout} seconds") from exc
        except OSError as exc:
            raise LiftError(f"could not start Docker: {exc}") from exc
        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout or "Remill failed").strip()
            raise LiftError(f"Remill exited {proc.returncode}: {detail}")
        artifacts = publish(stage_output, args.outdir, args.emit)

    return {
        "ok": True,
        "tool": "native-lift",
        "input": str(source),
        "inputBytes": len(data),
        "inputSha256": hashlib.sha256(data).hexdigest(),
        "arch": args.arch,
        "os": args.os,
        "address": args.address,
        "entryAddress": entry,
        "emit": args.emit,
        "image": ref,
        "runtime": runtime_version,
        "artifacts": artifacts,
    }


def emit_result(result: dict, output_format: str) -> None:
    if output_format == "json":
        print(json.dumps(result, sort_keys=True))
        return
    if result.get("ok"):
        print(
            f"native-lift: {result['inputBytes']} bytes, {result['arch']}, "
            f"entry=0x{result['entryAddress']:x}"
        )
        for name, path in result["artifacts"].items():
            print(f"  {name}: {path}")
    else:
        print(f"native-lift: {result['error']}", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        result = lift(args)
    except (LiftError, RuntimeUnavailable, ValueError, OSError, json.JSONDecodeError) as exc:
        emit_result({"ok": False, "tool": "native-lift", "error": str(exc)}, args.format)
        return 1
    emit_result(result, args.format)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

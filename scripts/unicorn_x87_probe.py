#!/usr/bin/env python3
"""Crash-isolated Unicorn x86/x87 capability probe and backend selector.

Each capability runs in a child process because a host SIGILL cannot be caught as a
Python exception.  The supervisor turns signals into structured tooling results and,
on Apple Silicon, can retry with an x86_64 Unicorn runtime under Rosetta.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import signal
import subprocess
import sys
from pathlib import Path
from typing import Any


CAPABILITIES = ("execution", "register-access")
PROBE_ADDRESS = 0x01000000
DATA_ADDRESS = 0x01001000
X87_CONTROL_WORD = 0x037F


class CapabilityError(RuntimeError):
    """The requested Unicorn backend is unavailable or unsafe."""


def _emit(event: str, **fields: Any) -> None:
    print(json.dumps({"event": event, **fields}, sort_keys=True), flush=True)


def _library_provenance(unicorn: Any, backend: str) -> dict[str, Any]:
    package = Path(unicorn.__file__).resolve().parent
    names = ("libunicorn.2.dylib", "libunicorn.so.2", "unicorn.dll")
    library = next((package / "lib" / name for name in names if (package / "lib" / name).is_file()), None)
    digest = hashlib.sha256(library.read_bytes()).hexdigest() if library else None
    host_arch = os.environ.get("REKIT_HOST_ARCH") or platform.machine()
    process_arch = platform.machine()
    return {
        "emulator": "unicorn",
        "emulatorVersion": unicorn.__version__,
        "backend": backend,
        "hostArchitecture": host_arch,
        "processArchitecture": process_arch,
        "translation": "rosetta" if backend == "unicorn-rosetta-x86_64" else "native",
        "libraryPath": str(library) if library else None,
        "librarySha256": digest,
    }


def _worker(site: Path, capability: str, backend: str) -> int:
    sys.path.insert(0, str(site))
    _emit("operation", name="import_unicorn")
    import unicorn
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_32
    from unicorn.x86_const import (
        UC_X86_REG_FP0,
        UC_X86_REG_FPCW,
        UC_X86_REG_FPSW,
        UC_X86_REG_FPTAG,
    )

    provenance = _library_provenance(unicorn, backend)
    _emit("operation", name="uc_open(x86,32)")
    uc = Uc(UC_ARCH_X86, UC_MODE_32)

    if capability == "execution":
        # fld1; fstp qword ptr [DATA_ADDRESS]. This verifies an x87 instruction and
        # its exact guest-memory result without substituting host FP arithmetic.
        code = b"\xd9\xe8\xdd\x1d" + DATA_ADDRESS.to_bytes(4, "little")
        _emit("operation", name="uc_mem_map(code)")
        uc.mem_map(PROBE_ADDRESS, 0x1000)
        _emit("operation", name="uc_mem_write(code)")
        uc.mem_write(PROBE_ADDRESS, code)
        _emit("operation", name="uc_mem_map(data)")
        uc.mem_map(DATA_ADDRESS, 0x1000)
        _emit("operation", name="uc_reg_write(FPCW)")
        uc.reg_write(UC_X86_REG_FPCW, X87_CONTROL_WORD)
        _emit("operation", name="uc_emu_start(x87)")
        uc.emu_start(PROBE_ADDRESS, PROBE_ADDRESS + len(code), count=2)
        _emit("operation", name="uc_mem_read(x87-result)")
        actual = bytes(uc.mem_read(DATA_ADDRESS, 8))
        expected = bytes.fromhex("000000000000f03f")
        if actual != expected:
            raise CapabilityError(f"x87 result {actual.hex()} != {expected.hex()}")
        detail = {"instructionBytes": code.hex(), "resultBytes": actual.hex()}
    elif capability == "register-access":
        fp_one = (0x8000000000000000, 0x3FFF)
        operations = (
            ("uc_reg_write(FPCW)", lambda: uc.reg_write(UC_X86_REG_FPCW, X87_CONTROL_WORD)),
            ("uc_reg_read(FPCW)", lambda: uc.reg_read(UC_X86_REG_FPCW)),
            ("uc_reg_write(FPSW)", lambda: uc.reg_write(UC_X86_REG_FPSW, 0)),
            ("uc_reg_read(FPSW)", lambda: uc.reg_read(UC_X86_REG_FPSW)),
            ("uc_reg_write(FPTAG)", lambda: uc.reg_write(UC_X86_REG_FPTAG, 0xFFFF)),
            ("uc_reg_read(FPTAG)", lambda: uc.reg_read(UC_X86_REG_FPTAG)),
            ("uc_reg_write(FP0)", lambda: uc.reg_write(UC_X86_REG_FP0, fp_one)),
            ("uc_reg_read(FP0)", lambda: uc.reg_read(UC_X86_REG_FP0)),
        )
        values: dict[str, Any] = {}
        for name, operation in operations:
            _emit("operation", name=name)
            value = operation()
            if value is not None:
                values[name] = value
        if values["uc_reg_read(FPCW)"] != X87_CONTROL_WORD:
            raise CapabilityError("FPCW did not round-trip")
        if tuple(values["uc_reg_read(FP0)"]) != fp_one:
            raise CapabilityError("FP0 80-bit value did not round-trip")
        detail = {"controlWord": X87_CONTROL_WORD, "fp0": list(fp_one)}
    else:  # pragma: no cover - argparse and supervisor constrain this
        raise CapabilityError(f"unknown capability: {capability}")

    _emit("result", ok=True, capability=capability, provenance=provenance, detail=detail)
    return 0


def _parse_events(stdout: str) -> list[dict[str, Any]]:
    events = []
    for line in stdout.splitlines():
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            events.append(value)
    return events


def _attempt(command: list[str], *, backend: str, capability: str, timeout: int = 15) -> dict[str, Any]:
    environment = os.environ.copy()
    environment.setdefault("REKIT_HOST_ARCH", platform.machine())
    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=timeout,
                                   check=False, env=environment)
    except (OSError, subprocess.SubprocessError) as exc:
        return {"backend": backend, "capability": capability, "ok": False,
                "errorType": "launch-error", "error": str(exc)}
    events = _parse_events(completed.stdout)
    last_operation = next((event.get("name") for event in reversed(events)
                           if event.get("event") == "operation"), None)
    result = next((event for event in reversed(events) if event.get("event") == "result"), None)
    signal_number = -completed.returncode if completed.returncode < 0 else None
    signal_name = None
    if signal_number:
        try:
            signal_name = signal.Signals(signal_number).name
        except ValueError:
            signal_name = f"signal-{signal_number}"
    record = {
        "backend": backend,
        "capability": capability,
        "ok": completed.returncode == 0 and bool(result and result.get("ok")),
        "exitCode": completed.returncode if completed.returncode >= 0 else None,
        "signal": signal_name,
        "crashedOperation": last_operation if signal_number else None,
    }
    if result:
        record["provenance"] = result.get("provenance")
        record["detail"] = result.get("detail")
    if completed.stderr.strip():
        record["stderr"] = completed.stderr.strip()[-1000:]
    return record


def _worker_command(python: list[str], script: Path, site: Path, capability: str,
                    backend: str) -> list[str]:
    return [*python, str(script), "--worker", "--site", str(site),
            "--capability", capability, "--backend", backend]


def probe(native_site: Path, rosetta_site: Path | None, capability: str) -> dict[str, Any]:
    script = Path(__file__).resolve()
    requested = list(CAPABILITIES) if capability == "all" else [capability]
    backends: list[tuple[str, list[str], Path]] = [
        ("unicorn-native", [sys.executable], native_site),
    ]
    if platform.system() == "Darwin" and platform.machine() == "arm64" and rosetta_site:
        backends.append(("unicorn-rosetta-x86_64", ["/usr/bin/arch", "-x86_64", "/usr/bin/python3"], rosetta_site))

    attempts = []
    selected = None
    selected_records: list[dict[str, Any]] = []
    for backend, python, site in backends:
        if not site.is_dir():
            attempts.append({"backend": backend, "ok": False, "errorType": "runtime-missing",
                             "error": f"runtime directory missing: {site}"})
            continue
        records = [
            _attempt(_worker_command(python, script, site, item, backend),
                     backend=backend, capability=item)
            for item in requested
        ]
        attempts.extend(records)
        if all(record["ok"] for record in records):
            selected = backend
            selected_records = records
            break

    capabilities = {
        item: next((record for record in selected_records if record["capability"] == item),
                   next((record for record in reversed(attempts) if record.get("capability") == item), None))
        for item in requested
    }
    provenance = next((record.get("provenance") for record in selected_records
                       if record.get("provenance")), None)
    return {
        "ok": selected is not None,
        "errorType": None if selected else "tooling-capability",
        "error": None if selected else "no Unicorn backend passed the requested x87 capability probe",
        "requestedCapability": capability,
        "selectedBackend": selected,
        "capabilities": capabilities,
        "attempts": attempts,
        "provenance": provenance,
        "environment": {
            "os": platform.system(),
            "osRelease": platform.release(),
            "macOSVersion": platform.mac_ver()[0] or None,
            "hostArchitecture": platform.machine(),
            "pythonVersion": platform.python_version(),
        },
    }


def ensure_backend(native_site: Path, rosetta_site: Path | None, argv: list[str]) -> dict[str, Any]:
    """Return proven native provenance or re-exec argv under a proven Rosetta lane."""
    existing = os.environ.get("REKIT_UNICORN_BACKEND")
    if existing:
        return json.loads(os.environ["REKIT_UNICORN_PROVENANCE"])
    report = probe(native_site, rosetta_site, "all")
    if not report["ok"]:
        raise CapabilityError(json.dumps(report, sort_keys=True))
    provenance = report["provenance"] or {"backend": report["selectedBackend"]}
    if report["selectedBackend"] == "unicorn-native":
        os.environ["REKIT_UNICORN_BACKEND"] = "unicorn-native"
        os.environ["REKIT_UNICORN_PROVENANCE"] = json.dumps(provenance, sort_keys=True)
        return provenance

    if not rosetta_site:
        raise CapabilityError("Rosetta backend selected without a runtime path")
    environment = os.environ.copy()
    environment.update({
        "REKIT_HOST_ARCH": platform.machine(),
        "REKIT_UNICORN_BACKEND": "unicorn-rosetta-x86_64",
        "REKIT_UNICORN_SITE": str(rosetta_site),
        "REKIT_UNICORN_PROVENANCE": json.dumps(provenance, sort_keys=True),
    })
    os.execve("/usr/bin/arch", ["/usr/bin/arch", "-x86_64", "/usr/bin/python3", *argv], environment)
    raise AssertionError("os.execve returned")  # pragma: no cover


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--site", required=True, type=Path)
    parser.add_argument("--rosetta-site", type=Path)
    parser.add_argument("--capability", choices=(*CAPABILITIES, "all"), default="all")
    parser.add_argument("--backend", default="unicorn-native")
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--format", choices=("json", "text"), default="json")
    args = parser.parse_args(argv[1:])
    if args.worker:
        try:
            return _worker(args.site.resolve(), args.capability, args.backend)
        except Exception as exc:
            _emit("result", ok=False, capability=args.capability,
                  error=f"{type(exc).__name__}: {exc}")
            return 1

    report = probe(args.site.resolve(), args.rosetta_site.resolve() if args.rosetta_site else None,
                   args.capability)
    if args.format == "json":
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(f"Unicorn x87 {args.capability}: {'available' if report['ok'] else 'unavailable'}")
        print(f"  selected backend: {report['selectedBackend'] or 'none'}")
        for attempt in report["attempts"]:
            state = "ok" if attempt.get("ok") else attempt.get("signal") or attempt.get("errorType") or "failed"
            operation = f" at {attempt['crashedOperation']}" if attempt.get("crashedOperation") else ""
            print(f"  {attempt['backend']} {attempt.get('capability', '')}: {state}{operation}")
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

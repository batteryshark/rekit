#!/usr/bin/env python3
"""Static PE/ELF/Mach-O disassembly with objdump or Rizin/radare2.

The complete listing is streamed to ``outdir/disassembly.txt`` so large binaries do
not have to fit in memory. The runner never executes or emulates the target.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path


_MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce",
    b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf",
    b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe",
    b"\xbe\xba\xfe\xca",
    b"\xca\xfe\xba\xbf",
    b"\xbf\xba\xfe\xca",
}
_OBJDUMP_TOOLS = {"llvm-objdump", "objdump"}
_RIZIN_TOOLS = {"rizin", "r2"}
_AUTO_ORDER = ("llvm-objdump", "objdump", "rizin", "r2")

_FUNCTION_RE = re.compile(r"^\s*[0-9a-fA-F]+\s+<[^>]+>:\s*$")
_OBJDUMP_INSN_RE = re.compile(r"^\s*[0-9a-fA-F]+:\s+\S")
_RIZIN_INSN_RE = re.compile(r"(?:^|\s)0x[0-9a-fA-F]{4,}\s+")
_RIZIN_FUNCTION_RE = re.compile(r"^\s*[┌╭]\s*\d+:\s+")


def emit_json(value: dict) -> None:
    sys.stdout.write(json.dumps(value) + "\n")


def detect_format(path: Path) -> str | None:
    """Return ELF, PE, Mach-O, or None after validating the container magic."""
    try:
        size = path.stat().st_size
        with path.open("rb") as stream:
            head = stream.read(64)
            if head.startswith(b"\x7fELF"):
                return "ELF"
            if head[:4] in _MACHO_MAGICS:
                return "Mach-O"
            if head.startswith(b"MZ") and len(head) >= 64:
                pe_offset = struct.unpack_from("<I", head, 0x3C)[0]
                if pe_offset <= size - 4:
                    stream.seek(pe_offset)
                    if stream.read(4) == b"PE\x00\x00":
                        return "PE"
    except (OSError, struct.error):
        return None
    return None


def available_tools(requested: str) -> list[tuple[str, str]]:
    names = _AUTO_ORDER if requested == "auto" else (requested,)
    available = []
    for name in names:
        found = shutil.which(name)
        if found:
            available.append((found, name))
    return available


def select_tool(requested: str) -> tuple[str | None, str | None]:
    """Return the preferred available tool; retained as a small public helper."""
    available = available_tools(requested)
    return available[0] if available else (None, None)


def command_for(tool_path: str, tool_name: str, input_path: Path) -> list[str]:
    if tool_name in _OBJDUMP_TOOLS:
        return [tool_path, "-d", "-C", str(input_path)]
    if tool_name in _RIZIN_TOOLS:
        return [
            tool_path,
            "-q",
            "-e",
            "scr.color=0",
            "-c",
            "aaa; pdf @@F",
            str(input_path),
        ]
    raise ValueError(f"unsupported disassembler: {tool_name}")


def summarize_listing(path: Path, tool_name: str) -> tuple[int, int]:
    functions = 0
    instructions = 0
    with path.open("r", encoding="utf-8", errors="replace") as stream:
        for line in stream:
            if _FUNCTION_RE.match(line):
                functions += 1
            elif tool_name in _RIZIN_TOOLS and _RIZIN_FUNCTION_RE.match(line):
                functions += 1
            if _OBJDUMP_INSN_RE.match(line):
                instructions += 1
            elif tool_name in _RIZIN_TOOLS and _RIZIN_INSN_RE.search(line):
                instructions += 1
    return functions, instructions


def _run_tool(
    input_path: Path,
    outdir: Path,
    tool_path: str,
    tool_name: str,
    timeout: int,
) -> dict:
    outdir.mkdir(parents=True, exist_ok=True)
    output_path = outdir / "disassembly.txt"
    temp_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            errors="replace",
            prefix=".disassembly-",
            suffix=".part",
            dir=str(outdir),
            delete=False,
        ) as output:
            temp_name = output.name
            try:
                proc = subprocess.run(
                    command_for(tool_path, tool_name, input_path),
                    stdout=output,
                    stderr=subprocess.PIPE,
                    text=True,
                    errors="replace",
                    timeout=max(1, timeout),
                    check=False,
                )
            except subprocess.TimeoutExpired:
                return {
                    "ok": False,
                    "tool": tool_name,
                    "error": f"disassembly timed out after {max(1, timeout)} seconds",
                }
            except OSError as exc:
                return {
                    "ok": False,
                    "tool": tool_name,
                    "error": f"failed to start disassembler: {exc}",
                }

        temp_path = Path(temp_name)
        output_bytes = temp_path.stat().st_size
        if proc.returncode != 0 or output_bytes == 0:
            return {
                "ok": False,
                "tool": tool_name,
                "exitCode": proc.returncode,
                "error": "disassembler produced no usable listing",
                "stderr": (proc.stderr or "").strip()[:2000],
            }

        os.replace(temp_path, output_path)
        temp_name = None
        functions, instructions = summarize_listing(output_path, tool_name)
        return {
            "ok": True,
            "tool": tool_name,
            "outputFile": str(output_path.resolve()),
            "bytes": output_bytes,
            "functionLabels": functions,
            "instructionLines": instructions,
            "exitCode": proc.returncode,
            "stderr": (proc.stderr or "").strip()[:2000] or None,
        }
    finally:
        if temp_name:
            try:
                Path(temp_name).unlink()
            except OSError:
                pass


def disassemble(
    input_path: Path,
    outdir: Path,
    requested_tool: str,
    timeout: int,
) -> tuple[dict, None]:
    candidates = available_tools(requested_tool)
    if not candidates:
        wanted = requested_tool if requested_tool != "auto" else ", ".join(_AUTO_ORDER)
        return {
            "ok": False,
            "error": f"no usable disassembler found ({wanted})",
            "hint": "Install LLVM/binutils, or install rizin/radare2 as a fallback.",
        }, None

    failures = []
    for tool_path, tool_name in candidates:
        result = _run_tool(input_path, outdir, tool_path, tool_name, timeout)
        if result.get("ok"):
            if failures:
                result["fallbacks"] = failures
            return result, None
        failures.append({
            "tool": tool_name,
            "error": result.get("error", "failed"),
            "exitCode": result.get("exitCode"),
            "stderr": result.get("stderr"),
        })
        if requested_tool != "auto":
            return result, None

    last = dict(result)
    last["attempts"] = failures
    return last, None


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="native-disassemble")
    parser.add_argument("input")
    parser.add_argument("outdir")
    parser.add_argument("--tool", choices=("auto", *_AUTO_ORDER), default="auto")
    parser.add_argument("--timeout", type=int, default=1800)
    parser.add_argument("--format", choices=("text", "json"), default="text")
    args = parser.parse_args(argv[1:])

    input_path = Path(args.input)
    if not input_path.is_file():
        emit_json({"ok": False, "error": f"file not found: {args.input}"})
        return 2

    binary_format = detect_format(input_path)
    if not binary_format:
        emit_json({
            "ok": False,
            "error": "unsupported or malformed input; expected PE, ELF, or Mach-O",
        })
        return 2

    result, _ = disassemble(input_path, Path(args.outdir), args.tool, args.timeout)
    result["format"] = binary_format
    result["input"] = str(input_path.resolve())

    if args.format == "json" or not result.get("ok"):
        emit_json(result)
    else:
        print(
            f"native-disassemble: {input_path.name} ({binary_format}) via "
            f"{result['tool']} → {result['outputFile']}"
        )
        print(
            f"  {result['bytes']} bytes · {result['functionLabels']} function label(s) · "
            f"{result['instructionLines']} instruction line(s)"
        )
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

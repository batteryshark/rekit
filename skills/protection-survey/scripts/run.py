#!/usr/bin/env python3
"""Static, explainable survey of source-level anti-analysis/protection patterns."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Pattern, Tuple


SOURCE_EXTENSIONS = {
    ".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".m", ".mm",
    ".s", ".asm", ".inc", ".rs", ".go", ".py", ".pyw", ".js", ".jsx",
    ".mjs", ".cjs", ".ts", ".tsx", ".java", ".kt", ".kts", ".cs", ".swift",
}
BUILD_FILES = {
    "makefile", "gnumakefile", "cmakelists.txt", "cargo.toml", "build.rs",
    "go.mod", "go.sum", "meson.build", "build.gradle", "build.gradle.kts",
    "package.json", "pyproject.toml", "setup.py",
}
SKIP_DIRS = {
    ".git", ".hg", ".svn", ".idea", ".vscode", "node_modules", "vendor",
    "third_party", "third-party", "dist", "build", "out", "target", ".venv",
    "venv", "__pycache__", ".tox", ".mypy_cache", ".pytest_cache", "Pods",
}


PatternSpec = Tuple[str, float, str, Tuple[Pattern[str], ...]]


def _rx(*patterns: str) -> Tuple[Pattern[str], ...]:
    return tuple(re.compile(pattern, re.IGNORECASE) for pattern in patterns)


PATTERNS: Dict[str, PatternSpec] = {
    "PROT.ANTI_DEBUG": (
        "anti-debug", 0.82, "debugger/tracer detection or disruption",
        _rx(
            r"\b(?:IsDebuggerPresent|CheckRemoteDebuggerPresent|NtQueryInformationProcess)\b",
            r"\bptrace\s*\([^\n]*(?:PTRACE_TRACEME|PT_DENY_ATTACH)",
            r"\b(?:sys\.gettrace|Debug\.isDebuggerConnected|Debugger\.IsAttached)\b",
            r"/proc/(?:self|\d+)/status|\bTracerPid\b",
            r"\b(?:DebugActiveProcess|OutputDebugString[AW]?)\b",
        ),
    ),
    "PROT.ANTI_VM": (
        "anti-vm", 0.66, "virtual-machine, sandbox, or analysis-environment check",
        _rx(
            r"\b(?:VMware|VirtualBox|VBox|QEMU|Xen|Hyper-V|Sandboxie|Cuckoo)\b",
            r"\bcpuid\b[^\n]*(?:hypervisor|0x40000000)",
            r"/sys/class/dmi|/proc/cpuinfo[^\n]*hypervisor",
            r"\b(?:GetSystemFirmwareTable|Win32_ComputerSystem|Win32_BIOS)\b",
        ),
    ),
    "PROT.RUNTIME_RESOLVE": (
        "runtime-resolution", 0.72, "API or symbol resolved at runtime",
        _rx(
            r"\b(?:GetProcAddress|LdrGetProcedureAddress|LoadLibrary(?:Ex)?[AW]?)\b",
            r"\b(?:dlopen|dlsym|NSLookupSymbolInImage)\s*\(",
            r"\b(?:NativeLibrary\.GetExport|Assembly\.Load|Class\.forName)\b",
            r"\b(?:syscall\.NewLazyDLL|NewProc)\b",
        ),
    ),
    "PROT.EXEC_MEMORY": (
        "executable-memory", 0.78, "memory allocated or changed to executable",
        _rx(
            r"\b(?:VirtualProtect|VirtualAlloc|NtProtectVirtualMemory|NtAllocateVirtualMemory)\b[^\n]*(?:PAGE_EXECUTE|0x40)",
            r"\b(?:mmap|mprotect)\s*\([^\n]*(?:PROT_EXEC|PROT_READ\s*\|\s*PROT_WRITE\s*\|\s*PROT_EXEC)",
            r"\b(?:MAP_JIT|pthread_jit_write_protect_np)\b",
        ),
    ),
    "PROT.EXCEPTION_FLOW": (
        "exception-flow", 0.64, "exception/signal machinery used as control flow",
        _rx(
            r"\b(?:AddVectoredExceptionHandler|SetUnhandledExceptionFilter|RaiseException)\b",
            r"\b__try\b|\b__except\s*\(",
            r"\b(?:sigaction|signal)\s*\([^\n]*(?:SIGTRAP|SIGSEGV|SIGILL)",
            r"\b(?:setjmp|longjmp|sigsetjmp|siglongjmp)\b",
        ),
    ),
    "PROT.EARLY_EXEC": (
        "early-execution", 0.70, "code scheduled before the ordinary entry point",
        _rx(
            r"__attribute__\s*\(\([^\n]*(?:constructor|init_priority)",
            r"\b(?:DllMain|TLS_CALLBACK|PIMAGE_TLS_CALLBACK)\b|\.CRT\$XL",
            r"\b(?:\.init_array|\.preinit_array|mod_init_func)\b",
            r"#\s*\[\s*(?:ctor|used)[^\]]*\]",
        ),
    ),
    "PROT.CUSTOM_SECTION": (
        "custom-section", 0.62, "data or code placed in a custom binary section",
        _rx(
            r"__attribute__\s*\(\([^\n]*section\s*\(",
            r"#\s*\[\s*(?:unsafe\s*\(\s*)?link_section\s*=",
            r"\b(?:__declspec\s*\(\s*allocate|#\s*pragma\s+section)\b",
            r"^\s*\.section\s+[._A-Za-z]",
        ),
    ),
    "PROT.INLINE_ASM": (
        "inline-assembly", 0.76, "inline or embedded assembly",
        _rx(
            r"\b(?:__asm__?|asm)\s*(?:volatile\s*)?\(",
            r"\b(?:asm|global_asm)\s*!\s*\(",
            r"\b__asm\s*\{",
        ),
    ),
    "PROT.OPAQUE_BRANCH": (
        "opaque-branch", 0.52, "constant-heavy conditional that may be opaque",
        _rx(
            r"\bif\s*\(\s*(?:0x[0-9a-f]+|\d+)\s*(?:\^|&|\||%|\*|<<|>>)\s*(?:0x[0-9a-f]+|\d+)[^\n]*\)",
            r"\bif\s*\([^\n]*(?:\bx\s*\*\s*x\b|\bx\s*&\s*1\b)[^\n]*(?:==|!=)\s*(?:0|1)\s*\)",
        ),
    ),
    "PROT.FLATTENING": (
        "control-flow-flattening", 0.58, "state-dispatch loop associated with flattened control flow",
        _rx(
            r"\bswitch\s*\(\s*(?:state|dispatcher|control_flow|next_block)\w*\s*\)",
            r"\bmatch\s+(?:state|dispatcher|control_flow|next_block)\w*\s*\{",
        ),
    ),
    "PROT.STACK_STRING": (
        "stack-string", 0.53, "byte/character array that may construct a string at runtime",
        _rx(
            r"\b(?:unsigned\s+char|char|uint8_t|byte)\s+\w+\s*\[[^\]]*\]\s*=\s*\{\s*(?:0x[0-9a-f]{1,2}\s*,\s*){3,}",
            r"\blet\s+(?:mut\s+)?\w+\s*=\s*\[\s*(?:0x[0-9a-f]{1,2}\s*,\s*){3,}",
        ),
    ),
    "PROT.BUILD_OBFUSCATION": (
        "build-obfuscation", 0.86, "build configuration enables an obfuscating transform",
        _rx(
            r"\b(?:obfuscator-llvm|ollvm)\b",
            r"-mllvm[^\n]*(?:-fla|-bcf|-sub|-split)",
            r"\bgarble\b[^\n]*(?:build|tiny|literals|seed)",
            r"\b(?:javascript-obfuscator|pyarmor|cythonize)\b",
        ),
    ),
    "PROT.PROCESS_INJECTION": (
        "process-instrumentation", 0.74, "cross-process memory/thread primitive",
        _rx(
            r"\b(?:VirtualAllocEx|WriteProcessMemory|CreateRemoteThread(?:Ex)?|NtCreateThreadEx)\b",
            r"\b(?:QueueUserAPC|SetWindowsHookEx[AW]?|RtlCreateUserThread)\b",
            r"\b(?:process_vm_writev|PTRACE_POKETEXT|mach_vm_write|thread_create_running)\b",
        ),
    ),
    "PROT.SELF_INTEGRITY": (
        "self-integrity", 0.60, "code or image integrity/self-check",
        _rx(
            r"\b(?:crc32|sha256|checksum|hash)\b[^\n]*(?:self|own_(?:image|binary)|text_section|\.text|current_exe|executable_path)",
            r"(?:self|own_(?:image|binary)|text_section|\.text|current_exe|executable_path)[^\n]*\b(?:crc32|sha256|checksum|hash)\b",
            r"\b(?:SecStaticCodeCheckValidity|WinVerifyTrust|CryptCATAdminCalcHashFromFileHandle)\b",
        ),
    ),
}


MULTILINE_PATTERNS = {
    "PROT.FLATTENING": re.compile(
        r"(?:while\s*\(\s*(?:1|true)\s*\)|loop\s*\{).{0,1600}?"
        r"(?:switch\s*\(|match\s+(?:state|dispatcher|control_flow|next_block))",
        re.IGNORECASE | re.DOTALL,
    )
}


def is_candidate(path: Path, explicit: bool = False) -> bool:
    if explicit:
        return True
    return path.suffix.lower() in SOURCE_EXTENSIONS or path.name.lower() in BUILD_FILES


def iter_files(root: Path, include_hidden: bool, max_files: int) -> Iterable[Path]:
    if root.is_file():
        if is_candidate(root, explicit=True):
            yield root
        return
    emitted = 0
    for directory, dirnames, filenames in os.walk(str(root)):
        dirnames[:] = [
            name for name in dirnames
            if name not in SKIP_DIRS and (include_hidden or not name.startswith("."))
        ]
        for filename in sorted(filenames):
            if not include_hidden and filename.startswith("."):
                continue
            path = Path(directory) / filename
            if not is_candidate(path):
                continue
            yield path
            emitted += 1
            if emitted >= max_files:
                return


def relative_name(path: Path, root: Path) -> str:
    if root.is_file():
        return path.name
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def make_finding(atom: str, path: str, line_no: int, col: int,
                 snippet: str, indicator: str) -> dict:
    family, confidence, note, _patterns = PATTERNS[atom]
    return {
        "atom": atom,
        "family": family,
        "confidence": confidence,
        "file": path,
        "line": line_no,
        "col": col,
        "indicator": indicator,
        "snippet": snippet.strip()[:220],
        "note": note,
        "method": "protection-survey",
    }


def scan_text(text: str, path: str, findings: List[dict], counts: Counter,
              max_findings: int) -> None:
    seen = set()
    lines = text.splitlines()
    for line_no, line in enumerate(lines, 1):
        for atom, (_family, _confidence, _note, patterns) in PATTERNS.items():
            for pattern in patterns:
                match = pattern.search(line)
                if not match:
                    continue
                key = (atom, line_no)
                if key in seen:
                    break
                seen.add(key)
                counts[atom] += 1
                if len(findings) < max_findings:
                    findings.append(make_finding(atom, path, line_no, match.start() + 1,
                                                 line, pattern.pattern))
                break

    for atom, pattern in MULTILINE_PATTERNS.items():
        match = pattern.search(text)
        if not match:
            continue
        line_no = text.count("\n", 0, match.start()) + 1
        key = (atom, line_no)
        if key in seen:
            continue
        counts[atom] += 1
        if len(findings) < max_findings:
            snippet = lines[line_no - 1] if 0 < line_no <= len(lines) else ""
            findings.append(make_finding(atom, path, line_no, 1, snippet,
                                         "multi-line state-dispatch loop"))


def assessment(counts: Counter) -> str:
    if not counts:
        return "No surveyed protection-pattern indicators found."
    strong = [atom for atom, count in counts.items()
              if count and PATTERNS[atom][1] >= 0.70]
    if len(strong) >= 3:
        return (
            "Multiple higher-confidence protection families co-occur. Review their "
            "call sites together before deciding whether they are hardening, instrumentation, "
            "compatibility code, or deliberate anti-analysis."
        )
    return (
        "Protection indicators are present, but individual APIs and build flags can be "
        "legitimate. Review the evidence in context and correlate categories."
    )


def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(prog="protection-survey")
    parser.add_argument("input")
    parser.add_argument("--format", choices=("text", "json"), default="json")
    parser.add_argument("--max-files", type=int, default=10000)
    parser.add_argument("--max-file-bytes", type=int, default=2 * 1024 * 1024)
    parser.add_argument("--max-findings", type=int, default=500)
    parser.add_argument("--include-hidden", action="store_true")
    args = parser.parse_args(argv[1:])

    root = Path(args.input).expanduser().resolve()
    if not root.exists():
        print(json.dumps({"ok": False, "error": f"not found: {root}"}))
        return 2
    if args.max_files < 1 or args.max_file_bytes < 1 or args.max_findings < 1:
        print(json.dumps({"ok": False, "error": "scan limits must be positive integers"}))
        return 2

    findings: List[dict] = []
    counts: Counter = Counter()
    skipped = Counter()
    files_scanned = 0
    for path in iter_files(root, args.include_hidden, args.max_files):
        try:
            size = path.stat().st_size
            if size > args.max_file_bytes:
                skipped["oversized"] += 1
                continue
            raw = path.read_bytes()
        except OSError:
            skipped["unreadable"] += 1
            continue
        if b"\x00" in raw[:4096]:
            skipped["binary"] += 1
            continue
        text = raw.decode("utf-8", "replace")
        files_scanned += 1
        scan_text(text, relative_name(path, root), findings, counts, args.max_findings)

    category_counts = dict(sorted(counts.items()))
    families = sorted({PATTERNS[atom][0] for atom in counts})
    result = {
        "ok": True,
        "root": str(root),
        "filesScanned": files_scanned,
        "skipped": dict(sorted(skipped.items())),
        "findingCount": sum(counts.values()),
        "evidenceReturned": len(findings),
        "truncated": sum(counts.values()) > len(findings),
        "categoryCounts": category_counts,
        "families": families,
        "assessment": assessment(counts),
        "findings": findings,
    }
    if args.format == "json":
        print(json.dumps(result, sort_keys=True))
        return 0

    print(f"protection-survey: {root}")
    print(f"scanned {files_scanned} file(s); {result['findingCount']} indicator(s)")
    for atom, count in category_counts.items():
        print(f"  {atom:28} {count}")
    print(f"\n{result['assessment']}\n")
    for finding in findings:
        print(f"  [{finding['confidence']:.2f}] {finding['atom']} "
              f"{finding['file']}:{finding['line']}:{finding['col']}")
        print(f"        > {finding['snippet']}")
    if result["truncated"]:
        print(f"\n  evidence capped at {len(findings)} finding(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

#!/usr/bin/env python3
"""emulate-code — emulate a raw code/shellcode blob with Unicorn and observe effects.

Runs the bytes on an emulated CPU (x86/x64/arm/arm64), not the host — so it's
*contained* (memory-only; no host syscalls unless explicitly wired). Reports the final
register state, instruction count, and memory writes. The safe way to "run" shellcode
or an isolated function to see what it computes.

    python3 emulate.py <blob> [--arch x64|x86|arm64|arm] [--base 0x1000000]
                        [--max-insn N] [--timeout SEC] [--format text|json]
"""

from __future__ import annotations

import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "site"))


def _regs(mod, prefix, names):
    return [(n, getattr(mod, f"{prefix}{n.upper()}")) for n in names]


def _arch_table():
    from unicorn import UC_ARCH_X86, UC_MODE_32, UC_MODE_64, UC_ARCH_ARM, UC_ARCH_ARM64, UC_MODE_ARM
    import unicorn.x86_const as x86
    import unicorn.arm_const as arm
    import unicorn.arm64_const as a64
    return {
        "x64": (UC_ARCH_X86, UC_MODE_64,
                _regs(x86, "UC_X86_REG_", "rax rbx rcx rdx rsi rdi rbp rsp rip "
                                          "r8 r9 r10 r11 r12 r13 r14 r15".split()),
                x86.UC_X86_REG_RSP),
        "x86": (UC_ARCH_X86, UC_MODE_32,
                _regs(x86, "UC_X86_REG_", "eax ebx ecx edx esi edi ebp esp eip".split()),
                x86.UC_X86_REG_ESP),
        "arm64": (UC_ARCH_ARM64, UC_MODE_ARM,
                  _regs(a64, "UC_ARM64_REG_", [f"x{i}" for i in range(31)] + ["sp", "pc"]),
                  a64.UC_ARM64_REG_SP),
        "arm": (UC_ARCH_ARM, UC_MODE_ARM,
                _regs(arm, "UC_ARM_REG_", [f"r{i}" for i in range(13)] + ["sp", "lr", "pc"]),
                arm.UC_ARM_REG_SP),
    }


def emulate(code: bytes, arch: str, base: int, max_insn: int, timeout: int):
    from unicorn import Uc, UC_HOOK_CODE, UC_HOOK_MEM_WRITE, UC_SECOND_SCALE, UcError

    uc_arch, uc_mode, reglist, sp_reg = _arch_table()[arch]
    mu = Uc(uc_arch, uc_mode)

    code_sz = max(0x200000, (len(code) + 0xFFF) & ~0xFFF)
    mu.mem_map(base, code_sz)
    mu.mem_write(base, code)
    stack = 0x7F000000
    mu.mem_map(stack, 0x100000)
    mu.reg_write(sp_reg, stack + 0x80000)

    count = [0]
    writes: list = []

    def on_code(_mu, _addr, _size, _ud):
        count[0] += 1

    def on_write(_mu, _access, addr, size, value, _ud):
        if len(writes) < 256:
            writes.append({"addr": hex(addr), "size": size, "value": hex(value & ((1 << (size * 8)) - 1))})

    mu.hook_add(UC_HOOK_CODE, on_code)
    mu.hook_add(UC_HOOK_MEM_WRITE, on_write)

    error = None
    stop = "completed"
    try:
        mu.emu_start(base, base + len(code), timeout=timeout * UC_SECOND_SCALE, count=max_insn)
    except UcError as exc:
        error, stop = str(exc), "fault"
    if error is None and count[0] >= max_insn:
        stop = "instruction-limit"

    regs = {n: hex(mu.reg_read(r)) for n, r in reglist}
    return {"ok": error is None, "arch": arch, "codeBytes": len(code),
            "instructions": count[0], "stopReason": stop, "error": error,
            "registers": regs, "memWrites": writes}


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="emulate-code")
    p.add_argument("input")
    p.add_argument("--arch", choices=["x64", "x86", "arm64", "arm"], default="x64")
    p.add_argument("--base", type=lambda x: int(x, 0), default=0x1000000)
    p.add_argument("--max-insn", type=int, default=200000)
    p.add_argument("--timeout", type=int, default=10)
    p.add_argument("--format", choices=["text", "json"], default="text")
    a = p.parse_args(argv[1:])
    if not os.path.isfile(a.input):
        print(json.dumps({"ok": False, "error": f"file not found: {a.input}"}))
        return 2
    code = open(a.input, "rb").read()
    if not code:
        print(json.dumps({"ok": False, "error": "empty code blob"}))
        return 2
    try:
        res = emulate(code, a.arch, a.base, a.max_insn, a.timeout)
    except Exception as exc:  # pragma: no cover
        print(json.dumps({"ok": False, "error": f"emulation setup failed: {exc}"}))
        return 1

    if a.format == "json":
        print(json.dumps(res))
        return 0
    print(f"emulate-code: {a.arch}  {res['codeBytes']} bytes  {res['instructions']} insn  "
          f"stop={res['stopReason']}" + (f"  fault: {res['error']}" if res['error'] else ""))
    gp = [f"{n}={v}" for n, v in list(res["registers"].items())[:10]]
    print("  regs: " + "  ".join(gp))
    if res["memWrites"]:
        print(f"  mem writes ({len(res['memWrites'])}):")
        for w in res["memWrites"][:10]:
            print(f"    {w['addr']} <- {w['value']} ({w['size']}b)")
    return 0 if res["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

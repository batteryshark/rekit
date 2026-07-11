#!/usr/bin/env python3
"""Persistent Unicorn/Qiling emulation operations for Rekit.

The transport is deliberately ordinary process invocation. Durable state lives in a
caller-selected directory, allowing the Rekit CLI and generated MCP tool to perform
separate operations against one emulated machine.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import shutil
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Iterator

HERE = Path(__file__).resolve().parent
SITE = HERE / "site"
if SITE.is_dir():
    sys.path.insert(0, str(SITE))

SCHEMA_VERSION = 1
PAGE = 0x1000
MAX_MAP = 256 * 1024 * 1024
MAX_STEPS = 1_000_000
MAX_TRACE = 10_000
DEFAULT_BASE = 0x1000000
DEFAULT_STACK = 0x7F000000


class SessionError(RuntimeError):
    pass


def parse_int(value: str | int | None, *, default: int | None = None) -> int:
    if value is None or value == "":
        if default is None:
            raise SessionError("a numeric value is required")
        return default
    if isinstance(value, int):
        result = value
    else:
        text = value.strip().lower()
        try:
            result = int(text, 0)
        except ValueError:
            if any(ch in "abcdef" for ch in text):
                result = int(text, 16)
            else:
                raise SessionError(f"invalid integer: {value}") from None
    if result < 0:
        raise SessionError("negative values are not allowed")
    return result


def parse_hex(value: str | None) -> bytes:
    if not value:
        raise SessionError("--data must contain hexadecimal bytes")
    text = "".join(value.split())
    if text.lower().startswith("0x"):
        text = text[2:]
    try:
        data = bytes.fromhex(text)
    except ValueError as exc:
        raise SessionError(f"invalid hexadecimal data: {exc}") from None
    if not data:
        raise SessionError("--data must not be empty")
    return data


def align_down(value: int) -> int:
    return value & ~(PAGE - 1)


def align_up(value: int) -> int:
    return (value + PAGE - 1) & ~(PAGE - 1)


def atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    temp.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temp, path)


def atomic_bytes(path: Path, value: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    temp.write_bytes(value)
    os.replace(temp, path)


@contextlib.contextmanager
def session_lock(root: Path) -> Iterator[None]:
    root.mkdir(parents=True, exist_ok=True)
    handle = (root / ".lock").open("a+b")
    try:
        if os.name == "nt":
            import msvcrt
            handle.seek(0)
            if handle.tell() == 0:
                handle.write(b"0")
                handle.flush()
            msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
        else:
            import fcntl
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        yield
    finally:
        if os.name == "nt":
            import msvcrt
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        handle.close()


def load_state(root: Path) -> dict[str, Any]:
    path = root / "session.json"
    if not path.is_file():
        raise SessionError(f"no emulation session at {root}; run create first")
    state = json.loads(path.read_text(encoding="utf-8"))
    if state.get("schema") != SCHEMA_VERSION:
        raise SessionError(f"unsupported session schema: {state.get('schema')}")
    return state


def save_state(root: Path, state: dict[str, Any]) -> None:
    state["updatedAt"] = int(time.time())
    atomic_json(root / "session.json", state)


def append_trace(state: dict[str, Any], entry: dict[str, Any]) -> None:
    trace = state.setdefault("trace", [])
    trace.append(entry)
    if len(trace) > MAX_TRACE:
        del trace[: len(trace) - MAX_TRACE]


def permissions(value: str | None) -> tuple[int, str]:
    if not value:
        return 7, "rwx"
    # Unicorn/Qiling use UC_PROT_READ=1, WRITE=2, EXEC=4.
    table = {"r": 1, "w": 2, "x": 4}
    if value.isdigit():
        mask = int(value)
    else:
        mask = sum(bit for char, bit in table.items() if char in value.lower())
    if mask < 1 or mask > 7:
        raise SessionError("--perms must be r, w, x, a combination, or 1..7")
    return mask, "".join(char for char, bit in table.items() if mask & bit)


def arch_spec(name: str) -> dict[str, Any]:
    try:
        import unicorn as uc
        import unicorn.arm64_const as arm64
        import unicorn.arm_const as arm
        import unicorn.mips_const as mips
        import unicorn.x86_const as x86
        import capstone as cs
    except Exception as exc:
        raise SessionError(f"emulation runtime unavailable: {exc}; run rekit install emulation-session") from None

    def regs(module: Any, prefix: str, names: list[str]) -> dict[str, int]:
        return {name: getattr(module, prefix + name.upper()) for name in names}

    specs = {
        "x64": (uc.UC_ARCH_X86, uc.UC_MODE_64, cs.CS_ARCH_X86, cs.CS_MODE_64,
                regs(x86, "UC_X86_REG_", "rax rbx rcx rdx rsi rdi rbp rsp rip r8 r9 r10 r11 r12 r13 r14 r15 eflags".split()), "rip", "rsp"),
        "x86": (uc.UC_ARCH_X86, uc.UC_MODE_32, cs.CS_ARCH_X86, cs.CS_MODE_32,
                regs(x86, "UC_X86_REG_", "eax ebx ecx edx esi edi ebp esp eip eflags".split()), "eip", "esp"),
        "arm": (uc.UC_ARCH_ARM, uc.UC_MODE_ARM, cs.CS_ARCH_ARM, cs.CS_MODE_ARM,
                regs(arm, "UC_ARM_REG_", [f"r{i}" for i in range(13)] + ["sp", "lr", "pc", "cpsr"]), "pc", "sp"),
        "thumb": (uc.UC_ARCH_ARM, uc.UC_MODE_THUMB, cs.CS_ARCH_ARM, cs.CS_MODE_THUMB,
                regs(arm, "UC_ARM_REG_", [f"r{i}" for i in range(13)] + ["sp", "lr", "pc", "cpsr"]), "pc", "sp"),
        "arm64": (uc.UC_ARCH_ARM64, uc.UC_MODE_ARM, cs.CS_ARCH_ARM64, cs.CS_MODE_ARM,
                regs(arm64, "UC_ARM64_REG_", [f"x{i}" for i in range(31)] + ["sp", "pc"]), "pc", "sp"),
        "mips": (uc.UC_ARCH_MIPS, uc.UC_MODE_MIPS32 | uc.UC_MODE_BIG_ENDIAN, cs.CS_ARCH_MIPS, cs.CS_MODE_MIPS32 | cs.CS_MODE_BIG_ENDIAN,
                regs(mips, "UC_MIPS_REG_", "v0 v1 a0 a1 a2 a3 t0 t1 t2 t3 t4 t5 t6 t7 s0 s1 s2 s3 s4 s5 s6 s7 t8 t9 gp sp fp ra pc".split()), "pc", "sp"),
        "mipsel": (uc.UC_ARCH_MIPS, uc.UC_MODE_MIPS32 | uc.UC_MODE_LITTLE_ENDIAN, cs.CS_ARCH_MIPS, cs.CS_MODE_MIPS32 | cs.CS_MODE_LITTLE_ENDIAN,
                regs(mips, "UC_MIPS_REG_", "v0 v1 a0 a1 a2 a3 t0 t1 t2 t3 t4 t5 t6 t7 s0 s1 s2 s3 s4 s5 s6 s7 t8 t9 gp sp fp ra pc".split()), "pc", "sp"),
    }
    if name not in specs:
        raise SessionError(f"unsupported Unicorn architecture: {name}")
    ua, um, ca, cm, register_map, pc, sp = specs[name]
    return {"uc_arch": ua, "uc_mode": um, "cs_arch": ca, "cs_mode": cm,
            "registers": register_map, "pc": pc, "sp": sp}


def create_unicorn(root: Path, args: argparse.Namespace) -> dict[str, Any]:
    target = Path(args.input).expanduser().resolve() if args.input else None
    if not target or not target.is_file():
        raise SessionError("Unicorn create requires an existing --input code blob")
    code = target.read_bytes()
    if not code:
        raise SessionError("input code blob is empty")
    arch = args.arch or "x64"
    spec = arch_spec(arch)
    base = parse_int(args.address, default=DEFAULT_BASE)
    code_start = align_down(base)
    code_size = align_up((base - code_start) + len(code))
    stack_start = DEFAULT_STACK
    stack_size = 0x100000
    if not (code_start + code_size <= stack_start or stack_start + stack_size <= code_start):
        raise SessionError("code mapping overlaps the default stack")
    regions = [
        {"address": code_start, "size": code_size, "perms": 7, "file": "regions/code.bin", "label": "code"},
        {"address": stack_start, "size": stack_size, "perms": 3, "file": "regions/stack.bin", "label": "stack"},
    ]
    code_image = bytearray(code_size)
    code_image[base - code_start : base - code_start + len(code)] = code
    atomic_bytes(root / "regions/code.bin", bytes(code_image))
    atomic_bytes(root / "regions/stack.bin", bytes(stack_size))
    pc_value = base | 1 if arch == "thumb" else base
    state = {"schema": SCHEMA_VERSION, "engine": "unicorn", "arch": arch,
             "target": str(target), "createdAt": int(time.time()), "closed": False,
             "entry": base, "end": base + len(code), "regions": regions,
             "registers": {spec["pc"]: pc_value, spec["sp"]: stack_start + stack_size // 2},
             "hooks": [], "snapshots": [], "trace": [], "traceEnabled": bool(args.trace)}
    save_state(root, state)
    return summary(state, root)


def hydrate_unicorn(root: Path, state: dict[str, Any]) -> tuple[Any, dict[str, Any]]:
    from unicorn import Uc
    spec = arch_spec(state["arch"])
    engine = Uc(spec["uc_arch"], spec["uc_mode"])
    for region in state["regions"]:
        engine.mem_map(region["address"], region["size"], region["perms"])
        data = (root / region["file"]).read_bytes()
        engine.mem_write(region["address"], data)
    for name, value in state.get("registers", {}).items():
        if name in spec["registers"]:
            engine.reg_write(spec["registers"][name], value)
    return engine, spec


def persist_unicorn(root: Path, state: dict[str, Any], engine: Any, spec: dict[str, Any]) -> None:
    for region in state["regions"]:
        atomic_bytes(root / region["file"], bytes(engine.mem_read(region["address"], region["size"])))
    state["registers"] = {name: engine.reg_read(number) for name, number in spec["registers"].items()}
    save_state(root, state)


def run_unicorn(root: Path, state: dict[str, Any], args: argparse.Namespace, *, stepping: bool) -> dict[str, Any]:
    import capstone
    import unicorn as uc
    engine, spec = hydrate_unicorn(root, state)
    disassembler = capstone.Cs(spec["cs_arch"], spec["cs_mode"])
    counter = 0
    stop_reason = "completed"
    hooks = {item["address"]: item for item in state.get("hooks", []) if item["type"] == "address"}

    def on_code(machine: Any, address: int, size: int, _data: Any) -> None:
        nonlocal counter, stop_reason
        counter += 1
        item = hooks.get(address)
        should_record = state.get("traceEnabled") or item is not None or stepping
        if should_record:
            raw = bytes(machine.mem_read(address, size))
            instruction = raw.hex()
            try:
                decoded = next(iter(disassembler.disasm(raw, address)), None)
                if decoded:
                    instruction = f"{decoded.mnemonic} {decoded.op_str}".strip()
            except Exception:
                pass
            append_trace(state, {"type": "instruction", "address": hex(address),
                                 "instruction": instruction, "hook": item.get("id") if item else None})
        if item and item.get("stop"):
            stop_reason = "breakpoint"
            machine.emu_stop()

    def on_write(_machine: Any, _access: int, address: int, size: int, value: int, _data: Any) -> None:
        if state.get("traceEnabled"):
            append_trace(state, {"type": "memory-write", "address": hex(address),
                                 "size": size, "value": hex(value & ((1 << (size * 8)) - 1))})

    engine.hook_add(uc.UC_HOOK_CODE, on_code)
    engine.hook_add(uc.UC_HOOK_MEM_WRITE, on_write)
    pc = parse_int(args.address, default=engine.reg_read(spec["registers"][spec["pc"]]))
    end = parse_int(args.end, default=state.get("end") or max(r["address"] + r["size"] for r in state["regions"]))
    count = min(parse_int(args.count, default=1 if stepping else 200000), MAX_STEPS)
    timeout = min(parse_int(args.timeout, default=10), 300)
    try:
        engine.emu_start(pc, end, timeout=timeout * 1_000_000, count=count)
        if stop_reason == "completed" and counter >= count:
            stop_reason = "step-complete" if stepping else "instruction-limit"
    except uc.UcError as exc:
        stop_reason = "fault"
        error = str(exc)
    else:
        error = None
    persist_unicorn(root, state, engine, spec)
    return {"ok": error is None, "engine": "unicorn", "stopReason": stop_reason,
            "instructions": counter, "pc": hex(state["registers"][spec["pc"]]),
            "error": error, "traceSize": len(state["trace"])}


def qiling_instance(root: Path, state: dict[str, Any], *, restore: bool = True) -> Any:
    try:
        from qiling import Qiling
        from qiling.const import QL_VERBOSE
    except Exception as exc:
        raise SessionError(f"Qiling runtime unavailable: {exc}; run rekit install emulation-session") from None
    ql = Qiling([state["target"], *state.get("argv", [])], state["rootfs"], verbose=QL_VERBOSE.DISABLED)
    snapshot = root / "current.qsnap"
    if restore and snapshot.is_file():
        ql.restore(snapshot=str(snapshot))
    return ql


def save_qiling(root: Path, ql: Any, state: dict[str, Any]) -> None:
    ql.save(mem=True, reg=True, fd=True, cpu_context=True, snapshot=str(root / "current.qsnap"))
    try:
        state["pc"] = int(ql.arch.regs.arch_pc)
    except Exception:
        pass
    try:
        state["arch"] = ql.arch.type.name.lower()
    except Exception:
        pass
    save_state(root, state)


def create_qiling(root: Path, args: argparse.Namespace) -> dict[str, Any]:
    target = Path(args.input).expanduser().resolve() if args.input else None
    rootfs = Path(args.rootfs).expanduser().resolve() if args.rootfs else None
    if not target or not target.is_file():
        raise SessionError("Qiling create requires an existing --input binary")
    if not rootfs or not rootfs.is_dir():
        raise SessionError("Qiling create requires a matching --rootfs directory")
    argv = json.loads(args.argv) if args.argv else []
    if not isinstance(argv, list) or not all(isinstance(item, str) for item in argv):
        raise SessionError("--argv must be a JSON array of strings")
    state = {"schema": SCHEMA_VERSION, "engine": "qiling", "arch": args.arch,
             "target": str(target), "rootfs": str(rootfs), "argv": argv,
             "createdAt": int(time.time()), "closed": False, "hooks": [],
             "snapshots": [], "trace": [], "traceEnabled": bool(args.trace)}
    ql = qiling_instance(root, state, restore=False)
    save_qiling(root, ql, state)
    return summary(state, root)


def install_qiling_hooks(ql: Any, state: dict[str, Any], stop_box: dict[str, str]) -> None:
    try:
        from qiling.const import QL_INTERCEPT
    except Exception:
        QL_INTERCEPT = None
    for item in state.get("hooks", []):
        kind = item["type"]
        if kind == "address":
            def address_cb(machine: Any, _item: dict[str, Any] = item) -> None:
                append_trace(state, {"type": "address-hook", "hook": _item["id"],
                                     "address": hex(_item["address"])})
                if _item.get("stop"):
                    stop_box["reason"] = "breakpoint"
                    machine.emu_stop()
            ql.hook_address(address_cb, item["address"])
        elif kind in {"syscall", "api"} and QL_INTERCEPT is not None:
            def call_cb(machine: Any, *values: Any, _item: dict[str, Any] = item, **_kw: Any) -> None:
                append_trace(state, {"type": _item["type"], "hook": _item["id"],
                                     "name": _item["name"], "args": [repr(v)[:160] for v in values]})
            if kind == "syscall":
                ql.os.set_syscall(item["name"], call_cb, QL_INTERCEPT.ENTER)
            else:
                ql.os.set_api(item["name"], call_cb, QL_INTERCEPT.ENTER)


def run_qiling(root: Path, state: dict[str, Any], args: argparse.Namespace, *, stepping: bool) -> dict[str, Any]:
    ql = qiling_instance(root, state)
    stop_box = {"reason": "completed"}
    install_qiling_hooks(ql, state, stop_box)
    count = min(parse_int(args.count, default=1 if stepping else 200000), MAX_STEPS)
    seen = 0

    def code_cb(machine: Any, address: int, size: int) -> None:
        nonlocal seen
        seen += 1
        if state.get("traceEnabled") or stepping:
            append_trace(state, {"type": "instruction", "address": hex(address), "size": size})
        if stepping and seen >= count:
            stop_box["reason"] = "step-complete"
            machine.emu_stop()

    ql.hook_code(code_cb)
    timeout = min(parse_int(args.timeout, default=30), 300)
    timed_out = threading.Event()

    def watchdog() -> None:
        timed_out.set()
        try:
            ql.emu_stop()
        except Exception:
            pass

    timer = threading.Timer(timeout, watchdog)
    timer.daemon = True
    timer.start()
    kwargs: dict[str, Any] = {}
    if args.address:
        kwargs["begin"] = parse_int(args.address)
    if args.end:
        kwargs["end"] = parse_int(args.end)
    try:
        ql.run(**kwargs)
        error = None
    except Exception as exc:
        error = str(exc)
        stop_box["reason"] = "fault"
    finally:
        timer.cancel()
    if timed_out.is_set():
        stop_box["reason"] = "timeout"
    save_qiling(root, ql, state)
    return {"ok": error is None, "engine": "qiling", "stopReason": stop_box["reason"],
            "instructions": seen, "pc": hex(state.get("pc", 0)), "error": error,
            "traceSize": len(state["trace"])}


def summary(state: dict[str, Any], root: Path) -> dict[str, Any]:
    result = {"ok": True, "session": str(root), "engine": state["engine"],
              "arch": state.get("arch"), "target": state.get("target"),
              "closed": state.get("closed", False), "hooks": len(state.get("hooks", [])),
              "snapshots": len(state.get("snapshots", [])), "traceSize": len(state.get("trace", []))}
    if state["engine"] == "unicorn":
        spec = arch_spec(state["arch"])
        result.update({"pc": hex(state.get("registers", {}).get(spec["pc"], 0)),
                       "regions": [{"address": hex(r["address"]), "size": r["size"], "perms": r["perms"], "label": r.get("label")} for r in state["regions"]]})
    else:
        result.update({"pc": hex(state.get("pc", 0)), "rootfs": state.get("rootfs")})
    return result


def engine_read_memory(root: Path, state: dict[str, Any], address: int, size: int) -> bytes:
    if size < 1 or size > 1024 * 1024:
        raise SessionError("memory read size must be between 1 and 1048576 bytes")
    if state["engine"] == "unicorn":
        engine, _ = hydrate_unicorn(root, state)
        return bytes(engine.mem_read(address, size))
    ql = qiling_instance(root, state)
    return bytes(ql.mem.read(address, size))


def engine_write_memory(root: Path, state: dict[str, Any], address: int, data: bytes) -> None:
    if state["engine"] == "unicorn":
        engine, spec = hydrate_unicorn(root, state)
        engine.mem_write(address, data)
        persist_unicorn(root, state, engine, spec)
    else:
        ql = qiling_instance(root, state)
        ql.mem.write(address, data)
        save_qiling(root, ql, state)


def engine_registers(root: Path, state: dict[str, Any]) -> dict[str, int]:
    if state["engine"] == "unicorn":
        return dict(state.get("registers", {}))
    ql = qiling_instance(root, state)
    mapping = ql.arch.regs.register_mapping
    names = list(mapping() if callable(mapping) else mapping)
    result = {}
    for name in names:
        try:
            result[name] = int(ql.arch.regs.read(name))
        except Exception:
            pass
    return result


def snapshot_save(root: Path, state: dict[str, Any], label: str) -> dict[str, Any]:
    snap_id = f"snap-{uuid.uuid4().hex[:10]}"
    snap_dir = root / "snapshots" / snap_id
    snap_dir.mkdir(parents=True)
    if state["engine"] == "unicorn":
        shutil.copytree(root / "regions", snap_dir / "regions")
    else:
        shutil.copy2(root / "current.qsnap", snap_dir / "current.qsnap")
    frozen = json.loads(json.dumps(state))
    frozen["snapshots"] = []
    atomic_json(snap_dir / "state.json", frozen)
    item = {"id": snap_id, "label": label or snap_id, "createdAt": int(time.time())}
    state.setdefault("snapshots", []).append(item)
    save_state(root, state)
    return {"ok": True, "snapshot": item}


def snapshot_find(state: dict[str, Any], value: str | None) -> dict[str, Any]:
    if not value:
        raise SessionError("--snapshot is required")
    matches = [item for item in state.get("snapshots", []) if value in {item["id"], item["label"]}]
    if len(matches) != 1:
        raise SessionError(f"snapshot not found or label is ambiguous: {value}")
    return matches[0]


def snapshot_restore(root: Path, state: dict[str, Any], value: str | None) -> dict[str, Any]:
    item = snapshot_find(state, value)
    snap_dir = root / "snapshots" / item["id"]
    restored = json.loads((snap_dir / "state.json").read_text(encoding="utf-8"))
    restored["snapshots"] = state.get("snapshots", [])
    if state["engine"] == "unicorn":
        for source in (snap_dir / "regions").iterdir():
            shutil.copy2(source, root / "regions" / source.name)
    else:
        shutil.copy2(snap_dir / "current.qsnap", root / "current.qsnap")
    save_state(root, restored)
    return {"ok": True, "restored": item, "state": summary(restored, root)}


def operate(root: Path, state: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    action = args.action
    if state.get("closed") and action not in {"info", "reopen", "list-snapshots", "get-trace"}:
        raise SessionError("session is closed; use reopen before changing it")
    if action == "info":
        return summary(state, root)
    if action == "close":
        state["closed"] = True
        save_state(root, state)
        return summary(state, root)
    if action == "reopen":
        state["closed"] = False
        save_state(root, state)
        return summary(state, root)
    if action in {"run", "step"}:
        if state["engine"] == "unicorn":
            return run_unicorn(root, state, args, stepping=action == "step")
        return run_qiling(root, state, args, stepping=action == "step")
    if action == "read-memory":
        address = parse_int(args.address)
        data = engine_read_memory(root, state, address, parse_int(args.size, default=64))
        return {"ok": True, "address": hex(address), "size": len(data), "hex": data.hex(),
                "ascii": "".join(chr(b) if 32 <= b < 127 else "." for b in data)}
    if action == "write-memory":
        address, data = parse_int(args.address), parse_hex(args.data)
        engine_write_memory(root, state, address, data)
        return {"ok": True, "address": hex(address), "bytesWritten": len(data)}
    if action == "map-memory":
        address, size = parse_int(args.address), align_up(parse_int(args.size))
        if address % PAGE or size < PAGE or size > MAX_MAP:
            raise SessionError("mapping address must be page-aligned and size must be 4 KiB..256 MiB")
        mask, text = permissions(args.perms)
        if state["engine"] == "unicorn":
            for region in state["regions"]:
                if not (address + size <= region["address"] or region["address"] + region["size"] <= address):
                    raise SessionError("mapping overlaps an existing region")
            filename = f"regions/map-{address:x}.bin"
            atomic_bytes(root / filename, bytes(size))
            state["regions"].append({"address": address, "size": size, "perms": mask, "file": filename, "label": args.label or "mapped"})
            save_state(root, state)
        else:
            ql = qiling_instance(root, state)
            ql.mem.map(address, size, perms=mask, info=args.label or "[rekit]")
            save_qiling(root, ql, state)
        return {"ok": True, "address": hex(address), "size": size, "perms": text}
    if action == "search-memory":
        pattern = parse_hex(args.data)
        if state["engine"] == "unicorn":
            matches = []
            for region in state["regions"]:
                data = (root / region["file"]).read_bytes()
                start = 0
                while len(matches) < 100:
                    offset = data.find(pattern, start)
                    if offset < 0:
                        break
                    matches.append(region["address"] + offset)
                    start = offset + 1
        else:
            ql = qiling_instance(root, state)
            matches = list(ql.mem.search(pattern))[:100]
        return {"ok": True, "matches": [hex(value) for value in matches], "truncated": len(matches) == 100}
    if action == "read-registers":
        values = engine_registers(root, state)
        requested = [name.strip().lower() for name in args.name.split(",")] if args.name else list(values)
        missing = [name for name in requested if name not in values]
        if missing:
            raise SessionError(f"unknown register(s): {', '.join(missing)}")
        return {"ok": True, "registers": {name: hex(values[name]) for name in requested}}
    if action == "write-register":
        if not args.name:
            raise SessionError("--name is required")
        value = parse_int(args.value)
        if state["engine"] == "unicorn":
            engine, spec = hydrate_unicorn(root, state)
            name = args.name.lower()
            if name not in spec["registers"]:
                raise SessionError(f"unknown register for {state['arch']}: {name}")
            engine.reg_write(spec["registers"][name], value)
            persist_unicorn(root, state, engine, spec)
        else:
            ql = qiling_instance(root, state)
            ql.arch.regs.write(args.name, value)
            save_qiling(root, ql, state)
        return {"ok": True, "register": args.name.lower(), "value": hex(value)}
    if action == "add-hook":
        kind = args.hook_type or "address"
        if state["engine"] == "unicorn" and kind != "address":
            raise SessionError("Unicorn sessions support address hooks only")
        item = {"id": f"hook-{uuid.uuid4().hex[:10]}", "type": kind,
                "label": args.label or "", "stop": bool(args.stop)}
        if kind == "address":
            item["address"] = parse_int(args.address)
        else:
            if not args.name:
                raise SessionError("syscall and API hooks require --name")
            item["name"] = args.name
        state.setdefault("hooks", []).append(item)
        save_state(root, state)
        return {"ok": True, "hook": item}
    if action == "list-hooks":
        hooks = json.loads(json.dumps(state.get("hooks", [])))
        for item in hooks:
            if "address" in item:
                item["address"] = hex(item["address"])
        return {"ok": True, "hooks": hooks}
    if action == "remove-hook":
        if not args.name:
            raise SessionError("--name must identify the hook")
        before = len(state.get("hooks", []))
        state["hooks"] = [item for item in state.get("hooks", []) if item["id"] != args.name]
        if len(state["hooks"]) == before:
            raise SessionError(f"hook not found: {args.name}")
        save_state(root, state)
        return {"ok": True, "removed": args.name}
    if action == "save-snapshot":
        return snapshot_save(root, state, args.label or "")
    if action == "restore-snapshot":
        return snapshot_restore(root, state, args.snapshot)
    if action == "list-snapshots":
        return {"ok": True, "snapshots": state.get("snapshots", [])}
    if action == "set-trace":
        if args.enabled not in {"true", "false"}:
            raise SessionError("--enabled true|false is required")
        state["traceEnabled"] = args.enabled == "true"
        save_state(root, state)
        return {"ok": True, "traceEnabled": state["traceEnabled"]}
    if action == "get-trace":
        count = min(parse_int(args.count, default=200), MAX_TRACE)
        return {"ok": True, "trace": state.get("trace", [])[-count:], "total": len(state.get("trace", []))}
    if action == "clear-trace":
        state["trace"] = []
        save_state(root, state)
        return {"ok": True, "traceSize": 0}
    raise SessionError(f"unsupported action: {action}")


ACTIONS = ["create", "info", "run", "step", "read-memory", "write-memory", "map-memory",
           "search-memory", "read-registers", "write-register", "add-hook", "list-hooks",
           "remove-hook", "save-snapshot", "restore-snapshot", "list-snapshots", "set-trace",
           "get-trace", "clear-trace", "close", "reopen"]


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(prog="emulation-session")
    value.add_argument("session")
    value.add_argument("action", choices=ACTIONS)
    value.add_argument("--engine", choices=["unicorn", "qiling"])
    value.add_argument("--arch", choices=["x64", "x86", "arm", "thumb", "arm64", "mips", "mipsel"])
    value.add_argument("--input")
    value.add_argument("--rootfs")
    value.add_argument("--argv")
    value.add_argument("--address")
    value.add_argument("--end")
    value.add_argument("--size")
    value.add_argument("--data")
    value.add_argument("--name")
    value.add_argument("--value")
    value.add_argument("--count")
    value.add_argument("--timeout")
    value.add_argument("--perms")
    value.add_argument("--label")
    value.add_argument("--snapshot")
    value.add_argument("--hook-type", choices=["address", "syscall", "api"])
    value.add_argument("--stop", action="store_true")
    value.add_argument("--trace", action="store_true")
    value.add_argument("--enabled", choices=["true", "false"])
    value.add_argument("--format", choices=["text", "json"], default="text")
    return value


def render_text(result: dict[str, Any]) -> str:
    if not result.get("ok"):
        return f"emulation-session: error: {result.get('error')}"
    return json.dumps(result, indent=2, sort_keys=True)


def main(argv: list[str]) -> int:
    args = parser().parse_args(argv[1:])
    root = Path(args.session).expanduser().resolve()
    try:
        with session_lock(root):
            if args.action == "create":
                if (root / "session.json").exists():
                    raise SessionError(f"session already exists at {root}")
                if args.engine == "unicorn":
                    result = create_unicorn(root, args)
                elif args.engine == "qiling":
                    result = create_qiling(root, args)
                else:
                    raise SessionError("create requires --engine unicorn|qiling")
            else:
                result = operate(root, load_state(root), args)
    except (SessionError, OSError, json.JSONDecodeError) as exc:
        result = {"ok": False, "error": str(exc), "session": str(root)}
    except Exception as exc:
        # Emulator backends raise version- and target-specific exception classes.
        # Keep the runner's machine contract stable without pretending the
        # operation succeeded or discarding the concrete backend failure.
        result = {"ok": False, "error": f"{type(exc).__name__}: {exc}", "session": str(root)}
    print(json.dumps(result, sort_keys=True) if args.format == "json" else render_text(result))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

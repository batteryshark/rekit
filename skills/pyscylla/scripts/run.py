"""pyscylla — rekit dispatcher for the libscylla Python bindings (IAT rebuild).

Wraps the vendored pyscylla package (scripts/pyscylla/) + native DLLs
(scripts/bin/libscylla-{x86,x64}.dll). Forwards `op` + args to the pyscylla CLI,
forcing JSON output for machine consumption. Windows-only (the libscylla DLL and
the live-process operations require Windows + a matching-arch Python).

    python3 run.py <op> [op-args...] [--json]

Ops: version | arch | procs | dump | iat-find | fix | rebuild | tree | refs
(see SKILL.md for each op's args; this runner is a clean passthrough.)
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))

# Ops that map 1:1 to pyscylla CLI subcommands.
_OPS = {
    "version", "arch", "procs", "dump", "iat-find", "fix", "rebuild", "tree", "refs",
}


def _emit(obj: dict) -> None:
    print(json.dumps(obj, indent=2))


def main(argv: list[str]) -> int:
    if not argv[1:]:
        _emit({"ok": False, "error": "no op given",
               "ops": sorted(_OPS),
               "hint": "see SKILL.md for each op's args; e.g.  run.py procs --json"})
        return 2

    op = argv[1]
    if op in ("-h", "--help", "help"):
        _emit({"ok": True, "ops": sorted(_OPS), "note": "pass op + its args; --json forced for rekit"})
        return 0
    if op not in _OPS:
        _emit({"ok": False, "error": f"unknown op '{op}'", "ops": sorted(_OPS)})
        return 2

    # Forward to `python -m pyscylla <op> <args> --json` with scripts/ on the path.
    # Subprocess keeps the native DLL load/unload isolated per invocation.
    rest = list(argv[2:])
    if "--json" not in rest and "-j" not in rest:
        rest.append("--json")

    env = dict(os.environ)
    env["PYTHONPATH"] = _HERE + os.pathsep + env.get("PYTHONPATH", "")

    cmd = [sys.executable, "-m", "pyscylla", op, *rest]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=300, env=env,
                           cwd=_HERE)
    except subprocess.TimeoutExpired:
        _emit({"ok": False, "op": op, "error": "pyscylla timed out (live process ops can be slow)"})
        return 1
    except (OSError, subprocess.SubprocessError) as exc:
        _emit({"ok": False, "op": op, "error": f"failed to invoke pyscylla: {exc}"})
        return 1

    out = (r.stdout or "").strip()
    err = (r.stderr or "").strip()

    # Detect the DLL-not-found / arch-mismatch signature and surface it cleanly.
    if r.returncode == 127 or "libscylla DLL not found" in err or "DllNotFoundError" in err:
        _emit({"ok": False, "op": op,
               "error": "libscylla DLL not loadable — Windows + matching-arch Python required",
               "detail": err[:400],
               "hint": "x64 target → 64-bit Python + libscylla-x64.dll; x86 target → 32-bit Python + libscylla-x86.dll. "
                       "Run on Windows."})
        return 127

    # Try to surface pyscylla's own JSON object; fall back to wrapping raw output.
    if out:
        try:
            obj = json.loads(out.splitlines()[-1] if not out.startswith("{") else out)
            if isinstance(obj, dict):
                obj.setdefault("op", op)
                _emit(obj)
                return 0 if (obj.get("ok", r.returncode == 0) and r.returncode == 0) else 1
        except json.JSONDecodeError:
            pass

    _emit({"ok": r.returncode == 0, "op": op, "stdout": out[:1200],
           "stderr": err[:400] or None, "exit": r.returncode})
    return 0 if r.returncode == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))

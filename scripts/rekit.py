#!/usr/bin/env python3
"""rekit — discover, doctor, and run self-contained agent skills.

Pure stdlib. Discovery is "scan skills/*/skill.json"; there is no registry.
See ../SKILL-CONTRACT.md for the manifest shape.

    rekit list [--json]
    rekit doctor [<id>] [--json]
    rekit info <id>
    rekit run <id> [args...]
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKILLS_DIR = ROOT / "skills"
_VER_RE = re.compile(r"(\d+(?:\.\d+)*)")


def discover() -> list[dict]:
    skills = []
    if not SKILLS_DIR.is_dir():
        return skills
    for manifest in sorted(SKILLS_DIR.glob("*/skill.json")):
        try:
            data = json.loads(manifest.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            skills.append({"id": manifest.parent.name, "_dir": manifest.parent,
                           "_error": f"unreadable skill.json: {exc}"})
            continue
        data["_dir"] = manifest.parent
        skills.append(data)
    return skills


def _get(skill_id: str) -> dict:
    for s in discover():
        if s.get("id") == skill_id:
            return s
    sys.exit(f"rekit: no skill with id '{skill_id}' (try `rekit list`)")


def _parse_version(text: str) -> tuple[int, ...] | None:
    m = _VER_RE.search(text or "")
    return tuple(int(x) for x in m.group(1).split(".")) if m else None


def _cmp_version(found: tuple[int, ...], minimum: str) -> bool:
    want = tuple(int(x) for x in minimum.split("."))
    n = max(len(found), len(want))
    return tuple((*found, *([0] * n))[:n]) >= tuple((*want, *([0] * n))[:n])


def check_prereq(pre: dict) -> dict:
    """Run a prerequisite's check command; return status dict (never raises)."""
    tool = pre.get("tool", "?")
    cmd = pre.get("check") or [tool, "--version"]
    result = {"tool": tool, "min_version": pre.get("min_version"),
              "install_hint": pre.get("install_hint")}
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    except FileNotFoundError:
        return {**result, "present": False, "reason": "not found on PATH"}
    except (subprocess.SubprocessError, OSError) as exc:
        return {**result, "present": False, "reason": f"check failed: {exc}"}
    out = (proc.stdout or "") + (proc.stderr or "")
    version = _parse_version(out)
    result["version"] = ".".join(map(str, version)) if version else None
    if proc.returncode != 0:
        return {**result, "present": False, "reason": f"check exited {proc.returncode}"}
    if pre.get("min_version") and version and not _cmp_version(version, pre["min_version"]):
        return {**result, "present": False,
                "reason": f"version {result['version']} < required {pre['min_version']}"}
    return {**result, "present": True, "reason": None}


def doctor_skill(skill: dict) -> dict:
    prereqs = [check_prereq(p) for p in skill.get("prerequisites", [])]
    return {"id": skill.get("id"), "ready": all(p["present"] for p in prereqs),
            "prerequisites": prereqs, "error": skill.get("_error")}


# --- commands --------------------------------------------------------------

def cmd_list(args) -> int:
    skills = discover()
    if args.json:
        print(json.dumps([{k: v for k, v in s.items() if not k.startswith("_")}
                          for s in skills], indent=2))
        return 0
    if not skills:
        print("(no skills found under skills/)")
        return 0
    for s in skills:
        caps = ", ".join(s.get("capabilities", []))
        print(f"{s.get('id', '?'):18} {s.get('description', s.get('_error', ''))}")
        if caps:
            print(f"{'':18} capabilities: {caps}")
    return 0


def cmd_doctor(args) -> int:
    skills = discover()
    if args.id:
        skills = [_get(args.id)]
    reports = [doctor_skill(s) for s in skills]
    if args.json:
        print(json.dumps(reports, indent=2))
        return 0
    all_ready = True
    for r in reports:
        mark = "OK " if r["ready"] else "!! "
        print(f"[{mark}] {r['id']}")
        for p in r["prerequisites"]:
            if p["present"]:
                print(f"       + {p['tool']} {p.get('version') or ''}".rstrip())
            else:
                all_ready = False
                print(f"       - {p['tool']} MISSING ({p['reason']}) — {p['install_hint']}")
        if r.get("error"):
            print(f"       ! {r['error']}")
    ready = sum(1 for r in reports if r["ready"])
    print(f"\n{ready}/{len(reports)} skill(s) ready. "
          f"{'All prerequisites satisfied.' if ready == len(reports) else 'Install the missing tools above to enable the rest.'}")
    return 0 if all_ready else 1


def cmd_info(args) -> int:
    s = _get(args.id)
    print(json.dumps({k: v for k, v in s.items() if not k.startswith("_")}, indent=2))
    md = s["_dir"] / "SKILL.md"
    if md.is_file():
        print(f"\n--- {md} ---\n")
        print(md.read_text(encoding="utf-8"))
    return 0


def cmd_run(args) -> int:
    s = _get(args.id)
    report = doctor_skill(s)
    if not report["ready"]:
        missing = [p for p in report["prerequisites"] if not p["present"]]
        for p in missing:
            print(f"rekit: '{s['id']}' unavailable — {p['tool']} missing "
                  f"({p['reason']}). {p['install_hint']}", file=sys.stderr)
        print(json.dumps({"ok": False, "error": "prerequisites missing",
                          "missing": [p["tool"] for p in missing]}))
        return 3
    entry = s.get("entry", {})
    command = list(entry.get("command", []))
    if not command:
        sys.exit(f"rekit: skill '{s['id']}' has no entry.command")
    # Resolve a relative script path (command[-1] or command[1]) against the skill dir.
    skill_dir = s["_dir"]
    resolved = []
    for i, part in enumerate(command):
        p = skill_dir / part
        resolved.append(str(p) if (i > 0 and p.exists()) else part)
    argv = resolved + list(args.rest)
    # Run in the caller's cwd (NOT the skill dir) so relative input paths the user
    # passes resolve correctly. The entry command's own script path is absolutised
    # above, and each skill's runner locates its vendored deps relative to its own
    # file, so cwd doesn't matter for the skill's internals.
    try:
        proc = subprocess.run(argv)
    except FileNotFoundError as exc:
        sys.exit(f"rekit: cannot run '{s['id']}': {exc}")
    return proc.returncode


def cmd_install(args) -> int:
    targets = discover() if not args.id else [_get(args.id)]
    built = failed = skipped = 0
    for s in targets:
        build = s["_dir"] / "scripts" / "build.sh"
        if not build.is_file():
            skipped += 1
            print(f"[--] {s.get('id')}: pure-stdlib / BYO-tool — nothing to vendor")
            continue
        print(f"[..] {s.get('id')}: building runtime…")
        proc = subprocess.run(["bash", str(build)])
        if proc.returncode == 0:
            built += 1
            print(f"[ok] {s.get('id')}")
        else:
            failed += 1
            print(f"[!!] {s.get('id')}: build failed (exit {proc.returncode})")
    print(f"\n{built} built, {skipped} nothing-to-build, {failed} failed.")
    return 0 if failed == 0 else 1


def cmd_caps(args) -> int:
    caps: dict = {}
    for s in discover():
        for c in s.get("capabilities", []):
            caps.setdefault(c, []).append(s.get("id"))
    if args.json:
        print(json.dumps({k: sorted(v) for k, v in sorted(caps.items())}, indent=2))
        return 0
    for c in sorted(caps):
        print(f"{c:28} {', '.join(sorted(caps[c]))}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="rekit", description="self-contained agent skills")
    sub = p.add_subparsers(dest="cmd", required=True)

    lst = sub.add_parser("list", help="list discovered skills")
    lst.add_argument("--json", action="store_true")
    lst.set_defaults(func=cmd_list)

    doc = sub.add_parser("doctor", help="check skill prerequisites")
    doc.add_argument("id", nargs="?")
    doc.add_argument("--json", action="store_true")
    doc.set_defaults(func=cmd_doctor)

    info = sub.add_parser("info", help="print a skill manifest + SKILL.md")
    info.add_argument("id")
    info.set_defaults(func=cmd_info)

    run = sub.add_parser("run", help="run a skill (checks prereqs first)")
    run.add_argument("id")
    run.add_argument("rest", nargs=argparse.REMAINDER,
                     help="arguments passed through to the skill")
    run.set_defaults(func=cmd_run)

    inst = sub.add_parser("install", help="vendor skill runtimes (run each build.sh)")
    inst.add_argument("id", nargs="?", help="one skill id, or omit for all")
    inst.set_defaults(func=cmd_install)

    caps = sub.add_parser("caps", help="capability → skills index")
    caps.add_argument("--json", action="store_true")
    caps.set_defaults(func=cmd_caps)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())

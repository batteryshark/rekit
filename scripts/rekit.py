#!/usr/bin/env python3
"""rekit — discover, doctor, and run self-contained agent skills.

Pure stdlib. Skill manifests live in ONE central registry, ../registry.json, keyed by
skill id; each skills/<id>/ dir holds the SKILL.md doc (name + description frontmatter)
+ the runner. Discovery = read the registry and pair each entry with its directory.
See ../SKILL-CONTRACT.md for the manifest shape.

    rekit list [--json]
    rekit search <query> [--capability C] [--tier N] [--dynamic|--static] [--json]
    rekit doctor [<id>] [--json]
    rekit info <id>
    rekit run <id> [args...]
    rekit install [<id>]
    rekit setup [--platform macos|linux|windows] [--tier base|build|recommended|all] [--json]
    rekit sync-docs [--check]
    rekit caps [--json]
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKILLS_DIR = ROOT / "skills"
REGISTRY_FILE = ROOT / "registry.json"
REQUIREMENTS_FILE = ROOT / "requirements.json"
_VER_RE = re.compile(r"(\d+(?:\.\d+)*)")
TIERS = ("base", "build", "recommended")


def _load_registry() -> dict:
    """The central manifest, ../registry.json: {id: {name, description, capabilities,
    kind, prerequisites, safety, entry, ...}}. Fail clearly rather than tracebacking."""
    try:
        data = json.loads(REGISTRY_FILE.read_text(encoding="utf-8"))
    except FileNotFoundError:
        sys.exit(f"rekit: registry not found at {REGISTRY_FILE}")
    except (json.JSONDecodeError, OSError) as exc:
        sys.exit(f"rekit: unreadable registry.json: {exc}")
    if not isinstance(data, dict):
        sys.exit("rekit: registry.json must be a JSON object keyed by skill id")
    return data


def discover() -> list[dict]:
    """Read the central registry and pair each entry with its skills/<id>/ dir. A
    registry entry whose directory is missing is surfaced with an `_error` (honest
    degradation), never silently dropped."""
    skills = []
    registry = _load_registry()
    for sid in sorted(registry):
        d = SKILLS_DIR / sid
        data = dict(registry[sid])
        data["id"] = sid
        data["_dir"] = d
        if not d.is_dir():
            data["_error"] = f"registry entry '{sid}' has no directory (skills/{sid}/)"
        skills.append(data)
    return skills


def _registry_drift() -> tuple[list[str], list[str]]:
    """(orphan_dirs, missing_dirs): skill dirs holding a SKILL.md that are absent from
    the registry, and registry ids whose directory is missing. The trade-off of a
    central registry — surfaced loudly by `doctor` so drift can't hide."""
    registry = _load_registry()
    dirs = {p.name for p in SKILLS_DIR.iterdir()
            if p.is_dir() and (p / "SKILL.md").is_file()} if SKILLS_DIR.is_dir() else set()
    return sorted(dirs - set(registry)), sorted(set(registry) - dirs)


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


# --- rekit's own requirements (base/build/recommended) --------------------
# Distinct from per-skill prerequisites: these are what rekit ITSELF needs to run
# (base) / to vendor skill runtimes (build) / to be a nice analysis workstation
# (recommended). Same check/min_version schema as a skill prereq, so check_prereq()
# handles them unchanged. See ../requirements.json.

def load_requirements() -> dict[str, list[dict]]:
    """Load rekit's own requirements.json. Returns {} if absent/unreadable (older
    installs / partial checkouts); never raises."""
    if not REQUIREMENTS_FILE.is_file():
        return {}
    try:
        data = json.loads(REQUIREMENTS_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}
    return {t: data.get(t, []) for t in TIERS}


def _detect_platform(override: str | None = None) -> str:
    """macos / linux / windows. Override wins; anything unknown falls back to linux."""
    if override:
        return override
    sysname = platform.system()
    if sysname == "Darwin":
        return "macos"
    if sysname == "Windows":
        return "windows"
    return "linux"  # Linux and any other unix


def check_tier(entries: list[dict]) -> list[dict]:
    """check_prereq over a tier's entries; carry through `install`/`why`/`builds`
    so callers can render install hints without re-reading the manifest."""
    out = []
    for pre in entries:
        res = check_prereq(pre)
        res["install"] = pre.get("install") or {}
        res["why"] = pre.get("why")
        res["builds"] = pre.get("builds")
        out.append(res)
    return out


# --- commands --------------------------------------------------------------

def _marker(skill: dict) -> str:
    """Tier glyph: ⚡ DYNAMIC (executes the target) · 🔨 CONSTRUCT (produces an artifact)."""
    if (skill.get("safety") or {}).get("executes_input") == "full":
        return "⚡ "
    if skill.get("kind") == "construct":
        return "🔨 "
    return ""


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
        print(f"{s.get('id', '?'):18} {_marker(s)}{s.get('description', s.get('_error', ''))}")
        if caps:
            print(f"{'':18} capabilities: {caps}")
    return 0


def cmd_doctor(args) -> int:
    show_base = not args.id  # the full doctor also reports rekit's own requirements
    tier_reports = None
    if show_base:
        reqs = load_requirements()
        tier_reports = {t: check_tier(reqs.get(t, [])) for t in TIERS}

    skills = discover()
    if args.id:
        skills = [_get(args.id)]
    reports = [doctor_skill(s) for s in skills]

    if args.json:
        # targeted: keep the existing single-element-list shape. full: wrap with the
        # rekit-level tiers so a caller gets base/build/recommended + skills at once.
        if show_base:
            payload = {"base": tier_reports["base"], "build": tier_reports["build"],
                       "recommended": tier_reports["recommended"], "skills": reports}
            print(json.dumps(payload, indent=2))
        else:
            print(json.dumps(reports, indent=2))
        return 0

    all_ready = True
    if tier_reports is not None:
        plat = _detect_platform()
        print(f"rekit requirements (this machine: {plat})\n")
        labels = {
            "base": "BASE",
            "build": "BUILD  (advisory — needed by `rekit install`)",
            "recommended": "RECOMMENDED  (advisory — agent/workstation niceties)",
        }
        for t in TIERS:
            print(f"  {labels[t]}")
            for p in tier_reports[t]:
                if p["present"]:
                    print(f"    + {p['tool']} {p.get('version') or ''}".rstrip())
                else:
                    line = f"    - {p['tool']} MISSING"
                    if p.get("reason"):
                        line += f" ({p['reason']})"
                    print(line)
                    cmd = (p.get("install") or {}).get(plat)
                    if cmd:
                        print(f"        {cmd}")
            print()
        print("--- skills ---")

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
    if show_base:
        orphans, missing = _registry_drift()
        if orphans or missing:
            print("\nregistry drift:")
            for sid in orphans:
                print(f"  ! skills/{sid}/ has a SKILL.md but no registry.json entry (unregistered)")
            for sid in missing:
                print(f"  ! registry.json lists '{sid}' but skills/{sid}/ is missing")
            print("  run `rekit sync-docs` after fixing registry.json to re-sync SKILL.md frontmatter.")
        print("Tip: `rekit setup [--tier all]` prints install commands for missing base/build/recommended tools.")
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
    # Dynamic-tier consent gate: a skill that EXECUTES the target requires explicit
    # opt-in. Isolation is a separate, optional axis — native is fine on a box you don't
    # mind risking; bind an isolation provider when you want one. Consent, not a gate.
    executes = (s.get("safety") or {}).get("executes_input", "no")
    if executes == "full" and not getattr(args, "allow_dynamic", False):
        print(f"rekit: '{s['id']}' is a DYNAMIC skill — it EXECUTES the target, not just "
              f"reads it.\n       Re-run with --allow-dynamic to consent. Run dynamic skills "
              f"only where you don't mind the risk (a disposable VM or a dedicated analysis "
              f"box), or bind an isolation provider.", file=sys.stderr)
        print(json.dumps({"ok": False, "error": "dynamic skill requires consent",
                          "executesInput": executes, "hint": "re-run with --allow-dynamic"}))
        return 4
    if executes == "full":
        print(f"rekit: ⚡ DYNAMIC — executing target via '{s['id']}'.", file=sys.stderr)

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
    # Pass consent through to a dynamic runner (so it doesn't double-gate).
    env = {**os.environ, "REKIT_ALLOW_DYNAMIC": "1"} if executes == "full" else None
    try:
        proc = subprocess.run(argv, env=env)
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


def cmd_setup(args) -> int:
    """Print (never run) install commands for MISSING tools in the chosen tier(s).
    Output is valid shell — comments carry the why — so it's copy-pasteable AND
    pipeable: `rekit setup --tier all | bash`. We do NOT auto-run package managers:
    they need sudo, differ wildly across OSes, and rekit avoids surprise on a box used
    for hostile input. See ../docs/PLATFORMS.md."""
    reqs = load_requirements()
    if not reqs:
        sys.exit("rekit: requirements.json not found or unreadable "
                 "(rekit install predates it?)")
    plat = _detect_platform(args.platform)
    tiers_wanted = list(TIERS) if args.tier == "all" else [args.tier]

    # collect missing tools, preserving tier order
    missing: list[tuple[str, str, str | None, str | None]] = []
    for t in tiers_wanted:
        for p in check_tier(reqs.get(t, [])):
            if not p["present"]:
                cmd = (p.get("install") or {}).get(plat)
                missing.append((t, p["tool"], cmd, p.get("why")))

    if args.json:
        by_tier = {t: [] for t in tiers_wanted}
        for (t, tool, cmd, _why) in missing:
            by_tier[t].append({"tool": tool, "present": False, "command": cmd})
        print(json.dumps({"platform": plat, "tier": args.tier,
                          "tiers": [{"name": t, "tools": by_tier[t]} for t in tiers_wanted]},
                         indent=2))
        return 0

    if plat == "windows":
        print("# rekit targets macOS and Linux. On Windows, run the commands below")
        print("# inside WSL2 (dynamic skills need Unix tracers anyway).\n")
    print(f"# rekit setup — platform: {plat}, tier: {args.tier}")
    print("# commands are PRINTED, not run. Review and run what you want, or pipe:")
    print(f"#     rekit setup --tier all | bash\n")
    if not missing:
        print(f"# nothing missing at tier '{args.tier}' on {plat}. All set.")
        return 0

    by_tier: dict[str, list] = {}
    for (t, tool, cmd, why) in missing:
        by_tier.setdefault(t, []).append((tool, cmd, why))
    for t in tiers_wanted:
        items = by_tier.get(t, [])
        if not items:
            continue
        print(f"# --- {t} ---")
        for (tool, cmd, why) in items:
            if why:
                print(f"# {tool} — {why}")
            if cmd:
                print(cmd)
            else:
                print(f"# (no install command recorded for {tool} on {plat})")
        print()
    print(f"# {len(missing)} tool(s) missing at tier '{args.tier}'. "
          f"Run `rekit doctor` after installing to confirm.")
    return 0


_WORD_RE = re.compile(r"[a-z0-9]+")


def _tokens(text: str) -> list[str]:
    return _WORD_RE.findall((text or "").lower())


def _score(skill: dict, qtokens: list[str]) -> tuple[int, list[str]]:
    """Keyword relevance of a skill to the query. Field-weighted substring match — no
    embeddings, no index; scales fine to hundreds of skills and stays dependency-free."""
    caps = [c.lower() for c in skill.get("capabilities", [])]
    tools = [(p.get("tool") or "").lower() for p in skill.get("prerequisites", [])]
    # (weight, why-label, haystack)
    fields = [
        (6, "capability", " ".join(caps)),
        (4, "id", (skill.get("id") or "").lower()),
        (3, "name", (skill.get("name") or "").lower()),
        (2, "prereq", " ".join(tools)),
        (1, "description", (skill.get("description") or "").lower()),
    ]
    score, why = 0, []
    for weight, label, hay in fields:
        if any(t in hay for t in qtokens):
            score += weight * sum(1 for t in qtokens if t in hay)
            why.append(label)
    # whole-query bonus when it lands inside one capability (e.g. "decompile" → *-decompile)
    joined = "".join(qtokens)
    if joined and any(joined in c.replace("-", "") for c in caps):
        score += 3
        if "capability" not in why:
            why.append("capability")
    return score, why


def cmd_search(args) -> int:
    qtokens = _tokens(args.query)
    if not qtokens:
        sys.exit("rekit: empty query")
    hits = []
    for s in discover():
        if s.get("_error"):
            continue
        safety = s.get("safety") or {}
        exec_in = safety.get("executes_input", "no")
        tier = safety.get("tier")
        kind = s.get("kind", "analyze")
        if args.capability and args.capability not in (s.get("capabilities") or []):
            continue
        if args.dynamic and exec_in != "full":
            continue
        if args.static and exec_in == "full":
            continue
        if args.construct and kind != "construct":
            continue
        if args.analyze and kind == "construct":
            continue
        if args.tier is not None and isinstance(tier, int) and tier > args.tier:
            continue
        score, why = _score(s, qtokens)
        if score > 0:
            hits.append((score, why, s))
    hits.sort(key=lambda x: (-x[0], x[2].get("id", "")))
    hits = hits[: args.limit]
    if args.json:
        print(json.dumps([{"id": s.get("id"), "score": sc, "matched": why,
                           "description": s.get("description"),
                           "capabilities": s.get("capabilities", []),
                           "executesInput": (s.get("safety") or {}).get("executes_input", "no")}
                          for sc, why, s in hits], indent=2))
        return 0 if hits else 1
    if not hits:
        print(f"no skills match '{args.query}'. Try `rekit caps` for the capability index.")
        return 1
    for sc, why, s in hits:
        print(f"{s.get('id', ''):20} {_marker(s)}{s.get('description', '')}")
        print(f"{'':20} · match: {', '.join(why)}  (score {sc})")
    print(f"\n{len(hits)} result(s). `rekit info <id>` for details · `rekit run <id> …` to use.")
    return 0


def _project_frontmatter(sid: str, entry: dict) -> str:
    """The name+description frontmatter a SKILL.md must carry, derived from its
    registry entry. `name` == the id; `description` is the registry description with
    angle brackets stripped and quotes/backslashes escaped for a YAML double-quoted
    scalar."""
    desc = (entry.get("description") or "").replace("<", "").replace(">", "")
    dq = '"' + desc.replace("\\", "\\\\").replace('"', '\\"') + '"'
    return f"---\nname: {sid}\ndescription: {dq}\n---\n"


def cmd_sync_docs(args) -> int:
    """Regenerate (or --check) each SKILL.md's name+description frontmatter from the
    registry — registry.json is the source of truth, frontmatter is a synced projection."""
    registry = _load_registry()
    changed = []
    for sid in sorted(registry):
        md = SKILLS_DIR / sid / "SKILL.md"
        if not md.is_file():
            continue
        text = md.read_text(encoding="utf-8")
        body = text
        if text.startswith("---"):  # drop the existing frontmatter, keep the body
            lines = text.splitlines(keepends=True)
            end = next((i for i in range(1, len(lines)) if lines[i].strip() == "---"), None)
            if end is not None:
                body = "".join(lines[end + 1:])
        new_text = _project_frontmatter(sid, registry[sid]) + (body if body.startswith("\n") else "\n" + body)
        if new_text != text:
            changed.append(sid)
            if not args.check:
                md.write_text(new_text, encoding="utf-8")
    if args.check:
        if changed:
            print("out of sync with registry.json: " + ", ".join(changed))
            return 1
        print("all SKILL.md frontmatter in sync with registry.json")
        return 0
    print(f"synced {len(changed)} SKILL.md frontmatter block(s)" +
          (f": {', '.join(changed)}" if changed else " (all already in sync)"))
    return 0


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


def cmd_mcp(args) -> int:
    """Serve the skill catalog over MCP (JSON-RPC over stdio). Thin hook into
    scripts/rekit_mcp.py, which is a pure-stdlib export adapter: one MCP tool per
    skill, each tool call is literally `rekit run <id> <args>` (same prereq +
    dynamic-consent gates as the CLI). Import is deferred so `rekit list` etc.
    never pay for it. See docs/POSITIONING.md §6."""
    import importlib
    # rekit_mcp.py is a sibling module; ensure this dir is importable.
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    mcp = importlib.import_module("rekit_mcp")
    return mcp.serve(allow_dynamic=args.allow_dynamic, prefix=args.prefix,
                     timeout=args.timeout)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="rekit", description="self-contained agent skills")
    sub = p.add_subparsers(dest="cmd", required=True)

    lst = sub.add_parser("list", help="list discovered skills")
    lst.add_argument("--json", action="store_true")
    lst.set_defaults(func=cmd_list)

    srch = sub.add_parser("search", help="find skills by keyword / capability")
    srch.add_argument("query", help="free text — matched against id, name, capabilities, prereq tools, description")
    srch.add_argument("--capability", help="require this exact capability")
    srch.add_argument("--tier", type=int, help="only skills at or below this safety tier")
    srch.add_argument("--dynamic", action="store_true", help="only DYNAMIC skills (execute the target)")
    srch.add_argument("--static", action="store_true", help="exclude DYNAMIC skills")
    srch.add_argument("--construct", action="store_true", help="only CONSTRUCT skills (produce artifacts)")
    srch.add_argument("--analyze", action="store_true", help="exclude CONSTRUCT skills")
    srch.add_argument("--limit", type=int, default=12, help="max results (default 12)")
    srch.add_argument("--json", action="store_true")
    srch.set_defaults(func=cmd_search)

    doc = sub.add_parser("doctor", help="check skill prerequisites")
    doc.add_argument("id", nargs="?")
    doc.add_argument("--json", action="store_true")
    doc.set_defaults(func=cmd_doctor)

    info = sub.add_parser("info", help="print a skill manifest + SKILL.md")
    info.add_argument("id")
    info.set_defaults(func=cmd_info)

    run = sub.add_parser("run", help="run a skill (checks prereqs first)")
    run.add_argument("--allow-dynamic", action="store_true",
                     help="consent to run a DYNAMIC skill (one that EXECUTES the target)")
    run.add_argument("id")
    run.add_argument("rest", nargs=argparse.REMAINDER,
                     help="arguments passed through to the skill")
    run.set_defaults(func=cmd_run)

    inst = sub.add_parser("install", help="vendor skill runtimes (run each build.sh)")
    inst.add_argument("id", nargs="?", help="one skill id, or omit for all")
    inst.set_defaults(func=cmd_install)

    setup = sub.add_parser("setup",
                           help="print install commands for missing base/build/recommended tools (never runs them)")
    setup.add_argument("--platform", choices=["macos", "linux", "windows"],
                       help="target platform (default: auto-detect)")
    setup.add_argument("--tier", choices=["base", "build", "recommended", "all"],
                       default="base", help="which tier to cover (default: base)")
    setup.add_argument("--json", action="store_true")
    setup.set_defaults(func=cmd_setup)

    caps = sub.add_parser("caps", help="capability → skills index")
    caps.add_argument("--json", action="store_true")
    caps.set_defaults(func=cmd_caps)

    syncd = sub.add_parser("sync-docs",
                           help="regenerate each SKILL.md name+description frontmatter from registry.json")
    syncd.add_argument("--check", action="store_true",
                       help="exit 1 if any SKILL.md frontmatter is out of sync (write nothing)")
    syncd.set_defaults(func=cmd_sync_docs)

    # Export surface: expose the whole catalog as ONE MCP server (one tool per
    # skill, schemas from entry.args). This is rekit speaking MCP as an output;
    # it is not an MCP client and does not host third-party servers. See
    # docs/POSITIONING.md §6. The long-lived server loop lives in rekit_mcp.py.
    mcp = sub.add_parser("mcp",
                         help="serve the skill catalog over MCP (one tool per skill)")
    mcp.add_argument("--allow-dynamic", action="store_true",
                     help="consent to ⚡ dynamic skills (mirrors `rekit run --allow-dynamic`)")
    mcp.add_argument("--prefix", default="", metavar="STR",
                     help="namespace tool names (e.g. 'rk_' → rk_hex-view)")
    mcp.add_argument("--timeout", type=int, default=600, metavar="SEC",
                     help="per-call cap in seconds (default 600)")
    mcp.set_defaults(func=cmd_mcp)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())

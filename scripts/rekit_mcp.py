#!/usr/bin/env python3
"""rekit mcp — expose the rekit skill catalog as a single MCP server.

A read-only, **transport-stateless export adapter**: every rekit skill becomes one MCP
tool (JSON Schema derived from `entry.args`; safety + consent carried through).
This is rekit speaking MCP as an *output* surface only — it is NOT an MCP
*client*, and it does not host third-party MCP servers. A skill may persist state in
an explicit caller-owned path (for example `emulation-session`); the adapter itself
does not retain hidden process state between calls.

Pure stdlib (rekit's rule). JSON-RPC 2.0 over newline-delimited stdio.

Execution model: a tool call is literally `rekit run <id> <args>` under the hood
(the same path a shell user takes), so availability checks, the dynamic-tier
consent gate, and path resolution are IDENTICAL to the CLI — zero drift. This
adapter is purely a transport + schema layer. We never import rekit.py; we talk
to the `rekit` binary via subprocess, so the adapter is decoupled from the
dispatcher's internals.

    rekit mcp                       # start the server (dynamic skills gated)
    rekit mcp --allow-dynamic       # enable ⚡ dynamic skills (consent)
    rekit mcp --prefix rk_          # namespace tool names (e.g. rk_hex-view)
    rekit mcp --timeout 900         # per-call cap (default 600s)

Tool shape (one per skill):
  name        = prefix + skill id            (e.g. "hex-view", "rk_hex-view")
  description = tier glyph + skill.description + (unavailable | dynamic-consent note)
  inputSchema = JSON object built from entry.args:
                  positional args (input/dir/path/...) -> required string props
                  --opt int                      -> integer
                  --opt str                      -> string
                  --opt enum                     -> string w/ enum (choices from
                                                   the metadata "choices" or parsed
                                                   from desc "a | b | c")
                  --opt flag                     -> boolean (true => bare switch)
A call appends positionals (declared order) then options, auto-injects
`--format json` when the skill supports json and the caller didn't set format,
and returns the skill's stdout as MCP text content (isError on nonzero exit).
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

PROTOCOL_VERSION = "2025-06-18"
SERVER_NAME = "rekit"
SERVER_VERSION = "0.1.0"
DEFAULT_TIMEOUT = 600  # seconds per tool call

# rekit.py lives next to this file; bin/rekit is one dir up. Prefer an explicit
# override (REKIT_BIN) so a harness can pin a specific checkout.
_HERE = Path(__file__).resolve().parent
_REKIT_BIN_DEFAULT = _HERE.parent / "bin" / "rekit"


class UserError(Exception):
    """A bad tool call (missing arg, bad type). Surfaces as an MCP error result."""


# --- locate the rekit binary -------------------------------------------------

def find_rekit() -> str:
    env = os.environ.get("REKIT_BIN")
    if env and Path(env).is_file():
        return env
    if _REKIT_BIN_DEFAULT.is_file():
        return str(_REKIT_BIN_DEFAULT)
    # last resort: hope `rekit` is on PATH
    return "rekit"


# --- catalog + doctor (via the CLI, never by importing the dispatcher) -------

def _rekit_run_json(args: list[str]) -> Any:
    """Run a rekit subcommand that prints JSON; return parsed object."""
    proc = subprocess.run([find_rekit(), *args],
                          capture_output=True, text=True, timeout=120)
    try:
        return json.loads(proc.stdout or "null")
    except json.JSONDecodeError:
        return None


def load_catalog() -> list[dict]:
    data = _rekit_run_json(["list", "--json"])
    return data if isinstance(data, list) else []


def load_doctor() -> dict[str, dict]:
    """skill id -> {ready, missing:[tool,...]} for honest-degradation annotation."""
    data = _rekit_run_json(["doctor", "--json"])
    out: dict[str, dict] = {}
    skills = data.get("skills") if isinstance(data, dict) else data
    if isinstance(skills, list):
        for r in skills:
            if isinstance(r, dict) and r.get("id"):
                out[r["id"]] = {
                    "ready": bool(r.get("ready", False)),
                    "missing": [p.get("tool") for p in r.get("prerequisites", [])
                                if not p.get("present")],
                }
    return out


# --- skill -> MCP tool mapping ----------------------------------------------

def _marker(skill: dict) -> str:
    if (skill.get("safety") or {}).get("executes_input") == "full":
        return "⚡ "
    if skill.get("kind") == "construct":
        return "🔨 "
    return ""


def _prop_name(arg_name: str) -> str:
    """Schema property name: leading dashes stripped ('--format' -> 'format')."""
    return arg_name.lstrip("-")


def _parse_choices(desc: str) -> list[str] | None:
    """Best-effort: turn 'text | json' or 'exe | obj | asm | ir' into an enum.
    Conservative — only clean pipe-lists of lowercase tokens. Long term, skills
    should declare a 'choices' field; we prefer that when present."""
    m = re.search(r"\b([a-z][a-z0-9]*)(?:\s*\|\s*([a-z][a-z0-9]*))+\b", desc or "")
    if not m:
        return None
    parts = [p.strip() for p in m.group(0).split("|")]
    if 2 <= len(parts) <= 6 and all(re.fullmatch(r"[a-z][a-z0-9]*", p) for p in parts):
        return parts
    return None


def _arg_schema(a: dict) -> dict:
    t = a.get("type", "str")
    desc = a.get("desc", "")
    if t == "flag":
        return {"type": "boolean", "description": desc}
    schema: dict = {"description": desc}
    if t == "int":
        schema["type"] = "integer"
    else:  # file, dir, path, str, enum
        schema["type"] = "string"
    choices = a.get("choices") or _parse_choices(desc)
    if choices:
        schema["enum"] = choices
    return schema


def _variants(key: str) -> list[str]:
    """Lookup keys to try for an MCP argument (model may camelCase things)."""
    v = [key]
    snake = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", key).lower()
    camel = re.sub(r"_(.)", lambda m: m.group(1).upper(), key)
    for alt in (snake, camel):
        if alt not in v:
            v.append(alt)
    return v


def skill_to_tool(skill: dict, prefix: str, status: dict | None,
                  allow_dynamic: bool) -> dict | None:
    """Map one skill to an MCP tool definition, or None to hide it."""
    sid = skill.get("id")
    effective = skill.get("effectiveManifest")
    if not sid or skill.get("authorityError") or not isinstance(effective, dict) \
            or not effective.get("digest"):
        return None
    entry = skill.get("entry") or {}
    args = entry.get("args") or []
    properties: dict[str, Any] = {}
    required: list[str] = []
    for a in args:
        pname = _prop_name(a["name"])
        properties[pname] = _arg_schema(a)
        if a.get("required") and not a["name"].startswith("-"):
            required.append(pname)

    desc = _marker(skill) + (skill.get("description") or "")
    safety = skill.get("safety") or {}
    executes = safety.get("executes_input", "no")

    # honest degradation: annotate availability (but still gate at call time)
    if status and not status.get("ready", True):
        missing = ", ".join(filter(None, status.get("missing") or []))
        desc += f"\n\n[unavailable on this host — missing requirement(s): {missing}. " \
                f"Install them, then restart this server.]"
    # dynamic skills are listed but consent-gated unless the server was started
    # with --allow-dynamic (mirrors `rekit run` refusing without the flag)
    if executes == "full":
        if allow_dynamic:
            desc += "\n\n[⚡ DYNAMIC — EXECUTES the target. This server was started " \
                    "with --allow-dynamic, so calls are consented. Run only where " \
                    "you don't mind the risk.]"
        else:
            desc += "\n\n[⚡ DYNAMIC — EXECUTES the target. GATED: calls return an " \
                    "error until this server is restarted with --allow-dynamic.]"

    return {
        "name": prefix + sid,
        "description": desc,
        "inputSchema": {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "properties": properties,
            "required": required,
        },
        # rekit-private metadata so tools/call can find the skill by id
        "_rekit_skill_id": sid,
        "_rekit_executes_input": executes,
        "_rekit_manifest_digest": effective["digest"],
    }


# --- reconstruct `rekit run` argv from a tool call --------------------------

def _lookup(arguments: dict, arg_name: str) -> Any:
    key = _prop_name(arg_name)
    for k in _variants(key):
        if k in arguments:
            return arguments[k]
    return None


def build_call_args(skill: dict, arguments: dict) -> list[str]:
    """Turn MCP named arguments into the positional + flag argv `rekit run` wants."""
    arguments = arguments or {}
    entry = skill.get("entry") or {}
    args = entry.get("args") or []
    positionals = [a for a in args if not a["name"].startswith("-")]
    options = [a for a in args if a["name"].startswith("-")]
    out: list[str] = []

    for a in positionals:
        val = _lookup(arguments, a["name"])
        if val is None:
            if a.get("required"):
                raise UserError(f"missing required argument '{a['name']}'")
            continue
        out.append(str(val))

    saw_format = False
    for a in options:
        t = a.get("type")
        val = _lookup(arguments, a["name"])
        if a["name"] == "--format":
            saw_format = val is not None
        if t == "flag":
            if val:  # truthy -> bare switch
                out.append(a["name"])
            continue
        if val is not None:
            out.append(a["name"])
            out.append(str(val))

    # give MCP consumers structured output by default when the skill can do JSON
    if not saw_format and any(a["name"] == "--format" for a in options):
        choices = next((a.get("choices") or _parse_choices(a.get("desc", ""))
                        for a in options if a["name"] == "--format"), None)
        if choices is None or "json" in choices:
            out += ["--format", "json"]
    return out


# --- execute a tool call -----------------------------------------------------

def run_skill(rekit_bin: str, skill_id: str, call_args: list[str],
              allow_dynamic: bool, timeout: int) -> dict:
    argv = [rekit_bin, "run"]
    if allow_dynamic:
        argv.append("--allow-dynamic")
    argv += [skill_id, *call_args]
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"isError": True,
                "content": [{"type": "text",
                             "text": f"rekit: tool call timed out after {timeout}s"}]}
    stdout = (proc.stdout or "").rstrip()
    stderr = (proc.stderr or "").rstrip()
    text = stdout
    if proc.returncode != 0:
        # surface the dispatcher's/helpful stderr (prereq-missing / consent gate)
        extra = stderr or f"(rekit run exited {proc.returncode} with no stderr)"
        text = f"{stdout}\n--- stderr ---\n{extra}" if stdout else extra
    return {"isError": proc.returncode != 0,
            "content": [{"type": "text", "text": text}]}


# --- JSON-RPC 2.0 over stdio ------------------------------------------------

class Server:
    def __init__(self, *, allow_dynamic: bool, prefix: str, timeout: int):
        self.allow_dynamic = allow_dynamic
        self.prefix = prefix
        self.timeout = timeout
        self.rekit = find_rekit()
        self.tools: list[dict] = []
        self.by_name: dict[str, dict] = {}
        self._refresh()

    def _refresh(self) -> None:
        doctor = load_doctor()
        self.tools = []
        self.by_name = {}
        for skill in load_catalog():
            if isinstance(skill, dict) and skill.get("id") and skill.get("entry"):
                tool = skill_to_tool(skill, self.prefix, doctor.get(skill["id"]),
                                     self.allow_dynamic)
                if tool:
                    self.tools.append(tool)
                    self.by_name[tool["name"]] = tool

    def _skill_by_tool(self, name: str) -> dict | None:
        tool = self.by_name.get(name)
        if not tool:
            return None
        sid = tool.get("_rekit_skill_id")
        for s in load_catalog():
            if isinstance(s, dict) and s.get("id") == sid:
                return s
        return None

    # -- request handlers ----------------------------------------------------

    def initialize(self, params: dict) -> dict:
        return {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
        }

    def list_tools(self, params: dict) -> dict:
        # strip rekit-private keys before exposing
        clean = []
        for t in self.tools:
            clean.append({k: v for k, v in t.items() if not k.startswith("_rekit")})
        return {"tools": clean}

    def call_tool(self, params: dict) -> dict:
        name = params.get("name")
        arguments = params.get("arguments") or {}
        tool = self.by_name.get(name)
        if not tool:
            raise UserError(f"unknown tool '{name}'")
        executes = tool.get("_rekit_executes_input", "no")
        if executes == "full" and not self.allow_dynamic:
            return {
                "isError": True,
                "content": [{"type": "text", "text":
                    "rekit: this is a DYNAMIC skill (it EXECUTES the target). "
                    "It is consent-gated. Restart this MCP server with "
                    "`rekit mcp --allow-dynamic` to consent, and run it only "
                    "where you don't mind the risk (a disposable VM or dedicated "
                    "analysis box), or behind an isolation provider."}],
            }
        skill = self._skill_by_tool(name)
        if not skill:
            raise UserError(f"skill for tool '{name}' not found in catalog")
        effective = skill.get("effectiveManifest")
        if skill.get("authorityError") or not isinstance(effective, dict) \
                or effective.get("digest") != tool.get("_rekit_manifest_digest"):
            return {"isError": True, "content": [{"type": "text", "text":
                    "rekit: manifest authority is invalid or changed; refresh the "
                    "catalog and review the effective contract before dispatch"}]}
        try:
            call_args = build_call_args(skill, arguments)
        except UserError as e:
            return {"isError": True,
                    "content": [{"type": "text", "text": f"rekit: {e}"}]}
        return run_skill(self.rekit, tool["_rekit_skill_id"], call_args,
                         self.allow_dynamic, self.timeout)

    # -- dispatch ------------------------------------------------------------

    def handle(self, msg: dict) -> dict | None:
        method = msg.get("method")
        rid = msg.get("id")
        is_request = rid is not None
        params = msg.get("params") or {}

        if method == "initialize":
            result = self.initialize(params)
        elif method == "notifications/initialized":
            return None  # notification — no response
        elif method == "tools/list":
            result = self.list_tools(params)
        elif method == "tools/call":
            try:
                result = self.call_tool(params)
            except UserError as e:
                if not is_request:
                    return None
                return {"jsonrpc": "2.0", "id": rid,
                        "error": {"code": -32602, "message": str(e)}}
        elif method == "ping":
            result = {}
        else:
            if not is_request:
                return None
            return {"jsonrpc": "2.0", "id": rid,
                    "error": {"code": -32601, "message": f"method not found: {method}"}}

        if not is_request:
            return None
        return {"jsonrpc": "2.0", "id": rid, "result": result}


def _send(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def serve(*, allow_dynamic: bool, prefix: str, timeout: int) -> int:
    server = Server(allow_dynamic=allow_dynamic, prefix=prefix, timeout=timeout)
    for raw in sys.stdin:
        raw = raw.strip()
        if not raw:
            continue
        try:
            msg = json.loads(raw)
        except json.JSONDecodeError:
            continue  # ignore malformed lines
        if not isinstance(msg, dict):
            continue
        try:
            reply = server.handle(msg)
        except Exception as exc:  # never kill the server on a bad call
            rid = msg.get("id") if isinstance(msg, dict) else None
            if rid is not None:
                _send({"jsonrpc": "2.0", "id": rid,
                       "error": {"code": -32603, "message": f"internal error: {exc}"}})
            continue
        if reply is not None:
            _send(reply)
    return 0


def main(argv: list[str]) -> int:
    import argparse
    p = argparse.ArgumentParser(prog="rekit mcp",
                                description="Expose the rekit skill catalog as an MCP server.")
    p.add_argument("--allow-dynamic", action="store_true",
                   help="consent to ⚡ dynamic skills (mirrors `rekit run --allow-dynamic`)")
    p.add_argument("--prefix", default="", metavar="STR",
                   help="namespace tool names (e.g. 'rk_' -> rk_hex-view)")
    p.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, metavar="SEC",
                   help=f"per-call cap in seconds (default {DEFAULT_TIMEOUT})")
    a = p.parse_args(argv)
    return serve(allow_dynamic=a.allow_dynamic, prefix=a.prefix, timeout=a.timeout)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

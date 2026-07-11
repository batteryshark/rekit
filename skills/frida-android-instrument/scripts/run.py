"""Bounded, observation-only Java instrumentation for authorized Android apps."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


EVENT_PREFIX = "REKIT_ANDROID_EVENT="
ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


def _consented(args: argparse.Namespace) -> bool:
    return args.yes_i_consent or os.environ.get("REKIT_ALLOW_DYNAMIC") == "1"


def _js(value: object) -> str:
    return json.dumps(value, ensure_ascii=False)


def build_agent(
    mode: str,
    class_name: str | None = None,
    method: str | None = None,
    match: str = "",
    max_events: int = 200,
    max_value: int = 256,
) -> str:
    """Generate a Frida CLI agent. Java is supplied by the Frida REPL runtime."""
    header = f"""
const PREFIX = {_js(EVENT_PREFIX)};
const MAX_EVENTS = {max_events};
const MAX_VALUE = {max_value};
let emitted = 0;
function emit(value) {{
  if (emitted >= MAX_EVENTS && value.kind !== 'done') return;
  if (value.kind !== 'done') emitted++;
  console.log(PREFIX + JSON.stringify(value));
}}
function preview(value) {{
  try {{
    if (value === null || value === undefined) return String(value);
    let text = String(value);
    if (text.length > MAX_VALUE) text = text.slice(0, MAX_VALUE) + '…';
    return text;
  }} catch (error) {{
    return '<unprintable: ' + String(error) + '>';
  }}
}}
setImmediate(function () {{
  if (typeof Java === 'undefined' || !Java.available) {{
    emit({{kind: 'error', error: 'Java runtime is not available in this process'}});
    emit({{kind: 'done'}});
    return;
  }}
  Java.perform(function () {{
    try {{
"""
    footer = """
    } catch (error) {
      emit({kind: 'error', error: String(error), stack: error.stack || null});
      emit({kind: 'done'});
    }
  });
});
"""
    if mode == "classes":
        body = f"""
      const needle = {_js(match.lower())};
      const names = Java.enumerateLoadedClassesSync().filter(function (name) {{
        return !needle || name.toLowerCase().indexOf(needle) !== -1;
      }}).sort();
      names.forEach(function (name) {{ emit({{kind: 'class', name: name}}); }});
      emit({{kind: 'done', count: names.length}});
"""
    elif mode == "methods":
        query = f"{class_name}!{match or '*'}/s"
        body = f"""
      const groups = Java.enumerateMethods({_js(query)});
      let count = 0;
      groups.forEach(function (group) {{
        group.classes.forEach(function (klass) {{
          klass.methods.forEach(function (name) {{
            count++;
            emit({{kind: 'method', className: klass.name, signature: name}});
          }});
        }});
      }});
      emit({{kind: 'done', count: count}});
"""
    elif mode == "hook":
        body = f"""
      const className = {_js(class_name)};
      const methodName = {_js(method)};
      const target = Java.use(className);
      if (!target[methodName]) throw new Error('method not found: ' + className + '.' + methodName);
      target[methodName].overloads.forEach(function (overload, index) {{
        const signature = overload.argumentTypes.map(function (item) {{ return item.className; }}).join(', ');
        overload.implementation = function () {{
          const args = Array.prototype.slice.call(arguments).map(preview);
          const result = overload.apply(this, arguments);
          emit({{kind: 'call', className: className, method: methodName,
                overload: index, signature: signature, args: args,
                returnValue: preview(result)}});
          return result;
        }};
        emit({{kind: 'hook', className: className, method: methodName,
              overload: index, signature: signature}});
      }});
      emit({{kind: 'ready', className: className, method: methodName}});
"""
    else:
        raise ValueError(f"unsupported mode: {mode}")
    return header + body + footer


def _parse_events(output: str) -> tuple[list[dict], list[str]]:
    events: list[dict] = []
    errors: list[str] = []
    for raw_line in output.splitlines():
        line = ANSI_RE.sub("", raw_line)
        position = line.find(EVENT_PREFIX)
        if position < 0:
            continue
        try:
            event = json.loads(line[position + len(EVENT_PREFIX):])
        except json.JSONDecodeError as exc:
            errors.append(f"invalid event JSON: {exc}")
            continue
        if isinstance(event, dict):
            events.append(event)
            if event.get("kind") == "error":
                errors.append(str(event.get("error", "unknown agent error")))
    return events, errors


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="frida-android-instrument")
    parser.add_argument("package", help="Android application identifier")
    parser.add_argument("--mode", choices=("classes", "methods", "hook"), default="classes")
    parser.add_argument("--class-name")
    parser.add_argument("--method")
    parser.add_argument("--match", default="")
    parser.add_argument("--spawn", action="store_true")
    parser.add_argument("--device-id")
    parser.add_argument("--timeout", type=int, default=15)
    parser.add_argument("--max-events", type=int, default=200)
    parser.add_argument("--max-value", type=int, default=256)
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--yes-i-consent", action="store_true")
    return parser


def _validation_error(args: argparse.Namespace) -> str | None:
    if args.mode in ("methods", "hook") and not args.class_name:
        return f"--class-name is required for --mode {args.mode}"
    if args.mode == "hook" and not args.method:
        return "--method is required for --mode hook"
    if args.timeout < 1 or args.timeout > 3600:
        return "--timeout must be between 1 and 3600 seconds"
    if args.max_events < 1 or args.max_events > 10000:
        return "--max-events must be between 1 and 10000"
    if args.max_value < 16 or args.max_value > 4096:
        return "--max-value must be between 16 and 4096"
    return None


def _emit(result: dict, output_format: str) -> None:
    if output_format == "json":
        print(json.dumps(result, ensure_ascii=False))
        return
    if not result.get("ok"):
        print(f"frida-android-instrument: {result.get('error', 'failed')}")
        if result.get("hint"):
            print(f"hint: {result['hint']}")
        return
    print(f"frida-android-instrument: {result['package']} [{result['mode']}]")
    for event in result.get("events", []):
        kind = event.get("kind")
        if kind == "class":
            print(f"  class  {event.get('name')}")
        elif kind == "method":
            print(f"  method {event.get('className')}.{event.get('signature')}")
        elif kind == "hook":
            print(f"  hook   {event.get('className')}.{event.get('method')}({event.get('signature')})")
        elif kind == "call":
            print(f"  call   {event.get('method')}({', '.join(event.get('args', []))}) -> {event.get('returnValue')}")
    if result.get("eventsTruncated"):
        print("  events truncated by --max-events")


def main(argv: list[str]) -> int:
    args = _parser().parse_args(argv[1:])
    if not _consented(args):
        _emit({
            "ok": False,
            "error": "Android Frida instrumentation executes or attaches to the target",
            "hint": "run via `rekit run --allow-dynamic frida-android-instrument …`",
        }, args.format)
        return 4
    error = _validation_error(args)
    if error:
        _emit({"ok": False, "error": error}, args.format)
        return 2
    frida_cli = shutil.which("frida")
    if not frida_cli:
        _emit({
            "ok": False,
            "error": "frida CLI not found",
            "hint": "install current frida-tools and provide a compatible device server or Gadget",
        }, args.format)
        return 3

    agent = build_agent(
        args.mode, args.class_name, args.method, args.match,
        args.max_events, args.max_value,
    )
    device_args = ["-D", args.device_id] if args.device_id else ["-U"]
    target_args = ["-f", args.package] if args.spawn else ["-N", args.package]
    with tempfile.TemporaryDirectory(prefix="rekit-frida-android-") as directory:
        agent_path = Path(directory) / "agent.js"
        agent_path.write_text(agent, encoding="utf-8")
        command = [
            frida_cli, *device_args, *target_args,
            "-l", str(agent_path), "-q", "-t", str(args.timeout),
            "--exit-on-error",
        ]
        if args.spawn:
            command.append("--kill-on-exit")
        try:
            proc = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=args.timeout + 10,
                check=False,
            )
            stdout, stderr = proc.stdout or "", proc.stderr or ""
            return_code = proc.returncode
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout if isinstance(exc.stdout, str) else (exc.stdout or b"").decode("utf-8", "replace")
            stderr = exc.stderr if isinstance(exc.stderr, str) else (exc.stderr or b"").decode("utf-8", "replace")
            return_code = None
        except OSError as exc:
            _emit({"ok": False, "error": f"failed to run frida: {exc}"}, args.format)
            return 1

    events, runtime_errors = _parse_events(stdout + "\n" + stderr)
    retained = [event for event in events if event.get("kind") != "done"]
    event_count = len(retained)
    truncated = event_count >= args.max_events
    if return_code not in (0, None) and not runtime_errors:
        runtime_errors.append((stderr or stdout).strip()[-1000:] or f"frida exited {return_code}")
    result = {
        "ok": not runtime_errors,
        "package": args.package,
        "mode": args.mode,
        "spawned": args.spawn,
        "device": args.device_id or "usb",
        "eventCount": event_count,
        "eventsTruncated": truncated,
        "events": retained,
        "runtimeErrors": runtime_errors,
        "fridaExitCode": return_code,
    }
    if not result["ok"]:
        result["error"] = runtime_errors[0]
    _emit(result, args.format)
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

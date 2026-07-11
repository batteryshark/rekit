#!/usr/bin/env python3
"""Signature-aware Frida tracing using a local API Monitor XML definition tree."""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import shlex
import sys
import threading
import time
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple


DEFAULT_APIS = (
    "CreateProcessW", "CreateFileW", "ReadFile", "WriteFile", "VirtualAlloc",
    "VirtualProtect", "WriteProcessMemory", "CreateRemoteThread", "RegOpenKeyExW",
    "RegSetValueExW", "WinHttpOpenRequest", "WinHttpSendRequest", "InternetOpenUrlW",
    "CryptDecrypt", "BCryptDecrypt",
)


@dataclass(frozen=True)
class Parameter:
    name: str
    type: str


@dataclass(frozen=True)
class ApiSignature:
    module: str
    name: str
    params: Tuple[Parameter, ...]
    return_type: str
    category: str
    source: str

    def score(self) -> Tuple[int, int, int]:
        return (len(self.params), int(bool(self.return_type)), int(bool(self.category)))


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _charset_type(type_name: str, wide: bool) -> str:
    replacements = (
        (("LPCTSTR", "LPCWSTR" if wide else "LPCSTR")),
        (("LPTSTR", "LPWSTR" if wide else "LPSTR")),
        (("PCTSTR", "PCWSTR" if wide else "PCSTR")),
        (("PTSTR", "PWSTR" if wide else "PSTR")),
        (("TCHAR", "WCHAR" if wide else "CHAR")),
    )
    result = type_name
    for source, replacement in replacements:
        result = result.replace(source, replacement)
    return result


def _iter_xml_files(root: Path) -> Iterable[Path]:
    if root.is_file():
        yield root
        return
    for path in sorted(root.rglob("*.xml")):
        if path.is_file():
            yield path


def _relative_source(path: Path, root: Path) -> str:
    if root.is_file():
        return path.name
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def parse_definition_file(path: Path, corpus_root: Path) -> List[ApiSignature]:
    raw = path.read_bytes()
    try:
        root_element = ET.fromstring(raw)
    except ET.ParseError:
        # A known API Monitor release contains at least one file with a stray byte
        # before its opening comment. Tolerate only a tiny non-XML prefix; do not
        # attempt broad repair that could hide genuinely damaged definitions.
        first_tag = raw.find(b"<")
        if not 0 < first_tag <= 16:
            raise
        root_element = ET.fromstring(raw[first_tag:])
    signatures: List[ApiSignature] = []
    for module in root_element.iter():
        if _local_name(module.tag) != "Module":
            continue
        module_name = module.attrib.get("Name", "").strip()
        if not module_name:
            continue
        category = ""
        for child in list(module):
            tag = _local_name(child.tag)
            if tag == "Category":
                category = child.attrib.get("Name", "").strip()
                continue
            if tag != "Api":
                continue
            api_name = child.attrib.get("Name", "").strip()
            if not api_name:
                continue
            params = []
            return_type = ""
            for item in list(child):
                item_tag = _local_name(item.tag)
                if item_tag == "Param":
                    params.append(Parameter(
                        item.attrib.get("Name", f"arg{len(params)}"),
                        item.attrib.get("Type", "void*"),
                    ))
                elif item_tag == "Return":
                    return_type = item.attrib.get("Type", "").strip()
            source = _relative_source(path, corpus_root)
            both = child.attrib.get("BothCharset", "").lower() in ("true", "1", "yes")
            if both and not api_name.endswith(("A", "W")):
                for suffix, wide in (("A", False), ("W", True)):
                    signatures.append(ApiSignature(
                        module_name, api_name + suffix,
                        tuple(Parameter(param.name, _charset_type(param.type, wide))
                              for param in params),
                        _charset_type(return_type, wide), category, source,
                    ))
            else:
                signatures.append(ApiSignature(
                    module_name, api_name, tuple(params), return_type, category, source
                ))
    return signatures


def load_signatures(root: Path) -> Tuple[List[ApiSignature], List[dict]]:
    signatures: List[ApiSignature] = []
    warnings = []
    for path in _iter_xml_files(root):
        try:
            signatures.extend(parse_definition_file(path, root))
        except (ET.ParseError, OSError) as exc:
            warnings.append({"file": _relative_source(path, root), "error": str(exc)})
    return signatures, warnings


def _matches(value: str, patterns: Sequence[str]) -> bool:
    lowered = value.lower()
    return any(fnmatch.fnmatchcase(lowered, pattern.lower()) for pattern in patterns)


def select_signatures(signatures: Sequence[ApiSignature], api_patterns: Sequence[str],
                      module_patterns: Sequence[str], max_hooks: int) -> Tuple[List[ApiSignature], int]:
    best: Dict[str, ApiSignature] = {}
    for signature in signatures:
        if module_patterns and not _matches(signature.module, module_patterns):
            continue
        matched = False
        for pattern in api_patterns:
            if "!" in pattern:
                module_pattern, api_pattern = pattern.split("!", 1)
                matched = (_matches(signature.module, (module_pattern,)) and
                           _matches(signature.name, (api_pattern,)))
            else:
                matched = _matches(signature.name, (pattern,))
            if matched:
                break
        if not matched:
            continue
        key = signature.name.lower()
        current = best.get(key)
        if current is None or signature.score() > current.score():
            best[key] = signature
    selected = sorted(best.values(), key=lambda item: (item.module.lower(), item.name.lower()))
    omitted = max(0, len(selected) - max_hooks)
    return selected[:max_hooks], omitted


def signature_summary(signature: ApiSignature) -> dict:
    return {
        "module": signature.module,
        "name": signature.name,
        "params": [asdict(param) for param in signature.params],
        "returnType": signature.return_type,
        "category": signature.category,
        "source": signature.source,
    }


def generate_agent(signatures: Sequence[ApiSignature], max_string: int) -> str:
    definitions = [signature_summary(signature) for signature in signatures]
    encoded = json.dumps(definitions, ensure_ascii=True).replace("</", "<\\/")
    return r"""
'use strict';
const definitions = %s;
const maxString = %d;

function findExport(moduleName, exportName) {
  try {
    const loaded = Process.findModuleByName(moduleName);
    if (loaded && typeof loaded.findExportByName === 'function') {
      const address = loaded.findExportByName(exportName);
      if (address) return address;
    }
  } catch (_) {}
  try {
    if (typeof Module.findExportByName === 'function') {
      const address = Module.findExportByName(moduleName, exportName);
      if (address) return address;
    }
  } catch (_) {}
  return null;
}

function safeString(value, typeName, apiName) {
  if (value.isNull()) return null;
  const type = String(typeName || '').toUpperCase();
  const wide = /(WCHAR|WSTR|PWSTR)/.test(type) ||
               (/(TCHAR|TSTR)/.test(type) && /W$/.test(apiName));
  const ansi = /(CHAR\s*\*|CSTR|PSTR)/.test(type) ||
               (/(TCHAR|TSTR)/.test(type) && /A$/.test(apiName));
  try {
    if (wide) return value.readUtf16String(maxString);
    if (ansi) return value.readUtf8String(maxString);
  } catch (_) {}
  return undefined;
}

function decodeArgument(value, parameter, apiName) {
  const type = String(parameter.type || 'void*');
  const preview = safeString(value, type, apiName);
  if (preview !== undefined) return {name: parameter.name, type: type, value: preview};
  const scalar = /^(?:CONST\s+)?(?:BOOL|BOOLEAN|BYTE|CHAR|SHORT|USHORT|WORD|INT|UINT|LONG|ULONG|DWORD|HRESULT|NTSTATUS|SIZE_T|SSIZE_T|DWORD_PTR|ULONG_PTR)$/i;
  try {
    if (scalar.test(type.replace(/[\[\]]/g, ''))) {
      return {name: parameter.name, type: type, value: value.toString()};
    }
  } catch (_) {}
  return {name: parameter.name, type: type, value: value.toString()};
}

const installedKeys = {};

function installDefinition(definition, reportMissing) {
  const key = definition.module.toLowerCase() + '!' + definition.name.toLowerCase();
  if (installedKeys[key]) return;
  const address = findExport(definition.module, definition.name);
  if (!address) {
    if (reportMissing) {
      send({kind: 'hook', installed: false, module: definition.module, api: definition.name});
    }
    return false;
  }
  try {
    Interceptor.attach(address, {
      onEnter(args) {
        this.started = Date.now();
        this.decoded = definition.params.map(function (parameter, index) {
          return decodeArgument(args[index], parameter, definition.name);
        });
      },
      onLeave(retval) {
        send({
          kind: 'call', module: definition.module, api: definition.name,
          category: definition.category, args: this.decoded || [],
          returnType: definition.returnType, returnValue: retval.toString(),
          threadId: Process.getCurrentThreadId(), durationMs: Date.now() - this.started
        });
      }
    });
    installedKeys[key] = true;
    send({kind: 'hook', installed: true, module: definition.module,
          api: definition.name, address: address.toString()});
    return true;
  } catch (error) {
    send({kind: 'hook', installed: false, module: definition.module,
          api: definition.name, error: String(error)});
    return false;
  }
}

let moduleObserver = null;
if (typeof Process.attachModuleObserver === 'function') {
  moduleObserver = Process.attachModuleObserver({
    onAdded(module) {
      definitions.forEach(function (definition) { installDefinition(definition, false); });
    }
  });
} else {
  definitions.forEach(function (definition) { installDefinition(definition, true); });
}
""" % (encoded, max_string)


def _consented(args: argparse.Namespace) -> bool:
    return args.yes_i_consent or os.environ.get("REKIT_ALLOW_DYNAMIC") == "1"


def _split_csv(value: str) -> List[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def trace_target(target: Path, target_args: str, source: str, timeout: int,
                 max_events: int) -> Tuple[List[dict], List[dict], List[dict], int]:
    try:
        import frida  # type: ignore
    except ImportError as exc:
        raise RuntimeError("Python frida bindings are unavailable; install frida-tools") from exc

    events: List[dict] = []
    hooks: List[dict] = []
    errors: List[dict] = []
    dropped_events = 0
    finished = threading.Event()

    def on_message(message: dict, data: Optional[bytes]) -> None:
        nonlocal dropped_events
        if message.get("type") == "send":
            payload = message.get("payload", {})
            if payload.get("kind") == "hook":
                hooks.append(payload)
            elif payload.get("kind") == "call":
                if len(events) < max_events:
                    events.append(payload)
                else:
                    dropped_events += 1
        elif message.get("type") == "error":
            errors.append({"description": message.get("description", "Frida script error"),
                           "stack": message.get("stack", "")[:2000]})

    argv = [str(target)]
    if target_args:
        argv.extend(shlex.split(target_args, posix=os.name != "nt"))
    device = frida.get_local_device()
    pid = device.spawn(argv)
    session = None
    try:
        session = device.attach(pid)
        session.on("detached", lambda *unused: finished.set())
        script = session.create_script(source)
        script.on("message", on_message)
        script.load()
        device.resume(pid)
        finished.wait(timeout)
    finally:
        if not finished.is_set():
            try:
                device.kill(pid)
            except Exception as exc:  # Frida exposes backend-specific exception types.
                errors.append({"description": f"failed to stop spawned target: {exc}"})
        if session is not None:
            try:
                session.detach()
            except Exception:
                pass
    return hooks, events, errors, dropped_events


def main(argv: List[str]) -> int:
    default_definitions = Path(__file__).resolve().parents[1] / "assets" / "apimonitor"
    parser = argparse.ArgumentParser(prog="frida-api-trace")
    parser.add_argument("target")
    parser.add_argument("--definitions", default=str(default_definitions))
    parser.add_argument("--apis", default=",".join(DEFAULT_APIS))
    parser.add_argument("--modules", default="")
    parser.add_argument("--target-args", default="")
    parser.add_argument("--timeout", type=int, default=20)
    parser.add_argument("--max-hooks", type=int, default=64)
    parser.add_argument("--max-events", type=int, default=1000)
    parser.add_argument("--max-string", type=int, default=256)
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--yes-i-consent", action="store_true")
    args = parser.parse_args(argv[1:])

    if not _consented(args):
        print(json.dumps({"ok": False, "error": "frida-api-trace EXECUTES the target",
                          "hint": "run via `rekit run --allow-dynamic frida-api-trace ...`"}))
        return 4
    target = Path(args.target).expanduser().resolve()
    definitions = Path(args.definitions).expanduser().resolve()
    if not target.is_file():
        print(json.dumps({"ok": False, "error": f"target not found: {target}"}))
        return 2
    if not definitions.exists():
        print(json.dumps({
            "ok": False,
            "error": f"API definitions not found: {definitions}",
            "hint": "place your local API Monitor XML tree in skills/frida-api-trace/assets/apimonitor or pass --definitions",
        }))
        return 2
    if min(args.timeout, args.max_hooks, args.max_events, args.max_string) < 1:
        print(json.dumps({"ok": False, "error": "timeout and max limits must be positive"}))
        return 2

    signatures, parse_warnings = load_signatures(definitions)
    api_patterns = _split_csv(args.apis)
    module_patterns = _split_csv(args.modules)
    selected, omitted = select_signatures(signatures, api_patterns, module_patterns,
                                           args.max_hooks)
    if not selected:
        print(json.dumps({
            "ok": False,
            "error": "no API signatures matched",
            "definitionCount": len(signatures),
            "apiPatterns": api_patterns,
            "modulePatterns": module_patterns,
            "parseWarnings": parse_warnings[:20],
        }))
        return 2

    source = generate_agent(selected, args.max_string)
    started = time.monotonic()
    try:
        hooks, events, runtime_errors, dropped_events = trace_target(
            target, args.target_args, source, args.timeout, args.max_events
        )
    except Exception as exc:
        # Frida uses backend-specific exception classes; return them as a bounded error.
        print(json.dumps({"ok": False, "error": f"Frida trace failed: {exc}"}))
        return 1

    final_hooks: Dict[str, dict] = {}
    for hook in hooks:
        key = f"{hook.get('module', '').lower()}!{hook.get('api', '').lower()}"
        current = final_hooks.get(key)
        if current is None or hook.get("installed"):
            final_hooks[key] = hook
    for signature in selected:
        key = f"{signature.module.lower()}!{signature.name.lower()}"
        if key not in final_hooks:
            final_hooks[key] = {
                "kind": "hook", "installed": False, "module": signature.module,
                "api": signature.name, "error": "module/export was not observed during trace",
            }
    hook_status = sorted(final_hooks.values(),
                         key=lambda item: (item.get("module", "").lower(),
                                           item.get("api", "").lower()))
    installed = sum(1 for hook in hook_status if hook.get("installed"))
    result = {
        "ok": True,
        "target": str(target),
        "definitions": str(definitions),
        "definitionsParsed": len(signatures),
        "selectedCount": len(selected),
        "omittedByHookCap": omitted,
        "selected": [signature_summary(signature) for signature in selected],
        "hookCoverage": {"installed": installed, "missing": len(hook_status) - installed,
                         "status": hook_status},
        "eventCount": len(events) + dropped_events,
        "eventsReturned": len(events),
        "eventsTruncated": dropped_events > 0,
        "events": events,
        "parseWarnings": parse_warnings[:100],
        "runtimeErrors": runtime_errors,
        "durationSeconds": round(time.monotonic() - started, 3),
    }
    if args.format == "json":
        print(json.dumps(result, sort_keys=True))
        return 0
    print(f"frida-api-trace: {target.name}")
    print(f"  signatures: {len(selected)} selected; hooks: {installed}/{len(hook_status)} installed")
    print(f"  calls:      {result['eventCount']} captured in {result['durationSeconds']:.3f}s")
    for event in events[:30]:
        arguments = ", ".join(f"{item['name']}={item['value']}" for item in event["args"])
        print(f"  {event['module']}!{event['api']}({arguments}) -> {event['returnValue']}")
    if result["eventCount"] > 30:
        print(f"  ... {result['eventCount'] - 30} more event(s); use --format json")
    for hook in hook_status:
        if not hook.get("installed"):
            print(f"  missing: {hook['module']}!{hook['api']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

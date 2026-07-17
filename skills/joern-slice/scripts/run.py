#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from collections import deque
from pathlib import Path

from runtime import RuntimeUnavailable, container_base, metadata, verify_runtime


SCRIPT_DIR = Path(__file__).resolve().parent
SKILL_DIR = SCRIPT_DIR.parent
DEFAULT_PROFILE = SKILL_DIR / "assets" / "behavior-flow.json"
FORMATS = ("text", "json")
MODES = ("data-flow", "usages", "behavior-flow")


class SliceError(RuntimeError):
    pass


def parser() -> argparse.ArgumentParser:
    languages = ("auto", *metadata()["languages"])
    p = argparse.ArgumentParser(
        description="Build a bounded Joern CPG and emit normalized static-analysis evidence"
    )
    p.add_argument("target", type=Path, help="source file or source tree")
    p.add_argument("outdir", type=Path, help="atomic artifact output directory")
    p.add_argument("--language", default="auto", choices=languages)
    p.add_argument("--mode", default="behavior-flow", choices=MODES)
    p.add_argument("--profile", type=Path, help="declarative behavior profile JSON")
    p.add_argument("--sink-filter", help="Joern sink regex for data-flow mode")
    p.add_argument("--slice-depth", type=int, default=12)
    p.add_argument("--reuse-cpg", type=Path, help="reuse an existing local CPG")
    p.add_argument("--timeout", type=int, default=900)
    p.add_argument("--format", default="text", choices=FORMATS)
    return p


def canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def digest_json(value: object) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def load_profile(path: Path) -> tuple[dict, str]:
    try:
        profile = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SliceError(f"could not load behavior profile {path}: {exc}") from exc
    if not isinstance(profile, dict) or profile.get("schemaVersion") != 1:
        raise SliceError("behavior profile must be a schemaVersion 1 object")
    if not isinstance(profile.get("id"), str) or not profile["id"]:
        raise SliceError("behavior profile id must be a non-empty string")
    for group in ("sources", "sinks"):
        entries = profile.get(group)
        if not isinstance(entries, list) or not entries:
            raise SliceError(f"behavior profile {group} must be a non-empty array")
        seen = set()
        for entry in entries:
            if not isinstance(entry, dict):
                raise SliceError(f"each {group} entry must be an object")
            identifier = entry.get("id")
            pattern = entry.get("pattern")
            if not isinstance(identifier, str) or not identifier or identifier in seen:
                raise SliceError(f"each {group} id must be non-empty and unique")
            if not isinstance(pattern, str) or not pattern:
                raise SliceError(f"{group} entry {identifier} has no pattern")
            try:
                re.compile(pattern, re.IGNORECASE)
            except re.error as exc:
                raise SliceError(f"invalid regex for {group} entry {identifier}: {exc}") from exc
            seen.add(identifier)
    return profile, digest_json(profile)


def collect_target(target: Path, destination: Path) -> dict:
    target = target.expanduser().resolve()
    if not target.exists():
        raise SliceError(f"target does not exist: {target}")
    if not (target.is_file() or target.is_dir()):
        raise SliceError(f"target is not a regular file or directory: {target}")
    limits = metadata()
    entries = []
    excluded = []
    total_bytes = 0
    candidates = [target] if target.is_file() else sorted(target.rglob("*"))
    root = target.parent if target.is_file() else target
    for source in candidates:
        relative = source.name if target.is_file() else source.relative_to(root).as_posix()
        if source.is_symlink():
            excluded.append({"path": relative, "reason": "symlink"})
            continue
        if not source.is_file():
            continue
        size = source.stat().st_size
        if len(entries) + 1 > int(limits["maxInputFiles"]):
            raise SliceError(f"target exceeds {limits['maxInputFiles']} regular files")
        if total_bytes + size > int(limits["maxInputBytes"]):
            raise SliceError(f"target exceeds {limits['maxInputBytes']} bytes")
        remaining = int(limits["maxInputBytes"]) - total_bytes
        with source.open("rb") as handle:
            data = handle.read(remaining + 1)
        if len(data) > remaining:
            raise SliceError(f"target exceeds {limits['maxInputBytes']} bytes")
        item = {
            "path": relative,
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        }
        entries.append(item)
        total_bytes += len(data)
        staged = destination / relative
        staged.parent.mkdir(parents=True, exist_ok=True)
        staged.write_bytes(data)
        staged.chmod(0o444)
    if not entries:
        raise SliceError("target contains no regular files")
    manifest = {
        "schemaVersion": 1,
        "root": str(target),
        "files": entries,
        "excluded": excluded,
    }
    return {
        "path": str(target),
        "files": len(entries),
        "bytes": total_bytes,
        "excluded": excluded,
        "manifestSha256": digest_json({"files": entries}),
    }


def run_phase(command: list[str], *, timeout: float, phase: str) -> tuple[str, str, float]:
    started = time.monotonic()
    try:
        proc = subprocess.run(
            command, capture_output=True, text=True, timeout=max(1, timeout), check=False
        )
    except subprocess.TimeoutExpired as exc:
        raise SliceError(f"{phase} timed out") from exc
    except OSError as exc:
        raise SliceError(f"could not start Docker for {phase}: {exc}") from exc
    elapsed = time.monotonic() - started
    stdout = (proc.stdout or "")[-16384:]
    stderr = (proc.stderr or "")[-16384:]
    if proc.returncode != 0:
        detail = (stderr or stdout or "unknown Joern error").strip()
        raise SliceError(f"{phase} exited {proc.returncode}: {detail}")
    return stdout, stderr, elapsed


def docker_prefix(ref: str, output: Path, input_dir: Path | None = None) -> list[str]:
    command = container_base(ref)
    image = command.pop()
    if input_dir is not None:
        command.extend(["--mount", f"type=bind,src={input_dir},dst=/input,readonly"])
    command.extend(["--mount", f"type=bind,src={output},dst=/output"])
    return command + [image]


def sink_expression(profile: dict) -> str:
    patterns = [entry["pattern"] for entry in profile["sinks"]]
    return ".*(?:" + "|".join(f"(?:{pattern})" for pattern in patterns) + ").*"


def validate_raw(path: Path, stdout: str, stderr: str, mode: str) -> dict:
    if not path.is_file():
        if stdout.strip() == "Empty slice, no file generated." and not stderr.strip():
            if mode == "usages":
                return {"$type": "ProgramUsageSlice", "objectSlices": [], "userDefinedTypes": []}
            return {"$type": "DataFlowSlice", "nodes": [], "edges": []}
        detail = (stderr or stdout or "Joern reported success without an artifact").strip()
        raise SliceError(f"Joern did not produce slices.json: {detail}")
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SliceError(f"Joern produced invalid slices.json: {exc}") from exc
    if not isinstance(raw, dict):
        raise SliceError("Joern slice artifact must be a JSON object")
    fields = ("objectSlices", "userDefinedTypes") if mode == "usages" else ("nodes", "edges")
    for field in fields:
        if not isinstance(raw.get(field), list):
            raise SliceError(f"Joern slice artifact has no {field} array")
    return raw


def node_text(node: dict) -> str:
    return " ".join(
        str(node.get(field, ""))
        for field in ("name", "code", "typeFullName", "parentMethod", "parentFile")
    )


def stable_nodes(raw_nodes: list[dict]) -> tuple[list[dict], dict]:
    normalized = []
    raw_to_stable = {}
    used = set()
    ordered = sorted(raw_nodes, key=lambda node: canonical_json({
        key: node.get(key) for key in (
            "parentFile", "parentMethod", "lineNumber", "columnNumber", "label", "name", "code", "id"
        )
    }))
    for node in ordered:
        identity = {
            key: node.get(key) for key in (
                "parentFile", "parentMethod", "lineNumber", "columnNumber", "label", "name", "code", "typeFullName"
            )
        }
        base = "n-" + digest_json(identity)[:16]
        stable = base
        suffix = 2
        while stable in used:
            stable = f"{base}-{suffix}"
            suffix += 1
        used.add(stable)
        raw_to_stable[node.get("id")] = stable
        normalized.append({"id": stable, **identity})
    return normalized, raw_to_stable


def shortest_path(adjacency: dict[str, list[str]], start: str, goals: set[str]) -> list[str]:
    queue = deque([[start]])
    visited = {start}
    while queue:
        path = queue.popleft()
        if path[-1] in goals and len(path) > 1:
            return path
        for destination in adjacency.get(path[-1], []):
            if destination not in visited:
                visited.add(destination)
                queue.append(path + [destination])
    return []


def furthest_path(adjacency: dict[str, list[str]], start: str) -> list[str]:
    queue = deque([[start]])
    visited = {start}
    best = [start]
    while queue:
        path = queue.popleft()
        if len(path) > len(best):
            best = path
        for destination in adjacency.get(path[-1], []):
            if destination not in visited:
                visited.add(destination)
                queue.append(path + [destination])
    return best


def usage_graph(raw: dict) -> tuple[list[dict], list[dict]]:
    raw_nodes = []
    raw_edges = []
    serial = 0

    def add_node(**fields) -> str:
        nonlocal serial
        serial += 1
        identifier = f"usage-{serial}"
        raw_nodes.append({"id": identifier, **fields})
        return identifier

    def embedded(value: object) -> dict:
        if isinstance(value, dict):
            return value
        if isinstance(value, str):
            try:
                parsed = json.loads(value)
                return parsed if isinstance(parsed, dict) else {"code": value}
            except json.JSONDecodeError:
                return {"code": value}
        return {"code": str(value)}

    for obj in raw.get("objectSlices", []):
        if not isinstance(obj, dict):
            continue
        file_name = obj.get("fileName")
        method_name = obj.get("fullName")
        method = add_node(
            label="METHOD_USAGE",
            name=method_name,
            code=obj.get("code"),
            parentFile=file_name,
            parentMethod=method_name,
            lineNumber=obj.get("lineNumber"),
            columnNumber=obj.get("columnNumber"),
        )
        for item in obj.get("slices", []):
            if not isinstance(item, dict):
                continue
            target_data = embedded(item.get("targetObj"))
            target = add_node(
                label="USAGE_TARGET",
                name=target_data.get("name"),
                code=target_data.get("code") or item.get("targetObj"),
                typeFullName=target_data.get("typeFullName"),
                parentFile=file_name,
                parentMethod=method_name,
                lineNumber=target_data.get("lineNumber"),
                columnNumber=target_data.get("columnNumber"),
            )
            raw_edges.append({"src": method, "dst": target, "label": "CONTAINS_USAGE"})
            definition_data = embedded(item.get("definedBy"))
            definition = add_node(
                label="USAGE_DEFINITION",
                name=definition_data.get("name"),
                code=definition_data.get("code") or item.get("definedBy"),
                typeFullName=definition_data.get("typeFullName"),
                parentFile=file_name,
                parentMethod=method_name,
                lineNumber=definition_data.get("lineNumber"),
                columnNumber=definition_data.get("columnNumber"),
            )
            raw_edges.append({"src": definition, "dst": target, "label": "DEFINES"})
            for group, label in (("argToCalls", "ARGUMENT_TO_CALL"), ("invokedCalls", "INVOKES")):
                for call in item.get(group, []):
                    if not isinstance(call, dict):
                        continue
                    lines = call.get("lineNumber")
                    columns = call.get("columnNumber")
                    call_node = add_node(
                        label="CALL_USAGE",
                        name=call.get("callName"),
                        code=call.get("callName"),
                        typeFullName=call.get("returnType"),
                        parentFile=file_name,
                        parentMethod=method_name,
                        lineNumber=lines[0] if isinstance(lines, list) and lines else lines,
                        columnNumber=columns[0] if isinstance(columns, list) and columns else columns,
                    )
                    raw_edges.append({"src": target, "dst": call_node, "label": label})
    nodes, id_map = stable_nodes(raw_nodes)
    edges = [
        {"src": id_map[edge["src"]], "dst": id_map[edge["dst"]], "label": edge["label"]}
        for edge in raw_edges
    ]
    edges.sort(key=lambda item: (item["src"], item["dst"], item["label"]))
    return nodes, edges


def normalize(raw: dict, *, mode: str, profile: dict | None) -> dict:
    if mode == "usages":
        nodes, edges = usage_graph(raw)
        id_map = {}
    else:
        nodes, id_map = stable_nodes(raw["nodes"])
        edges = []
        for edge in raw["edges"]:
            source = id_map.get(edge.get("src"))
            destination = id_map.get(edge.get("dst"))
            if source and destination:
                edges.append({"src": source, "dst": destination, "label": edge.get("label")})
        edges.sort(key=lambda item: (item["src"], item["dst"], str(item["label"])))
    evidence = {
        "graphType": raw.get("$type"),
        "nodes": nodes,
        "edges": edges,
        "paths": [],
        "findings": [],
    }
    if mode != "behavior-flow" or profile is None:
        return evidence

    raw_by_stable = {
        id_map[node.get("id")]: node for node in raw["nodes"] if node.get("id") in id_map
    }
    source_hits = []
    sink_hits = []
    for stable, node in raw_by_stable.items():
        text = node_text(node)
        for entry in profile["sources"]:
            if re.search(entry["pattern"], text, re.IGNORECASE):
                source_hits.append((stable, entry["id"]))
        for entry in profile["sinks"]:
            if re.search(entry["pattern"], text, re.IGNORECASE):
                sink_hits.append((stable, entry["id"]))
    adjacency = {}
    outdegree = {node["id"]: 0 for node in nodes}
    for edge in edges:
        adjacency.setdefault(edge["src"], []).append(edge["dst"])
        outdegree[edge["src"]] = outdegree.get(edge["src"], 0) + 1
    terminals = {identifier for identifier, degree in outdegree.items() if degree == 0}
    selected_sinks = sink_hits or [(None, entry["id"]) for entry in profile["sinks"]]
    for source, source_kind in source_hits:
        for sink, sink_kind in selected_sinks:
            path = shortest_path(adjacency, source, {sink}) if sink else []
            relation = "explicit-reaching-def"
            if not path:
                path = [source] if source in terminals else shortest_path(adjacency, source, terminals)
                relation = "slice-selected-by-sink"
            if not path:
                path = furthest_path(adjacency, source)
                relation = "slice-selected-by-sink"
            if not path:
                continue
            path_id = "p-" + digest_json({"nodes": path, "sink": sink})[:16]
            evidence["paths"].append({
                "id": path_id,
                "nodes": path,
                "sinkContext": sink,
                "relation": relation,
            })
            evidence["findings"].append({
                "id": "f-" + digest_json({"path": path_id, "source": source_kind, "sink": sink_kind})[:16],
                "kind": profile.get("findingKind", "behavior-flow"),
                "sourceKind": source_kind,
                "sinkKind": sink_kind,
                "path": path_id,
                "confidence": "structural",
            })
            if len(evidence["findings"]) >= 20:
                return evidence
    return evidence


def publish(stage: Path, outdir: Path) -> dict[str, str]:
    names = ("cpg.bin", "raw-slice.json", "evidence.json")
    for name in names:
        artifact = stage / name
        if not artifact.is_file() or artifact.stat().st_size == 0:
            raise SliceError(f"analysis did not produce {name}")
    outdir = outdir.expanduser().resolve()
    outdir.mkdir(parents=True, exist_ok=True)
    transaction = Path(tempfile.mkdtemp(prefix=".joern-slice-publish-", dir=outdir))
    backups = {}
    replaced = []
    try:
        for name in names:
            shutil.copyfile(stage / name, transaction / name)
        for name in names:
            destination = outdir / name
            if destination.exists():
                backup = transaction / f"{name}.previous"
                os.replace(destination, backup)
                backups[name] = backup
            os.replace(transaction / name, destination)
            replaced.append(name)
    except OSError:
        for name in reversed(replaced):
            (outdir / name).unlink(missing_ok=True)
        for name, backup in backups.items():
            if backup.exists():
                os.replace(backup, outdir / name)
        raise
    finally:
        shutil.rmtree(transaction, ignore_errors=True)
    return {name: str(outdir / name) for name in names}


def analyze(args: argparse.Namespace) -> dict:
    if not 1 <= args.slice_depth <= 64:
        raise SliceError("slice depth must be between 1 and 64")
    if not 1 <= args.timeout <= 3600:
        raise SliceError("timeout must be between 1 and 3600 seconds")
    target_path = args.target.expanduser().resolve()
    outdir_path = args.outdir.expanduser().resolve()
    if target_path.is_dir():
        try:
            outdir_path.relative_to(target_path)
        except ValueError:
            pass
        else:
            raise SliceError("output directory must not be inside the analyzed source tree")
    profile = None
    profile_digest = None
    profile_path = args.profile or DEFAULT_PROFILE
    if args.mode == "behavior-flow":
        profile, profile_digest = load_profile(profile_path.expanduser().resolve())
    elif args.profile:
        raise SliceError("--profile is only valid in behavior-flow mode")
    if args.mode == "usages" and args.sink_filter:
        raise SliceError("--sink-filter is only valid for data-flow modes")
    if args.mode == "behavior-flow" and args.sink_filter:
        raise SliceError("--sink-filter cannot override a behavior profile")
    try:
        ref, identity = verify_runtime()
    except RuntimeUnavailable as exc:
        raise SliceError(str(exc)) from exc

    started = time.monotonic()
    timings = {}
    with tempfile.TemporaryDirectory(prefix="rekit-joern-slice-") as name:
        stage = Path(name)
        stage_input = stage / "input"
        stage_output = stage / "output"
        stage_input.mkdir(mode=0o755)
        stage_output.mkdir(mode=0o777)
        stage_output.chmod(0o777)
        target = collect_target(args.target, stage_input)
        cpg = stage_output / "cpg.bin"
        if args.reuse_cpg:
            reuse = args.reuse_cpg.expanduser().resolve()
            if not reuse.is_file() or reuse.stat().st_size == 0:
                raise SliceError(f"reused CPG is not a non-empty regular file: {reuse}")
            if reuse.stat().st_size > int(metadata()["maxCpgBytes"]):
                raise SliceError("reused CPG exceeds the configured size limit")
            provenance_path = reuse.parent / "evidence.json"
            try:
                provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise SliceError(
                    f"reused CPG requires valid sibling evidence.json provenance: {exc}"
                ) from exc
            if provenance.get("target", {}).get("manifestSha256") != target["manifestSha256"]:
                raise SliceError("reused CPG target manifest does not match the current target")
            prior_analysis = provenance.get("analysis", {})
            if prior_analysis.get("language") != args.language:
                raise SliceError("reused CPG frontend does not match --language")
            if provenance.get("producer", {}).get("image") != ref:
                raise SliceError("reused CPG was not produced by the selected immutable image")
            shutil.copyfile(reuse, cpg)
            timings["parseSeconds"] = 0.0
        else:
            command = docker_prefix(ref, stage_output, stage_input)
            image = command.pop()
            command.extend(["--entrypoint", "joern-parse", image, "/input"])
            if args.language != "auto":
                command.extend(["--language", args.language])
            command.extend(["-o", "/output/cpg.bin"])
            remaining = args.timeout - (time.monotonic() - started)
            if remaining <= 0:
                raise SliceError(f"analysis timed out after {args.timeout} seconds")
            _stdout, _stderr, elapsed = run_phase(command, timeout=remaining, phase="CPG parse")
            timings["parseSeconds"] = round(elapsed, 6)
            if not cpg.is_file() or cpg.stat().st_size == 0:
                raise SliceError("Joern parser reported success without a non-empty cpg.bin")

        raw_path = stage_output / "slices.json"
        command = docker_prefix(ref, stage_output)
        image = command.pop()
        command.extend(["--workdir", "/output", "--entrypoint", "joern-slice", image])
        slice_mode = "data-flow" if args.mode == "behavior-flow" else args.mode
        command.append(slice_mode)
        if slice_mode == "data-flow":
            command.extend(["--slice-depth", str(args.slice_depth)])
            sink = sink_expression(profile) if profile else args.sink_filter
            if sink:
                command.extend(["--sink-filter", sink])
        command.append("/output/cpg.bin")
        remaining = args.timeout - (time.monotonic() - started)
        if remaining <= 0:
            raise SliceError(f"analysis timed out after {args.timeout} seconds")
        stdout, stderr, elapsed = run_phase(command, timeout=remaining, phase="CPG slice")
        timings["sliceSeconds"] = round(elapsed, 6)
        raw = validate_raw(raw_path, stdout, stderr, slice_mode)
        (stage_output / "raw-slice.json").write_bytes(canonical_json(raw) + b"\n")
        normalized = normalize(raw, mode=args.mode, profile=profile)
        unresolved = [
            {
                "file": node.get("parentFile"),
                "line": node.get("lineNumber"),
                "code": node.get("code"),
                "typeFullName": node.get("typeFullName"),
            }
            for node in normalized["nodes"]
            if "<unresolved" in str(node.get("typeFullName", ""))
            or "<unresolved" in str(node.get("parentMethod", ""))
        ]
        observed_files = sorted({
            node.get("parentFile") for node in normalized["nodes"] if node.get("parentFile")
        })
        evidence = {
            "schemaVersion": 1,
            "producer": {
                "tool": "joern-slice",
                "joernVersion": metadata()["joernVersion"],
                "revision": metadata()["revision"],
                "image": ref,
                "runtime": identity,
            },
            "target": target,
            "analysis": {
                "mode": args.mode,
                "language": args.language,
                "sliceDepth": args.slice_depth,
                "profile": profile.get("id") if profile else None,
                "profileSha256": profile_digest,
                "proofDepth": "interprocedural-cpg",
                "limits": {
                    "timeoutSeconds": args.timeout,
                    "maxInputBytes": metadata()["maxInputBytes"],
                    "maxInputFiles": metadata()["maxInputFiles"],
                },
            },
            "coverage": {
                "inputFiles": target["files"],
                "inputBytes": target["bytes"],
                "filesObservedInSlice": observed_files,
                "excluded": target["excluded"],
                "unresolved": unresolved[:100],
                "truncated": len(normalized["findings"]) >= 20 or len(unresolved) > 100,
                "limitations": [
                    "Joern does not report complete per-file parse coverage in this command",
                    "one run represents one frontend and does not establish cross-language flow"
                ],
            },
            "graph": normalized,
            "metrics": {
                **timings,
                "totalSeconds": round(time.monotonic() - started, 6),
                "cpgBytes": cpg.stat().st_size,
                "rawNodes": len(raw.get("nodes", raw.get("objectSlices", []))),
                "rawEdges": len(raw.get("edges", [])),
                "normalizedNodes": len(normalized["nodes"]),
                "normalizedEdges": len(normalized["edges"]),
                "findings": len(normalized["findings"]),
            },
        }
        (stage_output / "evidence.json").write_bytes(canonical_json(evidence) + b"\n")
        artifacts = publish(stage_output, args.outdir)
    return {
        "ok": True,
        "tool": "joern-slice",
        "target": target,
        "mode": args.mode,
        "language": args.language,
        "findings": evidence["metrics"]["findings"],
        "metrics": evidence["metrics"],
        "image": ref,
        "artifacts": artifacts,
    }


def emit_result(result: dict, output_format: str) -> None:
    if output_format == "json":
        print(json.dumps(result, sort_keys=True))
    elif result.get("ok"):
        print(
            f"joern-slice: {result['target']['files']} files, "
            f"{result['findings']} behavior findings"
        )
        for name, path in result["artifacts"].items():
            print(f"  {name}: {path}")
    else:
        print(f"joern-slice: {result['error']}", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        result = analyze(args)
    except (SliceError, RuntimeUnavailable, ValueError, OSError, json.JSONDecodeError) as exc:
        emit_result({"ok": False, "tool": "joern-slice", "error": str(exc)}, args.format)
        return 1
    emit_result(result, args.format)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

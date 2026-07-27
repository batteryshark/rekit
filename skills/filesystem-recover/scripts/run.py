#!/usr/bin/env python3
"""Recover files from an image with tsk_recover, without mounting the image."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path, PurePosixPath
from typing import Dict, Iterable, List, Optional, Set, Tuple


VALID_SECTOR_SIZES = (512, 1024, 2048, 4096)
ORPHAN_NAME = re.compile(r"^OrphanFile-(?P<record>[0-9]+)(?:-[0-9]+-[0-9]+)?$")
FLS_ENTRY = re.compile(
    r"^\s*\+*\s*(?P<types>[-a-zA-Z]/[-a-zA-Z])\s+"
    r"(?P<deleted>\*\s+)?"
    r"(?P<metadata>[0-9]+(?:-[0-9]+-[0-9]+)?)"
    r"(?P<reallocated>\(realloc\))?:\s*(?P<path>.+?)\s*$"
)


def fail(message: str, code: int = 2) -> int:
    print(json.dumps({"ok": False, "tool": "filesystem-recover", "error": message}))
    return code


def ensure_empty_output(outdir: Path) -> Path:
    if outdir.exists():
        if not outdir.is_dir():
            raise ValueError("output exists and is not a directory: {}".format(outdir))
        if any(outdir.iterdir()):
            raise ValueError("output directory must be empty: {}".format(outdir))
    else:
        outdir.mkdir(parents=True)
    files = outdir / "files"
    files.mkdir()
    return files


def build_command(
    tool: str,
    image: Path,
    output: Path,
    offset: int,
    mode: str,
    sector_size: int,
    fstype: Optional[str],
) -> List[str]:
    command = [tool]
    if mode == "allocated":
        command.append("-a")
    elif mode == "all":
        command.append("-e")
    command.extend(["-b", str(sector_size), "-o", str(offset)])
    if fstype:
        command.extend(["-f", fstype])
    command.extend([str(image.resolve()), str(output.resolve())])
    return command


def build_fls_command(
    tool: str,
    image: Path,
    offset: int,
    sector_size: int,
    fstype: Optional[str],
) -> List[str]:
    command = [
        tool,
        "-r",
        "-p",
        "-b",
        str(sector_size),
        "-o",
        str(offset),
    ]
    if fstype:
        command.extend(["-f", fstype])
    command.append(str(image.resolve()))
    return command


def hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def recovered_files(root: Path) -> Iterable[Path]:
    for current, directories, files in os.walk(root, followlinks=False):
        directories[:] = sorted(
            name
            for name in directories
            if not (Path(current) / name).is_symlink()
        )
        for name in sorted(files):
            path = Path(current) / name
            if path.is_file() and not path.is_symlink():
                yield path


def write_manifest(
    root: Path, destination: Path, should_hash: bool, max_files: int
) -> Dict[str, object]:
    count = 0
    total_bytes = 0
    truncated = False
    with destination.open("w", encoding="utf-8", newline="\n") as handle:
        for path in recovered_files(root):
            if count >= max_files:
                truncated = True
                break
            stat = path.stat()
            record = {
                "path": path.relative_to(root).as_posix(),
                "size": stat.st_size,
                "modifiedNs": stat.st_mtime_ns,
                "sha256": hash_file(path) if should_hash else None,
            }
            handle.write(json.dumps(record, sort_keys=True) + "\n")
            count += 1
            total_bytes += stat.st_size
    return {
        "fileCount": count,
        "totalBytes": total_bytes,
        "manifestTruncated": truncated,
        "hashesRecorded": should_hash,
    }


def tail_text(path: Path, limit: int = 8192) -> str:
    with path.open("rb") as handle:
        handle.seek(0, os.SEEK_END)
        size = handle.tell()
        handle.seek(max(0, size - limit))
        return handle.read(limit).decode("utf-8", "replace")


def parse_fls_entry(line: str) -> Optional[dict]:
    match = FLS_ENTRY.match(line)
    if not match:
        return None
    metadata_address = match.group("metadata")
    return {
        "types": match.group("types"),
        "deleted": bool(match.group("deleted")),
        "metadataAddress": metadata_address,
        "metadataRecord": metadata_address.split("-", 1)[0],
        "reallocated": bool(match.group("reallocated")),
        "path": match.group("path"),
    }


def safe_relative_path(raw: str) -> Optional[Path]:
    normalized = raw.replace("\\", "/").lstrip("/")
    pure = PurePosixPath(normalized)
    if not pure.parts or any(part in ("", ".", "..") for part in pure.parts):
        return None
    if "\x00" in normalized or (pure.parts and pure.parts[0].endswith(":")):
        return None
    return Path(*pure.parts)


def orphan_sources(root: Path, max_files: int) -> Tuple[Dict[str, List[Path]], bool]:
    sources: Dict[str, List[Path]] = {}
    visited = 0
    for path in recovered_files(root):
        if visited >= max_files:
            return sources, True
        visited += 1
        match = ORPHAN_NAME.match(path.name)
        if match and "$OrphanFiles" in path.relative_to(root).parts:
            sources.setdefault(match.group("record"), []).append(path)
    return sources, False


def write_metadata_names(
    raw_fls: Path,
    output: Path,
    wanted_records: Set[str],
    max_records: int,
) -> Tuple[Dict[str, List[dict]], dict]:
    candidates: Dict[str, List[dict]] = {}
    parsed = 0
    truncated = False
    with raw_fls.open("r", encoding="utf-8", errors="replace") as source, output.open(
        "w", encoding="utf-8", newline="\n"
    ) as destination:
        for line in source:
            entry = parse_fls_entry(line)
            if not entry:
                continue
            if parsed >= max_records:
                truncated = True
                break
            destination.write(json.dumps(entry, sort_keys=True) + "\n")
            parsed += 1
            record = str(entry["metadataRecord"])
            if record in wanted_records and len(candidates.setdefault(record, [])) < 64:
                candidates[record].append(entry)
    return candidates, {
        "metadataNameCount": parsed,
        "metadataNamesTruncated": truncated,
    }


def is_orphan_placeholder(path: str) -> bool:
    relative = safe_relative_path(path)
    return bool(
        relative
        and "$OrphanFiles" in relative.parts
        and ORPHAN_NAME.match(relative.name)
    )


def apply_metadata_renames(
    root: Path,
    sources: Dict[str, List[Path]],
    candidates: Dict[str, List[dict]],
    output: Path,
) -> dict:
    renamed = 0
    skipped = 0
    errors = 0
    with output.open("w", encoding="utf-8", newline="\n") as handle:
        for record in sorted(sources, key=lambda value: int(value)):
            usable: Dict[str, dict] = {}
            for entry in candidates.get(record, []):
                relative = safe_relative_path(str(entry["path"]))
                if (
                    relative is None
                    or entry["reallocated"]
                    or is_orphan_placeholder(str(entry["path"]))
                    or not str(entry["types"]).endswith("/r")
                ):
                    continue
                usable.setdefault(relative.as_posix(), entry)
            for source in sorted(sources[record]):
                source_relative = source.relative_to(root)
                record_result = {
                    "metadataRecord": record,
                    "source": source_relative.as_posix(),
                    "candidatePaths": sorted(usable),
                }
                if not usable:
                    record_result["status"] = "no-usable-name"
                    skipped += 1
                elif len(usable) > 1:
                    record_result["status"] = "ambiguous"
                    skipped += 1
                else:
                    destination_relative = Path(next(iter(usable)))
                    destination = root / destination_relative
                    record_result["destination"] = destination_relative.as_posix()
                    if destination == source:
                        record_result["status"] = "already-named"
                        skipped += 1
                    elif destination.exists():
                        record_result["status"] = "collision"
                        skipped += 1
                    else:
                        try:
                            destination.parent.mkdir(parents=True, exist_ok=True)
                            source.rename(destination)
                            record_result["status"] = "renamed"
                            record_result["metadataAddress"] = usable[
                                destination_relative.as_posix()
                            ]["metadataAddress"]
                            renamed += 1
                        except OSError as exc:
                            record_result["status"] = "error"
                            record_result["error"] = str(exc)
                            errors += 1
                handle.write(json.dumps(record_result, sort_keys=True) + "\n")
    return {
        "orphanPlaceholderCount": sum(len(paths) for paths in sources.values()),
        "metadataRenamedCount": renamed,
        "metadataRenameSkipped": skipped,
        "metadataRenameErrors": errors,
    }


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("outdir", type=Path)
    parser.add_argument("--offset", type=int, required=True)
    parser.add_argument(
        "--mode", choices=("allocated", "deleted", "all"), default="deleted"
    )
    parser.add_argument("--fstype")
    parser.add_argument("--sector-size", type=int, default=512)
    parser.add_argument("--timeout", type=int, default=14_400)
    parser.add_argument("--max-files", type=int, default=1_000_000)
    parser.add_argument("--max-name-records", type=int, default=2_000_000)
    parser.add_argument("--no-hash", action="store_true")
    parser.add_argument("--no-metadata-names", action="store_true")
    args = parser.parse_args(argv)
    if not args.input.is_file():
        return fail("input is not a regular file: {}".format(args.input))
    if args.offset < 0:
        return fail("--offset must be a non-negative sector count")
    if args.sector_size not in VALID_SECTOR_SIZES:
        return fail("--sector-size must be one of 512, 1024, 2048, 4096")
    if args.offset * args.sector_size >= args.input.stat().st_size:
        return fail("--offset resolves outside the image")
    if args.timeout < 1 or args.timeout > 604_800:
        return fail("--timeout must be between 1 and 604800 seconds")
    if args.max_files < 1 or args.max_files > 10_000_000:
        return fail("--max-files must be between 1 and 10000000")
    if args.max_name_records < 1 or args.max_name_records > 10_000_000:
        return fail("--max-name-records must be between 1 and 10000000")
    recover_tool = shutil.which("tsk_recover")
    if not recover_tool:
        return fail(
            "tsk_recover is not on PATH; install The Sleuth Kit "
            "(https://www.sleuthkit.org/)",
            3,
        )
    fls_tool = None if args.no_metadata_names else shutil.which("fls")
    if not args.no_metadata_names and not fls_tool:
        return fail(
            "fls is not on PATH; install The Sleuth Kit or pass "
            "--no-metadata-names to disable MFT/inode name mapping",
            3,
        )
    try:
        files_dir = ensure_empty_output(args.outdir)
        stdout_log = args.outdir / "tsk-recover.stdout.log"
        stderr_log = args.outdir / "tsk-recover.stderr.log"
        command = build_command(
            recover_tool,
            args.input,
            files_dir,
            args.offset,
            args.mode,
            args.sector_size,
            args.fstype,
        )
        started = time.monotonic()
        timed_out = False
        with stdout_log.open("wb") as stdout, stderr_log.open("wb") as stderr:
            try:
                process = subprocess.run(
                    command,
                    stdin=subprocess.DEVNULL,
                    stdout=stdout,
                    stderr=stderr,
                    timeout=args.timeout,
                    check=False,
                )
                exit_code = process.returncode
            except subprocess.TimeoutExpired:
                timed_out = True
                exit_code = None

        fls_exit_code = None
        fls_timed_out = False
        metadata_inventory = {
            "metadataNamesEnabled": not args.no_metadata_names,
            "metadataNameCount": 0,
            "metadataNamesTruncated": False,
            "orphanPlaceholderCount": 0,
            "metadataRenamedCount": 0,
            "metadataRenameSkipped": 0,
            "metadataRenameErrors": 0,
            "metadataNamesFile": None,
            "metadataRenamesFile": None,
        }
        if not args.no_metadata_names:
            assert fls_tool is not None
            raw_fls = args.outdir / "fls-names.txt"
            fls_stderr = args.outdir / "fls.stderr.log"
            fls_command = build_fls_command(
                fls_tool,
                args.input,
                args.offset,
                args.sector_size,
                args.fstype,
            )
            with raw_fls.open("wb") as stdout, fls_stderr.open("wb") as stderr:
                try:
                    fls_process = subprocess.run(
                        fls_command,
                        stdin=subprocess.DEVNULL,
                        stdout=stdout,
                        stderr=stderr,
                        timeout=args.timeout,
                        check=False,
                    )
                    fls_exit_code = fls_process.returncode
                except subprocess.TimeoutExpired:
                    fls_timed_out = True
            sources, source_scan_truncated = orphan_sources(files_dir, args.max_files)
            metadata_names = args.outdir / "metadata-names.jsonl"
            metadata_renames = args.outdir / "metadata-renames.jsonl"
            if fls_exit_code == 0 and not fls_timed_out:
                candidates, name_counts = write_metadata_names(
                    raw_fls,
                    metadata_names,
                    set(sources),
                    args.max_name_records,
                )
            else:
                metadata_names.write_text("", encoding="utf-8")
                candidates = {}
                name_counts = {
                    "metadataNameCount": 0,
                    "metadataNamesTruncated": False,
                }
            if exit_code == 0 and not timed_out and fls_exit_code == 0 and not fls_timed_out:
                rename_counts = apply_metadata_renames(
                    files_dir, sources, candidates, metadata_renames
                )
            else:
                metadata_renames.write_text("", encoding="utf-8")
                rename_counts = {
                    "orphanPlaceholderCount": sum(
                        len(paths) for paths in sources.values()
                    ),
                    "metadataRenamedCount": 0,
                    "metadataRenameSkipped": sum(
                        len(paths) for paths in sources.values()
                    ),
                    "metadataRenameErrors": 0,
                }
            metadata_inventory.update(name_counts)
            metadata_inventory.update(rename_counts)
            metadata_inventory["metadataNamesIncomplete"] = (
                fls_exit_code != 0 or fls_timed_out
            )
            metadata_inventory["orphanScanTruncated"] = source_scan_truncated
            metadata_inventory["metadataNamesFile"] = str(metadata_names.resolve())
            metadata_inventory["metadataRenamesFile"] = str(metadata_renames.resolve())

        manifest_path = args.outdir / "manifest.jsonl"
        inventory = write_manifest(
            files_dir, manifest_path, not args.no_hash, args.max_files
        )
        result = {
            "ok": (
                exit_code == 0
                and not timed_out
                and (
                    args.no_metadata_names
                    or (
                        fls_exit_code == 0
                        and not fls_timed_out
                        and metadata_inventory["metadataRenameErrors"] == 0
                    )
                )
            ),
            "tool": "filesystem-recover",
            "image": str(args.input.resolve()),
            "imageSize": args.input.stat().st_size,
            "offsetSectors": args.offset,
            "offsetBytes": args.offset * args.sector_size,
            "sectorSize": args.sector_size,
            "mode": args.mode,
            "fstype": args.fstype,
            "outputDir": str(args.outdir.resolve()),
            "filesDir": str(files_dir.resolve()),
            "manifest": str(manifest_path.resolve()),
            "exitCode": exit_code,
            "timedOut": timed_out,
            "flsExitCode": fls_exit_code,
            "flsTimedOut": fls_timed_out,
            "flsStderrTail": (
                tail_text(args.outdir / "fls.stderr.log")
                if not args.no_metadata_names
                else ""
            ),
            "elapsedSeconds": round(time.monotonic() - started, 3),
            "stderrTail": tail_text(stderr_log),
            **inventory,
            **metadata_inventory,
        }
        report = args.outdir / "recovery.json"
        result["report"] = str(report.resolve())
        report.write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    except (OSError, ValueError) as exc:
        return fail("recovery failed: {}".format(exc), 1)
    print(json.dumps(result, sort_keys=True))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

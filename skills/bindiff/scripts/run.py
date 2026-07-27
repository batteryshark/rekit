#!/usr/bin/env python3
"""bindiff — function-level structural diff of two binaries with Google BinDiff.

Answers the questions byte diffing cannot: which function in the new build is
the old `check_license`, what changed inside it, what is brand new, and what was
removed — across recompiles that move every address.

Pipeline: each input is turned into a `.BinExport` (BinDiff's disassembly
interchange format) by a disassembler backend, `bindiff` matches them, and the
resulting `.BinDiff` SQLite database is parsed into JSON. Functions present in
only one side are recovered by reading the `.BinExport` call graphs directly,
since BinDiff's database records matched pairs only.

Static throughout: disassemble, match, report. Nothing is executed.

    python3 run.py <primary> <secondary> <outdir> [--backend auto|ida|ghidra|none]
                   [--format text|json] [--top N] [--identical-threshold F]
                   [--timeout SECONDS]

`primary` is the *old* / reference build, `secondary` the *new* one. Either may
already be a `.BinExport` file, in which case no disassembler is needed.
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import binexport_read  # noqa: E402

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

BINDIFF_HINT = ("install BinDiff 8 (https://github.com/google/bindiff/releases) and put "
                "`bindiff` on PATH (macOS: /Applications/BinDiff/bindiff, "
                "Linux: /opt/bindiff/bin/bindiff)")
IDA_HINT = ("install the BinExport plugin for IDA "
            "(https://github.com/google/binexport/releases) into your IDA plugins dir, "
            "and put `idat` on PATH or set IDA_HOME")
GHIDRA_HINT = ("install Ghidra (https://ghidra-sre.org) plus the BinExport extension "
               "(BinExport_Ghidra-Java.zip from https://github.com/google/binexport/releases), "
               "and put <ghidra>/support/analyzeHeadless on PATH or set GHIDRA_HOME")


class StepError(Exception):
    """A pipeline step failed; carries an operator-actionable hint."""

    def __init__(self, message: str, hint: str = "", log: str = ""):
        super().__init__(message)
        self.hint = hint
        self.log = log


# --------------------------------------------------------------------------- #
# Tool discovery
# --------------------------------------------------------------------------- #

def _find_bindiff() -> str | None:
    found = shutil.which("bindiff")
    if found:
        return found
    for cand in ("/opt/bindiff/bin/bindiff", "/Applications/BinDiff/bindiff",
                 "/usr/local/bin/bindiff",
                 r"C:\Program Files\BinDiff\bin\bindiff.exe"):
        if os.path.isfile(cand):
            return cand
    return None


def _find_ida() -> str | None:
    for name in ("idat64", "idat"):
        found = shutil.which(name)
        if found:
            return found
    for env in ("IDA_HOME", "IDA_DIR", "IDADIR"):
        home = os.environ.get(env)
        if not home:
            continue
        for name in ("idat64", "idat", "idat64.exe", "idat.exe"):
            cand = os.path.join(home, name)
            if os.path.isfile(cand):
                return cand
    for app in sorted(glob.glob("/Applications/IDA*.app"), reverse=True):
        for name in ("idat64", "idat"):
            cand = os.path.join(app, "Contents", "MacOS", name)
            if os.path.isfile(cand):
                return cand
    return None


def _find_ghidra() -> str | None:
    found = shutil.which("analyzeHeadless")
    if found:
        return found
    for env in ("GHIDRA_HOME", "GHIDRA_INSTALL_DIR", "GHIDRA_ROOT"):
        home = os.environ.get(env)
        if home:
            cand = os.path.join(home, "support", "analyzeHeadless")
            if os.path.isfile(cand):
                return cand
    return None


# Extensions worth stripping from a derived filename. Everything else is kept:
# builds are routinely named `piu-1.08-unstripped` or `app-2.3.1`, and a blind
# splitext() would turn those into `piu-1` / `app-2`, collapsing a corpus of
# versions into near-identical names.
KNOWN_EXTENSIONS = {".binexport", ".exe", ".bin", ".elf", ".so", ".dll", ".dylib",
                    ".out", ".i64", ".idb"}


def _stem(path: str) -> str:
    """Filename without a *recognised* extension — version suffixes are preserved."""
    base = os.path.basename(path)
    root, ext = os.path.splitext(base)
    return root if ext.lower() in KNOWN_EXTENSIONS else base


def _is_binexport(path: str) -> bool:
    return os.path.splitext(path)[1].lower() == ".binexport"


def _tail(text: str, limit: int = 2000) -> str:
    text = (text or "").strip()
    return text if len(text) <= limit else "..." + text[-limit:]


# --------------------------------------------------------------------------- #
# Export backends
# --------------------------------------------------------------------------- #

def _export_ida(tool: str, binary: str, out_file: str, timeout: int) -> None:
    """Headless IDA + BinExport plugin: -OBinExportAutoAction:BinExportBinary."""
    # IDA drops its database next to the input, so work on a copy in a temp dir
    # and leave the operator's sample directory untouched.
    workdir = tempfile.mkdtemp(prefix="rekit_bindiff_ida_")
    try:
        staged = os.path.join(workdir, os.path.basename(binary))
        shutil.copy2(binary, staged)
        cmd = [tool, "-A", "-OBinExportAutoAction:BinExportBinary",
               f"-OBinExportModule:{out_file}",
               "-OBinExportAlsoLogToStdErr:TRUE",
               f"-L{os.path.join(workdir, 'ida.log')}", staged]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=timeout, cwd=workdir)
        except subprocess.TimeoutExpired:
            raise StepError(f"IDA export timed out after {timeout}s: {binary}") from None
        except OSError as exc:
            raise StepError(f"cannot run IDA ({tool}): {exc}", IDA_HINT) from None
        if not os.path.isfile(out_file):
            log = ""
            try:
                with open(os.path.join(workdir, "ida.log"), encoding="utf-8",
                          errors="replace") as handle:
                    log = handle.read()
            except OSError:
                pass
            raise StepError(
                f"IDA produced no BinExport for {binary} (exit {proc.returncode})",
                IDA_HINT, _tail(log or proc.stderr or proc.stdout))
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def _export_ghidra(tool: str, binary: str, out_file: str, timeout: int) -> None:
    """Headless Ghidra + BinExport extension, driven by our bundled Jython script."""
    project = tempfile.mkdtemp(prefix="rekit_bindiff_ghidra_")
    cmd = [tool, project, "rekit-bindiff", "-import", binary,
           "-scriptPath", SCRIPT_DIR, "-postScript", "ghidra_binexport.py", out_file,
           "-deleteProject", "-analysisTimeoutPerFile", str(max(60, timeout // 2))]
    try:
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            raise StepError(f"Ghidra export timed out after {timeout}s: {binary}") from None
        except OSError as exc:
            raise StepError(f"cannot run analyzeHeadless: {exc}", GHIDRA_HINT) from None
        if not os.path.isfile(out_file):
            raise StepError(
                f"Ghidra produced no BinExport for {binary} (exit {proc.returncode})",
                GHIDRA_HINT, _tail(proc.stderr or proc.stdout))
    finally:
        shutil.rmtree(project, ignore_errors=True)


def _resolve_backend(requested: str) -> tuple[str, str | None]:
    """Return (backend_name, tool_path). Raises when the choice is unavailable."""
    if requested == "none":
        return "none", None
    if requested == "ida":
        tool = _find_ida()
        if not tool:
            raise StepError("IDA (idat) not found", IDA_HINT)
        return "ida", tool
    if requested == "ghidra":
        tool = _find_ghidra()
        if not tool:
            raise StepError("Ghidra analyzeHeadless not found", GHIDRA_HINT)
        return "ghidra", tool
    tool = _find_ida()
    if tool:
        return "ida", tool
    tool = _find_ghidra()
    if tool:
        return "ghidra", tool
    raise StepError(
        "no BinExport backend found (need IDA Pro or Ghidra)",
        f"{IDA_HINT}; or {GHIDRA_HINT}; or pass two .BinExport files with --backend none")


def _to_binexport(path: str, backend: str, tool: str | None, outdir: str,
                  timeout: int) -> str:
    """Return a `.BinExport` path for `path`, exporting it if needed."""
    if _is_binexport(path):
        return os.path.abspath(path)
    if backend == "none":
        raise StepError(
            f"--backend none requires .BinExport inputs, got: {path}",
            "drop --backend none to disassemble with IDA or Ghidra")
    export_dir = os.path.join(outdir, "binexport")
    os.makedirs(export_dir, exist_ok=True)
    out_file = os.path.join(export_dir, _stem(path) + ".BinExport")
    if backend == "ida":
        _export_ida(tool or "", os.path.abspath(path), out_file, timeout)
    else:
        _export_ghidra(tool or "", os.path.abspath(path), out_file, timeout)
    return out_file


# --------------------------------------------------------------------------- #
# Diff + result parsing
# --------------------------------------------------------------------------- #

def _run_bindiff(tool: str, primary: str, secondary: str, outdir: str,
                 timeout: int) -> str:
    before = {p: os.path.getmtime(p) for p in glob.glob(os.path.join(outdir, "*.BinDiff"))}
    cmd = [tool, "--logo=false", f"--primary={primary}", f"--secondary={secondary}",
           f"--output_dir={outdir}", "--output_format=bin"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise StepError(f"bindiff timed out after {timeout}s") from None
    except OSError as exc:
        raise StepError(f"cannot run bindiff ({tool}): {exc}", BINDIFF_HINT) from None
    produced = [p for p in glob.glob(os.path.join(outdir, "*.BinDiff"))
                if p not in before or os.path.getmtime(p) > before[p]]
    if not produced:
        raise StepError(f"bindiff wrote no result database (exit {proc.returncode})",
                        BINDIFF_HINT, _tail(proc.stderr or proc.stdout))
    return max(produced, key=os.path.getmtime)


def _read_result_db(db_path: str) -> dict:
    """Read a `.BinDiff` SQLite result into plain dicts."""
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    except sqlite3.Error as exc:
        raise StepError(f"cannot open BinDiff database {db_path}: {exc}") from None
    conn.row_factory = sqlite3.Row
    try:
        meta = conn.execute(
            "SELECT version, similarity, confidence, created FROM metadata").fetchone()
        files = conn.execute(
            "SELECT id, filename, exefilename, hash, functions, libfunctions, "
            "basicblocks, instructions FROM file ORDER BY id").fetchall()
        algorithms = {row["id"]: row["name"]
                      for row in conn.execute("SELECT id, name FROM functionalgorithm")}
        matches = []
        for row in conn.execute(
                "SELECT address1, name1, address2, name2, similarity, confidence, "
                "flags, algorithm, basicblocks, edges, instructions "
                "FROM function ORDER BY similarity ASC, address1 ASC"):
            matches.append({
                "address1": row["address1"], "name1": row["name1"] or "",
                "address2": row["address2"], "name2": row["name2"] or "",
                "similarity": row["similarity"], "confidence": row["confidence"],
                "algorithm": algorithms.get(row["algorithm"], str(row["algorithm"])),
                "basicblocks": row["basicblocks"], "edges": row["edges"],
                "instructions": row["instructions"],
            })
    except sqlite3.Error as exc:
        raise StepError(f"unexpected BinDiff database schema: {exc}",
                        "this reader targets BinDiff 8 result databases") from None
    finally:
        conn.close()
    return {
        "version": meta["version"] if meta else "",
        "similarity": meta["similarity"] if meta else 0.0,
        "confidence": meta["confidence"] if meta else 0.0,
        "files": [dict(row) for row in files],
        "matches": matches,
    }


def _inventory(path: str) -> dict:
    """Function inventory from a .BinExport, keyed by address (best effort)."""
    try:
        parsed = binexport_read.read(path)
    except binexport_read.BinExportError:
        return {}
    return {fn["address"]: fn for fn in parsed["functions"]
            if fn["type"] in binexport_read.MATCHABLE_TYPES}


def _unmatched(inventory: dict, matched_addresses: set) -> list[dict]:
    return [{"address": addr, "name": binexport_read.label(fn), "type": fn["type"]}
            for addr, fn in sorted(inventory.items())
            if addr not in matched_addresses]


def analyze(db_path: str, primary_export: str, secondary_export: str,
            identical_threshold: float) -> dict:
    """Turn a BinDiff result plus both exports into the full report."""
    result = _read_result_db(db_path)
    matches = result["matches"]

    identical = [m for m in matches if m["similarity"] >= identical_threshold]
    changed = [m for m in matches if m["similarity"] < identical_threshold]
    renamed = [m for m in matches
               if m["name1"] and m["name2"] and m["name1"] != m["name2"]]
    # A named function on one side matched to an autogenerated name on the other:
    # the symbol is portable from the named side to the stripped side.
    portable = [m for m in matches if bool(m["name1"]) != bool(m["name2"])]

    inv1, inv2 = _inventory(primary_export), _inventory(secondary_export)
    removed = _unmatched(inv1, {m["address1"] for m in matches})
    added = _unmatched(inv2, {m["address2"] for m in matches})

    return {
        "similarity": result["similarity"],
        "confidence": result["confidence"],
        "bindiffVersion": result["version"],
        "files": result["files"],
        "counts": {
            "primaryFunctions": len(inv1) or None,
            "secondaryFunctions": len(inv2) or None,
            "matched": len(matches),
            "identical": len(identical),
            "changed": len(changed),
            "renamed": len(renamed),
            "portableNames": len(portable),
            "removed": len(removed) if inv1 else None,
            "added": len(added) if inv2 else None,
        },
        "changed": changed,
        "matches": matches,
        "renamed": renamed,
        "portableNames": portable,
        "removed": removed,
        "added": added,
        "inventoryAvailable": bool(inv1 and inv2),
    }


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #

def _fmt_match(m: dict) -> str:
    name1 = m["name1"] or f"sub_{m['address1']:x}"
    name2 = m["name2"] or f"sub_{m['address2']:x}"
    return (f"  {m['similarity']:.3f} / {m['confidence']:.2f}  "
            f"0x{m['address1']:x} {name1}  ->  0x{m['address2']:x} {name2}"
            f"   [{m['algorithm']}]")


def render_text(report: dict, top: int, files: dict) -> str:
    counts = report["counts"]
    lines = [
        f"bindiff: similarity {report['similarity']:.4f}  "
        f"confidence {report['confidence']:.4f}",
        f"  matched {counts['matched']} functions "
        f"({counts['identical']} identical, {counts['changed']} changed)",
    ]
    if report["inventoryAvailable"]:
        lines.append(f"  primary {counts['primaryFunctions']} functions, "
                     f"secondary {counts['secondaryFunctions']} functions, "
                     f"{counts['removed']} removed, {counts['added']} added")
    else:
        lines.append("  unmatched-function inventory unavailable "
                     "(could not read one of the .BinExport files)")

    def section(title: str, items: list, formatter) -> None:
        if not items:
            return
        shown = items[:top]
        lines.append("")
        suffix = f" (showing {len(shown)} of {len(items)})" if len(items) > len(shown) else ""
        lines.append(f"{title}{suffix}:")
        lines.extend(formatter(item) for item in shown)

    section("changed functions (least similar first)", report["changed"], _fmt_match)
    section("name changes", report["renamed"],
            lambda m: f"  0x{m['address1']:x} {m['name1']}  ->  "
                      f"0x{m['address2']:x} {m['name2']}")
    section("added in secondary", report["added"],
            lambda f: f"  0x{f['address']:x} {f['name']} [{f['type']}]")
    section("removed from primary", report["removed"],
            lambda f: f"  0x{f['address']:x} {f['name']} [{f['type']}]")

    lines.append("")
    for key, path in files.items():
        lines.append(f"  {key}: {path}")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #

def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="bindiff")
    p.add_argument("primary", help="old/reference binary or .BinExport")
    p.add_argument("secondary", help="new/candidate binary or .BinExport")
    p.add_argument("outdir")
    p.add_argument("--backend", choices=["auto", "ida", "ghidra", "none"], default="auto")
    p.add_argument("--format", choices=["text", "json"], default="text")
    p.add_argument("--top", type=int, default=25)
    p.add_argument("--identical-threshold", type=float, default=1.0)
    p.add_argument("--timeout", type=int, default=3600)
    a = p.parse_args(argv[1:])

    def fail(payload: dict, code: int) -> int:
        print(json.dumps(payload))
        return code

    for path in (a.primary, a.secondary):
        if not os.path.isfile(path):
            return fail({"ok": False, "error": f"file not found: {path}"}, 2)

    tool = _find_bindiff()
    if not tool:
        return fail({"ok": False, "error": "bindiff not found", "hint": BINDIFF_HINT}, 3)

    os.makedirs(a.outdir, exist_ok=True)
    outdir = os.path.abspath(a.outdir)

    try:
        needs_backend = not (_is_binexport(a.primary) and _is_binexport(a.secondary))
        backend, backend_tool = _resolve_backend(a.backend) if needs_backend else ("none", None)
        primary_export = _to_binexport(a.primary, backend, backend_tool, outdir, a.timeout)
        secondary_export = _to_binexport(a.secondary, backend, backend_tool, outdir, a.timeout)
        db_path = _run_bindiff(tool, primary_export, secondary_export, outdir, a.timeout)
        report = analyze(db_path, primary_export, secondary_export, a.identical_threshold)
    except StepError as exc:
        payload = {"ok": False, "error": str(exc)}
        if exc.hint:
            payload["hint"] = exc.hint
        if exc.log:
            payload["log"] = exc.log
        return fail(payload, 1)

    matches_file = os.path.join(outdir, "matches.json")
    unmatched_file = os.path.join(outdir, "unmatched.json")
    summary_file = os.path.join(outdir, "summary.json")
    with open(matches_file, "w", encoding="utf-8") as handle:
        json.dump({"matches": report["matches"], "renamed": report["renamed"],
                   "portableNames": report["portableNames"]}, handle, indent=2)
    with open(unmatched_file, "w", encoding="utf-8") as handle:
        json.dump({"added": report["added"], "removed": report["removed"]}, handle, indent=2)

    files = {"resultDb": db_path, "matchesFile": matches_file,
             "unmatchedFile": unmatched_file, "summaryFile": summary_file,
             "primaryExport": primary_export, "secondaryExport": secondary_export}
    summary = {
        "ok": True, "tool": "bindiff", "backend": backend,
        "similarity": report["similarity"], "confidence": report["confidence"],
        "bindiffVersion": report["bindiffVersion"],
        "counts": report["counts"],
        "topChanged": report["changed"][:a.top],
        "added": report["added"][:a.top],
        "removed": report["removed"][:a.top],
        **files,
    }
    with open(summary_file, "w", encoding="utf-8") as handle:
        json.dump(summary, handle, indent=2)

    if a.format == "json":
        print(json.dumps(summary))
    else:
        print(render_text(report, a.top, files))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

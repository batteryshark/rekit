#!/usr/bin/env python3
"""diaphora-diff — headless Diaphora program diffing, name recovery, and change reports.

Diaphora matches functions between two builds using dozens of heuristics (call
graph shape, small primes products, MD index, pseudocode ASTs, ...). It is the
strongest free matcher for the case this skill exists to serve: one build has
symbols and the others are stripped, and you need the names carried across —
then a written record of what actually changed between versions.

The work splits into two halves, deliberately:

  export   needs IDA. Analyses one binary and writes a Diaphora SQLite database
           holding every function's pseudocode, assembly, prototype and dozens
           of structural fingerprints. Expensive; cache it and never redo it.
  diff     needs no IDA. Pure Python over two exported databases. So a corpus of
           N builds costs N exports and then any pairing is cheap.

Operations:

    run.py export  <binary> <outdb>                    (IDA)
    run.py diff    <db1> <db2> <outdir>                (no IDA)
    run.py report  <db1> <db2> <outdir> --results DB   (no IDA, no Diaphora)
    run.py compare <binaryA> <binaryB> <outdir>        (export both, cached, then diff)

`db1`/`binaryA` is the **primary** — for name recovery make this the build that
HAS symbols, so names flow primary → secondary.

Static throughout: disassembles, matches, and reports. Never runs the targets.
"""

from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DIAPHORA_DIR = os.path.join(SCRIPT_DIR, "diaphora")
SITE_DIR = os.path.join(SCRIPT_DIR, "site")

DIAPHORA_HINT = ("run `bin/rekit install diaphora-diff` to vendor the pinned Diaphora "
                 "release into skills/diaphora-diff/scripts/diaphora")
IDA_HINT = ("IDA Pro is required for the `export` step only — put `idat` on PATH or set "
            "IDA_HOME (macOS: /Applications/IDA*.app/Contents/MacOS/idat). "
            "`diff` and `report` need no IDA.")

# Diaphora's own match categories, best first. `multimatch` means one function
# matched several candidates — real, but ambiguous, so it is never auto-applied.
MATCH_TYPES = ("best", "partial", "unreliable", "multimatch")

# Names IDA/Diaphora generate when there is no symbol. Porting one of these
# teaches you nothing, so they are excluded from the rename map.
AUTO_NAME = re.compile(r"^(sub|loc|unknown_libname|nullsub|j_nullsub|def|byte|word|dword)_"
                       r"[0-9A-Fa-f]+$|^j_sub_[0-9A-Fa-f]+$")


# Extensions worth stripping from a derived filename. Everything else is kept:
# builds are routinely named `piu-1.08-unstripped` or `app-2.3.1`, and a blind
# splitext() would turn those into `piu-1` / `app-2`, collapsing a corpus of
# versions into near-identical names.
KNOWN_EXTENSIONS = {".i64", ".idb", ".exe", ".bin", ".elf", ".so", ".dll", ".dylib",
                    ".out", ".sqlite", ".binexport"}


class StepError(Exception):
    def __init__(self, message: str, hint: str = "", log: str = ""):
        super().__init__(message)
        self.hint = hint
        self.log = log


def stem(path: str) -> str:
    """Filename without a *recognised* extension — version suffixes are preserved."""
    base = os.path.basename(path)
    root, ext = os.path.splitext(base)
    return root if ext.lower() in KNOWN_EXTENSIONS else base


# --------------------------------------------------------------------------- #
# Tool discovery
# --------------------------------------------------------------------------- #

def _diaphora_script(name: str) -> str:
    path = os.path.join(DIAPHORA_DIR, name)
    if not os.path.isfile(path):
        raise StepError(f"vendored Diaphora not found ({path})", DIAPHORA_HINT)
    return path


def _find_ida(explicit: str | None = None) -> str:
    if explicit:
        if not os.path.isfile(explicit):
            raise StepError(f"--ida path does not exist: {explicit}", IDA_HINT)
        return explicit
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
    import glob as _glob
    for app in sorted(_glob.glob("/Applications/IDA*.app"), reverse=True):
        for name in ("idat64", "idat"):
            cand = os.path.join(app, "Contents", "MacOS", name)
            if os.path.isfile(cand):
                return cand
    raise StepError("IDA (idat) not found", IDA_HINT)


def _child_env() -> dict:
    env = dict(os.environ)
    parts = [p for p in (SITE_DIR, DIAPHORA_DIR, env.get("PYTHONPATH")) if p]
    env["PYTHONPATH"] = os.pathsep.join(parts)
    return env


def _tail(text: str, limit: int = 2000) -> str:
    text = (text or "").strip()
    return text if len(text) <= limit else "..." + text[-limit:]


# --------------------------------------------------------------------------- #
# export (IDA)
# --------------------------------------------------------------------------- #

def export(binary: str, out_db: str, ida: str | None, decompiler: bool,
           timeout: int) -> dict:
    """Analyse `binary` in headless IDA and write a Diaphora export database."""
    tool = _find_ida(ida)
    script = _diaphora_script("diaphora.py")
    out_db = os.path.abspath(out_db)
    os.makedirs(os.path.dirname(out_db) or ".", exist_ok=True)

    # IDA writes its database next to the input; stage a copy so the original
    # sample directory is never touched.
    workdir = tempfile.mkdtemp(prefix="rekit_diaphora_")
    try:
        staged = os.path.join(workdir, os.path.basename(binary))
        shutil.copy2(binary, staged)
        log_file = os.path.join(workdir, "ida.log")
        env = _child_env()
        env["DIAPHORA_AUTO"] = "1"
        env["DIAPHORA_EXPORT_FILE"] = out_db
        if decompiler:
            env["DIAPHORA_USE_DECOMPILER"] = "1"
        cmd = [tool, "-A", f"-S{script}", f"-L{log_file}", staged]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=timeout, cwd=workdir, env=env)
        except subprocess.TimeoutExpired:
            raise StepError(f"IDA export timed out after {timeout}s: {binary}") from None
        except OSError as exc:
            raise StepError(f"cannot run IDA ({tool}): {exc}", IDA_HINT) from None
        if not os.path.isfile(out_db):
            log = ""
            if os.path.isfile(log_file):
                with open(log_file, encoding="utf-8", errors="replace") as handle:
                    log = handle.read()
            raise StepError(
                f"Diaphora produced no export database for {binary} "
                f"(IDA exit {proc.returncode})",
                DIAPHORA_HINT, _tail(log or proc.stderr or proc.stdout))
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    with sqlite3.connect(f"file:{out_db}?mode=ro", uri=True) as conn:
        count = conn.execute("SELECT count(*) FROM functions").fetchone()[0]
    return {"exportDb": out_db, "functions": count,
            "bytes": os.path.getsize(out_db), "decompiler": bool(decompiler)}


def cached_export(binary: str, cache_dir: str, ida: str | None, decompiler: bool,
                  timeout: int) -> dict:
    """Export `binary` unless a cached database for those exact bytes exists."""
    digest = hashlib.sha256()
    with open(binary, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    out_db = os.path.join(cache_dir,
                          f"{stem(binary)}-{digest.hexdigest()[:12]}.sqlite")
    if os.path.isfile(out_db):
        with sqlite3.connect(f"file:{out_db}?mode=ro", uri=True) as conn:
            count = conn.execute("SELECT count(*) FROM functions").fetchone()[0]
        return {"exportDb": out_db, "functions": count,
                "bytes": os.path.getsize(out_db), "cached": True}
    os.makedirs(cache_dir, exist_ok=True)
    return {**export(binary, out_db, ida, decompiler, timeout), "cached": False}


# --------------------------------------------------------------------------- #
# diff (no IDA)
# --------------------------------------------------------------------------- #

def diff(db1: str, db2: str, results_db: str, timeout: int) -> None:
    """Run Diaphora's matching engine over two export databases."""
    script = _diaphora_script("diaphora.py")
    env = _child_env()
    env["DIAPHORA_AUTO_DIFF"] = "1"
    env["DIAPHORA_DB1"] = os.path.abspath(db1)
    env["DIAPHORA_DB2"] = os.path.abspath(db2)
    env["DIAPHORA_DIFF_OUT"] = os.path.abspath(results_db)
    try:
        proc = subprocess.run([sys.executable, script], capture_output=True,
                              text=True, timeout=timeout, env=env)
    except subprocess.TimeoutExpired:
        raise StepError(f"Diaphora diff timed out after {timeout}s") from None
    except OSError as exc:
        raise StepError(f"cannot run Diaphora: {exc}", DIAPHORA_HINT) from None
    if not os.path.isfile(results_db):
        raise StepError(f"Diaphora wrote no results database (exit {proc.returncode})",
                        DIAPHORA_HINT, _tail(proc.stderr or proc.stdout))


# --------------------------------------------------------------------------- #
# report (no IDA, no Diaphora)
# --------------------------------------------------------------------------- #

def _as_int(value, base: int):
    """Parse one address, or None when it is not a number in that base."""
    if value is None:
        return None
    if isinstance(value, int):
        return value
    try:
        return int(str(value).strip(), base)
    except (TypeError, ValueError):
        return None


def _index_by_address(rows: list) -> dict:
    """int(address) -> row, for both of Diaphora's address spellings.

    Diaphora writes addresses as DECIMAL strings in an export database but as
    zero-padded HEX strings in a results database. Indexing under both readings
    keeps the join correct without betting on either convention — a bet that
    silently produced zero joins when it was wrong.
    """
    index = {}
    for row in rows:
        record = dict(row)
        for base in (10, 16):
            key = _as_int(record.get("address"), base)
            if key is not None:
                index.setdefault(key, record)
    return index


def _load_functions(db_path: str) -> dict:
    """address -> function row, from a Diaphora export database."""
    if not os.path.isfile(db_path):
        return {}
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT address, name, mangled_function, prototype, pseudocode, "
            "nodes, instructions, source_file FROM functions").fetchall()
        conn.close()
    except sqlite3.Error as exc:
        raise StepError(f"cannot read Diaphora export database {db_path}: {exc}",
                        DIAPHORA_HINT) from None
    return _index_by_address(rows)


def _lookup(index: dict, address) -> dict | None:
    """Resolve a results-table address against a function index (hex, then decimal)."""
    for base in (16, 10):
        key = _as_int(address, base)
        if key is not None and key in index:
            return index[key]
    return None


def _load_results(results_db: str) -> tuple[dict, list, list]:
    try:
        conn = sqlite3.connect(f"file:{results_db}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        config = conn.execute("SELECT * FROM config").fetchone()
        matches = [dict(r) for r in conn.execute(
            "SELECT type, address, name, address2, name2, ratio, nodes1, nodes2, "
            "description FROM results ORDER BY ratio ASC")]
        unmatched = [dict(r) for r in conn.execute(
            "SELECT type, address, name FROM unmatched")]
        conn.close()
    except sqlite3.Error as exc:
        raise StepError(f"cannot read Diaphora results database {results_db}: {exc}",
                        "expected a database written by `diaphora-diff diff`") from None
    return (dict(config) if config else {}), matches, unmatched


def _is_auto_name(name: str) -> bool:
    return not name or bool(AUTO_NAME.match(name))


# Identifiers Hex-Rays synthesises from an address. The address differs between
# any two builds, so the raw token carries no information about whether the thing
# being referenced actually changed.
ADDR_IDENT = re.compile(
    r"\b(j_sub|nullsub|sub|loc|off|unk|stru|jpt|flt|dbl|qword|dword|word|byte)"
    r"_([0-9A-Fa-f]{4,})\b")

# Hex-Rays' trailing allocation comments: `// eax`, `// [esp+32h] [ebp-12h]`.
TRAILING_COMMENT = re.compile(r"\s*//.*$")

# Compiler-assigned local variables. Adding one local renumbers every later one,
# so a one-line source change can rewrite half a function's text.
LOCAL_VAR = re.compile(r"\bv(\d+)\b")


def _strip_comment(line: str) -> str:
    """Drop a trailing // comment, unless the // sits inside a string literal."""
    match = TRAILING_COMMENT.search(line)
    if not match:
        return line
    if line.count('"', 0, match.start()) % 2:
        return line
    return line[:match.start()]


def normalize_pseudocode(text: str, token_map: dict | None = None) -> list[str]:
    """Strip decompiler bookkeeping so a diff shows source changes, not renumbering.

    Three sources of false difference are removed:

    1. trailing register/stack allocation comments;
    2. address-derived identifiers, rewritten to a token shared by both sides
       whenever the referenced function is itself a matched pair — so a call that
       merely moved reads as unchanged, while a call to a genuinely different
       function still stands out (unmatched addresses are left verbatim);
    3. local variable numbering, canonicalised to order of first appearance.

    Argument names (`a1`, `a2`) are deliberately NOT renumbered: their order is
    meaningful, and rewriting it would hide a real signature change.
    """
    token_map = token_map or {}
    lines = []
    for line in (text or "").splitlines():
        line = _strip_comment(line)

        def substitute(match: "re.Match") -> str:
            prefix, digits = match.group(1), match.group(2)
            try:
                token = token_map.get(int(digits, 16))
            except ValueError:
                token = None
            return token if token else match.group(0)

        lines.append(ADDR_IDENT.sub(substitute, line))

    head, decls, body = _split_declarations(lines)

    # Number locals by first use in the BODY, not in the declaration block: the
    # compiler's declaration order shifts freely between builds, and letting it
    # drive the numbering cascades that churn through every statement.
    ordinals: dict = {}
    for name in LOCAL_VAR.findall("\n".join(body)):
        ordinals.setdefault(name, f"v{len(ordinals) + 1}")
    for name in LOCAL_VAR.findall("\n".join(decls)):
        ordinals.setdefault(name, f"v{len(ordinals) + 1}")

    def renumber(text: str) -> str:
        return LOCAL_VAR.sub(lambda m: ordinals.get(m.group(1), m.group(0)), text)

    # The declaration block is collapsed to a count. These are compiler
    # temporaries, not source variables: their order, types and numbering churn
    # freely between builds and swamped the real change. The count still moves
    # when locals are added or removed, and --raw-pseudo shows them verbatim.
    summary = [f"  // {len(decls)} local(s)"] if decls else []
    return head + summary + [renumber(line) for line in body]


# A Hex-Rays local declaration: `char *v6;`, `int v1;`, `_BYTE v9[4];` — a simple
# statement with no call, no assignment, no control flow.
DECLARATION = re.compile(r"^\s*[A-Za-z_][A-Za-z0-9_ *]*\s\*?[A-Za-z_]\w*(\[\w*\])?;\s*$")


def _split_declarations(lines: list[str]) -> tuple[list, list, list]:
    """Split a decompiled function into (opening lines, declaration block, body)."""
    head: list = []
    decls: list = []
    index = 0
    # Opening brace / signature lines come first.
    while index < len(lines) and not lines[index].strip():
        head.append(lines[index])
        index += 1
    if index < len(lines) and lines[index].strip() in ("{", "}"):
        head.append(lines[index])
        index += 1
    while index < len(lines):
        line = lines[index]
        if not line.strip():
            decls.append(line)
        elif DECLARATION.match(line) and "return" not in line:
            decls.append(line)
        else:
            break
        index += 1
    # Blank padding at the end of the declaration run belongs with the body.
    while decls and not decls[-1].strip():
        decls.pop()
        index -= 1
    return head, decls, lines[index:]


def _pseudo_lines(fn: dict | None, token_map: dict | None = None,
                  normalize: bool = True) -> list[str]:
    if not fn or not fn.get("pseudocode"):
        return []
    text = fn["pseudocode"] or ""
    return normalize_pseudocode(text, token_map) if normalize else text.splitlines()


def build_token_map(matches: list) -> tuple[dict, dict]:
    """Per-side address -> shared token, so matched callees render identically."""
    primary_map, secondary_map = {}, {}
    for index, match in enumerate(matches):
        name = match.get("name") or ""
        token = name if name and not AUTO_NAME.match(name) else f"FN_{index}"
        # Only whitespace is unsafe here — `::`, `~`, `<>` are exactly how Hex-Rays
        # spells C++ methods, so keeping them makes the diff read like source.
        token = re.sub(r"\s+", "_", token)
        for side, address in ((primary_map, match.get("address")),
                              (secondary_map, match.get("address2"))):
            key = _as_int(address, 16)
            if key is not None:
                side.setdefault(key, token)
    return primary_map, secondary_map


def load_name_map(path: str | None) -> dict:
    """Load {address -> name} recovered by an earlier hop, keyed by int address.

    This is what lets name recovery chain: hop 1 recovers names onto build B, and
    feeding hop 1's renames.json in as hop 2's name map means B->C starts from the
    recovered names rather than from `sub_*` again. Without it every hop restarts
    from zero and only functions named in the original donor ever propagate.
    """
    if not path:
        return {}
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise StepError(f"cannot read name map {path}: {exc}",
                        "expected a renames.json produced by an earlier hop") from None
    entries = data if isinstance(data, list) else data.get("renames", [])
    mapping = {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        key = _as_int(entry.get("address"), 16)
        name = entry.get("newName")
        if key is not None and name:
            # Carry the mangled name and prototype too, not just the label. Past
            # hop 1 the primary export is itself stripped, so its own prototype is
            # a placeholder like `int __cdecl sub_8081600(_DWORD *a1)` — the C++
            # signature and parameter types would be lost one hop in, which is
            # precisely what makes a recovered name useful for source work.
            mapping[key] = {"newName": name,
                            "mangled": entry.get("mangled") or "",
                            "prototype": entry.get("prototype") or "",
                            "hops": entry.get("hops", 0)}
    return mapping


def build_report(db1: str, db2: str, results_db: str, min_ratio: float,
                 rename_types: tuple, name_map: dict | None = None) -> dict:
    """Correlate Diaphora's matches with both export databases."""
    config, matches, unmatched = _load_results(results_db)
    funcs1, funcs2 = _load_functions(db1), _load_functions(db2)
    name_map = name_map or {}
    if name_map:
        # Names recovered by an earlier hop stand in for the primary's own
        # (still autogenerated) names, so they carry another step down the chain.
        for match in matches:
            recovered = name_map.get(_as_int(match.get("address"), 16))
            if recovered and _is_auto_name(match.get("name") or ""):
                match["name"] = recovered["newName"]
                match["_carried"] = recovered

    identical, changed, renames = [], [], []
    resolved = 0
    for match in matches:
        addr1, addr2 = str(match["address"]), str(match["address2"])
        fn1, fn2 = _lookup(funcs1, addr1), _lookup(funcs2, addr2)
        if fn1 is not None and fn2 is not None:
            resolved += 1
        ratio = float(match["ratio"] or 0.0)
        record = {
            "type": match["type"],
            "ratio": ratio,
            "heuristic": match["description"],
            "primary": {"address": addr1, "name": match["name"],
                        "prototype": (fn1 or {}).get("prototype") or "",
                        "mangled": (fn1 or {}).get("mangled_function") or "",
                        "sourceFile": (fn1 or {}).get("source_file") or ""},
            "secondary": {"address": addr2, "name": match["name2"],
                          "prototype": (fn2 or {}).get("prototype") or "",
                          "mangled": (fn2 or {}).get("mangled_function") or ""},
            "nodes": [match["nodes1"], match["nodes2"]],
        }
        (identical if ratio >= 1.0 else changed).append(record)

        # Name recovery: primary has a real symbol, secondary does not.
        if (match["type"] in rename_types and ratio >= min_ratio
                and not _is_auto_name(match["name"]) and _is_auto_name(match["name2"])):
            # When the name was inherited, the primary's own metadata describes a
            # stripped function; the carried metadata is the real signature.
            carried = match.get("_carried")
            renames.append({
                "address": addr2,
                "newName": match["name"],
                "fromAddress": addr1,
                "ratio": ratio,
                "type": match["type"],
                "heuristic": match["description"],
                "mangled": (carried or {}).get("mangled")
                           or (fn1 or {}).get("mangled_function") or "",
                "prototype": (carried or {}).get("prototype")
                             or (fn1 or {}).get("prototype") or "",
                "hops": (carried or {}).get("hops", 0) + 1,
            })

    # Changed functions read best ascending (biggest change first); recovered names
    # read best descending (most trustworthy first) — opposite orders, same data.
    renames.sort(key=lambda r: r["ratio"], reverse=True)

    return {
        "primaryDb": config.get("main_db", db1),
        "secondaryDb": config.get("diff_db", db2),
        "diaphoraVersion": config.get("version", ""),
        # `matched` counts result ROWS; a multimatch lists one function against
        # several candidates, so rows overstate how many functions were paired.
        # The distinct counts are the ones to reason about.
        "counts": {
            "primaryFunctions": len({f["address"] for f in funcs1.values()}) or None,
            "secondaryFunctions": len({f["address"] for f in funcs2.values()}) or None,
            "matched": len(matches),
            "matchedDistinctPrimary": len({m["address"] for m in matches}),
            "matchedDistinctSecondary": len({m["address2"] for m in matches}),
            # Share of matches joined back to both export databases. Anything below
            # 1.0 means prototypes, mangled names and pseudocode diffs are partly
            # missing — surfaced rather than left to fail silently.
            "joinResolution": round(resolved / len(matches), 4) if matches else None,
            "identical": len(identical),
            "changed": len(changed),
            "byType": {t: sum(1 for m in matches if m["type"] == t) for t in MATCH_TYPES},
            "recoverableNames": len(renames),
            "unmatchedPrimary": sum(1 for u in unmatched if u["type"] == "primary"),
            "unmatchedSecondary": sum(1 for u in unmatched if u["type"] == "secondary"),
        },
        "identical": identical,
        "changed": changed,
        "renames": renames,
        "unmatched": unmatched,
        "_funcs1": funcs1,
        "_funcs2": funcs2,
        "_tokenMaps": build_token_map(matches),
    }


def write_pseudo_diffs(report: dict, outdir: str, limit: int,
                       normalize: bool = True) -> list:
    """Unified pseudocode diffs for changed functions — the documentation payload."""
    funcs1, funcs2 = report["_funcs1"], report["_funcs2"]
    if not funcs1 or not funcs2:
        return []
    map1, map2 = report["_tokenMaps"] if normalize else ({}, {})
    diff_dir = os.path.join(outdir, "pseudo")
    os.makedirs(diff_dir, exist_ok=True)
    written = []
    for record in report["changed"]:
        # The cap bounds files actually written, not candidates considered: a match
        # whose pseudocode is identical on both sides produces no diff and must not
        # consume a slot.
        if len(written) >= limit:
            break
        left = _pseudo_lines(_lookup(funcs1, record["primary"]["address"]),
                             map1, normalize)
        right = _pseudo_lines(_lookup(funcs2, record["secondary"]["address"]),
                              map2, normalize)
        if not left and not right:
            continue
        name = record["primary"]["name"] or record["secondary"]["name"] or "unnamed"
        safe = re.sub(r"[^A-Za-z0-9_.-]", "_", name)[:80]
        text = "\n".join(difflib.unified_diff(
            left, right,
            fromfile=f"{record['primary']['name']} @ {record['primary']['address']}",
            tofile=f"{record['secondary']['name']} @ {record['secondary']['address']}",
            lineterm=""))
        if not text.strip():
            continue
        path = os.path.join(diff_dir, f"{record['ratio']:.3f}_{safe}.diff")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text + "\n")
        written.append(os.path.relpath(path, outdir))
    return written


IDA_RENAME_TEMPLATE = '''\
# Generated by rekit diaphora-diff — apply recovered names to the SECONDARY binary.
#
# Run inside IDA on the secondary/stripped database:
#     File > Script file...   (or: idat -A -S"{script_name}" <binary>)
#
# Every name here came from a Diaphora match at ratio >= {min_ratio} of type
# {types}. Review before trusting: a match is evidence, not proof.

import ida_name
import idc

RENAMES = {renames}

def main():
    applied = skipped = 0
    for address, name in RENAMES:
        ea = int(address, 16) if isinstance(address, str) else address
        current = idc.get_func_name(ea)
        if current and not current.startswith(("sub_", "nullsub_", "j_sub_")):
            skipped += 1  # already named; never clobber existing work
            continue
        applied += 1 if ida_name.set_name(
            ea, name, ida_name.SN_NOWARN | ida_name.SN_FORCE) else 0
    print("rekit diaphora-diff: applied %d name(s), skipped %d already-named" %
          (applied, skipped))

main()
'''


def write_rename_script(report: dict, outdir: str, min_ratio: float,
                        rename_types: tuple) -> str | None:
    if not report["renames"]:
        return None
    pairs = [(r["address"], r["newName"]) for r in report["renames"]]
    path = os.path.join(outdir, "apply_names.py")
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(IDA_RENAME_TEMPLATE.format(
            script_name="apply_names.py", min_ratio=min_ratio,
            types="/".join(rename_types),
            renames=json.dumps(pairs, indent=4)))
    return path


def render_text(report: dict, top: int, files: dict) -> str:
    counts = report["counts"]
    by_type = ", ".join(f"{t} {counts['byType'][t]}" for t in MATCH_TYPES
                        if counts["byType"][t])
    lines = [
        f"diaphora-diff: {counts['matched']} match rows ({by_type})",
        f"  {counts['matchedDistinctPrimary']} distinct primary functions paired "
        f"of {counts['primaryFunctions']}",
        f"  {counts['identical']} identical, {counts['changed']} changed",
        f"  {counts['unmatchedPrimary']} unmatched in primary, "
        f"{counts['unmatchedSecondary']} unmatched in secondary",
        f"  {counts['recoverableNames']} names recoverable primary -> secondary",
    ]
    if counts.get("joinResolution") is not None and counts["joinResolution"] < 1.0:
        lines.append(f"  WARNING: only {counts['joinResolution']:.1%} of matches joined "
                     f"back to the export databases — prototypes and pseudocode "
                     f"diffs are incomplete")

    if report["renames"]:
        shown = report["renames"][:top]
        lines.append("")
        lines.append(f"recoverable names (showing {len(shown)} of "
                     f"{len(report['renames'])}):")
        for r in shown:
            lines.append(f"  {r['ratio']:.3f} [{r['type']}] {r['address']} -> "
                         f"{r['newName']}")

    if report["changed"]:
        shown = report["changed"][:top]
        lines.append("")
        lines.append(f"changed functions, least similar first (showing {len(shown)} of "
                     f"{len(report['changed'])}):")
        for c in shown:
            name = c["primary"]["name"] or c["secondary"]["name"]
            lines.append(f"  {c['ratio']:.3f} [{c['type']}] {name}  "
                         f"{c['primary']['address']} -> {c['secondary']['address']}"
                         f"   ({c['heuristic']})")

    lines.append("")
    for key, value in files.items():
        if value:
            lines.append(f"  {key}: {value}")
    return "\n".join(lines)


def emit_report(report: dict, outdir: str, args, extra: dict) -> dict:
    os.makedirs(outdir, exist_ok=True)
    rename_types = tuple(args.rename_types.split(","))

    matches_file = os.path.join(outdir, "matches.json")
    with open(matches_file, "w", encoding="utf-8") as handle:
        json.dump({"identical": report["identical"], "changed": report["changed"]},
                  handle, indent=2)
    renames_file = os.path.join(outdir, "renames.json")
    with open(renames_file, "w", encoding="utf-8") as handle:
        json.dump(report["renames"], handle, indent=2)
    unmatched_file = os.path.join(outdir, "unmatched.json")
    with open(unmatched_file, "w", encoding="utf-8") as handle:
        json.dump(report["unmatched"], handle, indent=2)

    pseudo = write_pseudo_diffs(report, outdir, args.max_pseudo_diffs,
                                normalize=not args.raw_pseudo)
    rename_script = write_rename_script(report, outdir, args.min_ratio, rename_types)

    files = {"matchesFile": matches_file, "renamesFile": renames_file,
             "unmatchedFile": unmatched_file, "renameScript": rename_script,
             "pseudoDiffs": os.path.join(outdir, "pseudo") if pseudo else None,
             **extra}
    summary = {
        "ok": True, "tool": "diaphora",
        "diaphoraVersion": report["diaphoraVersion"],
        "counts": report["counts"],
        "topRenames": report["renames"][:args.top],
        "topChanged": report["changed"][:args.top],
        "pseudoDiffCount": len(pseudo),
        "pseudoNormalized": not args.raw_pseudo,
        **{k: v for k, v in files.items() if v},
    }
    summary_file = os.path.join(outdir, "summary.json")
    with open(summary_file, "w", encoding="utf-8") as handle:
        json.dump(summary, handle, indent=2)
    summary["summaryFile"] = summary_file
    files["summaryFile"] = summary_file

    if args.format == "json":
        print(json.dumps(summary))
    else:
        print(render_text(report, args.top, files))
    return summary


# --------------------------------------------------------------------------- #

def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="diaphora-diff")
    p.add_argument("op", choices=["export", "diff", "report", "compare"])
    p.add_argument("target")
    p.add_argument("other", nargs="?")
    p.add_argument("outdir", nargs="?")
    p.add_argument("--results", help="report op: existing Diaphora results database")
    p.add_argument("--cache", help="compare op: export cache dir (default <outdir>/cache)")
    p.add_argument("--ida", help="path to idat (export/compare)")
    p.add_argument("--decompiler", action="store_true",
                   help="export with Hex-Rays pseudocode (slower, much better matching)")
    p.add_argument("--min-ratio", type=float, default=0.75,
                   help="minimum match ratio for a name to be considered recoverable")
    p.add_argument("--rename-types", default="best,partial",
                   help="match types eligible for name recovery")
    p.add_argument("--top", type=int, default=25)
    p.add_argument("--max-pseudo-diffs", type=int, default=200)
    p.add_argument("--name-map",
                   help="renames.json from an earlier hop, so recovered names carry "
                        "forward instead of each hop restarting from sub_*")
    p.add_argument("--raw-pseudo", action="store_true",
                   help="diff pseudocode verbatim, without stripping decompiler "
                        "renumbering and address noise")
    p.add_argument("--format", choices=["text", "json"], default="text")
    p.add_argument("--timeout", type=int, default=7200)
    a = p.parse_args(argv[1:])

    def fail(payload: dict, code: int) -> int:
        print(json.dumps(payload))
        return code

    try:
        if a.op == "export":
            if not os.path.isfile(a.target):
                return fail({"ok": False, "error": f"file not found: {a.target}"}, 2)
            if not a.other:
                return fail({"ok": False, "error": "export needs an output database path"}, 2)
            result = export(a.target, a.other, a.ida, a.decompiler, a.timeout)
            summary = {"ok": True, "tool": "diaphora", **result}
            print(json.dumps(summary) if a.format == "json" else
                  f"diaphora-diff: exported {result['functions']} functions "
                  f"→ {result['exportDb']}")
            return 0

        if a.op == "report":
            if not a.results:
                return fail({"ok": False, "error": "report needs --results <db>"}, 2)
            if not a.outdir:
                return fail({"ok": False, "error": "report needs an outdir"}, 2)
            report = build_report(a.target, a.other or "", a.results, a.min_ratio,
                                  tuple(a.rename_types.split(",")),
                                  load_name_map(a.name_map))
            emit_report(report, a.outdir, a, {"resultsDb": os.path.abspath(a.results)})
            return 0

        if a.op == "diff":
            if not (a.other and a.outdir):
                return fail({"ok": False, "error": "diff needs <db1> <db2> <outdir>"}, 2)
            for path in (a.target, a.other):
                if not os.path.isfile(path):
                    return fail({"ok": False, "error": f"file not found: {path}"}, 2)
            os.makedirs(a.outdir, exist_ok=True)
            results_db = os.path.abspath(os.path.join(a.outdir, "results.sqlite"))
            diff(a.target, a.other, results_db, a.timeout)
            report = build_report(a.target, a.other, results_db, a.min_ratio,
                                  tuple(a.rename_types.split(",")),
                                  load_name_map(a.name_map))
            emit_report(report, a.outdir, a, {"resultsDb": results_db})
            return 0

        # compare: export both (cached), then diff
        if not (a.other and a.outdir):
            return fail({"ok": False, "error": "compare needs <binaryA> <binaryB> <outdir>"}, 2)
        for path in (a.target, a.other):
            if not os.path.isfile(path):
                return fail({"ok": False, "error": f"file not found: {path}"}, 2)
        os.makedirs(a.outdir, exist_ok=True)
        cache = a.cache or os.path.join(a.outdir, "cache")
        first = cached_export(a.target, cache, a.ida, a.decompiler, a.timeout)
        second = cached_export(a.other, cache, a.ida, a.decompiler, a.timeout)
        results_db = os.path.abspath(os.path.join(a.outdir, "results.sqlite"))
        diff(first["exportDb"], second["exportDb"], results_db, a.timeout)
        report = build_report(first["exportDb"], second["exportDb"], results_db,
                              a.min_ratio, tuple(a.rename_types.split(",")),
                              load_name_map(a.name_map))
        emit_report(report, a.outdir, a, {
            "resultsDb": results_db,
            "primaryExportDb": first["exportDb"],
            "secondaryExportDb": second["exportDb"],
        })
        return 0

    except StepError as exc:
        payload = {"ok": False, "error": str(exc)}
        if exc.hint:
            payload["hint"] = exc.hint
        if exc.log:
            payload["log"] = exc.log
        return fail(payload, 1)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

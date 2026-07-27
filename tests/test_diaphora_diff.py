from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "skills" / "diaphora-diff" / "scripts" / "run.py"

# Subset of Diaphora's export schema that the report path reads.
EXPORT_SCHEMA = """
CREATE TABLE functions (
  id integer primary key, name varchar(255), address text unique, nodes integer,
  edges integer, instructions integer, prototype text, mangled_function text,
  pseudocode text, source_file text
)"""

RESULTS_SCHEMA = """
CREATE TABLE config (main_db text, diff_db text, version text, date text);
CREATE TABLE results (type, line, address, name, address2, name2, ratio,
                      nodes1, nodes2, description);
CREATE TABLE unmatched (type, line, address, name)
"""


def dec(address: int) -> str:
    """Export databases spell addresses as DECIMAL strings, as Diaphora does."""
    return str(address)


def hexs(address: int) -> str:
    """Results databases spell the same addresses as zero-padded HEX strings."""
    return f"{address:08x}"


def make_export(path: Path, rows: list[dict]) -> None:
    conn = sqlite3.connect(path)
    conn.executescript(EXPORT_SCHEMA)
    for i, row in enumerate(rows):
        conn.execute(
            "INSERT INTO functions (id, name, address, nodes, edges, instructions,"
            " prototype, mangled_function, pseudocode, source_file)"
            " VALUES (?,?,?,?,?,?,?,?,?,?)",
            (i, row["name"], row["address"], row.get("nodes", 4), 5,
             row.get("instructions", 30), row.get("prototype", ""),
             row.get("mangled", ""), row.get("pseudocode", ""),
             row.get("source_file", "")))
    conn.commit()
    conn.close()


def make_results(path: Path, matches: list[tuple], unmatched: list[tuple]) -> None:
    conn = sqlite3.connect(path)
    conn.executescript(RESULTS_SCHEMA)
    conn.execute("INSERT INTO config VALUES ('a.sqlite','b.sqlite','3.4.1','now')")
    for i, m in enumerate(matches):
        # type, address, name, address2, name2, ratio, description
        conn.execute("INSERT INTO results VALUES (?,?,?,?,?,?,?,?,?,?)",
                     (m[0], i, m[1], m[2], m[3], m[4], m[5], 4, 4, m[6]))
    for i, u in enumerate(unmatched):
        conn.execute("INSERT INTO unmatched VALUES (?,?,?,?)", (u[0], i, u[1], u[2]))
    conn.commit()
    conn.close()


PRIMARY_ROWS = [
    {"name": "CPlayer::Update", "address": dec(0x8048100),
     "mangled": "_ZN7CPlayer6UpdateEv", "prototype": "void CPlayer::Update(void)",
     "pseudocode": "void CPlayer::Update() {\n  tick();\n  draw();\n}"},
    {"name": "CStep::Judge", "address": dec(0x8048200),
     "mangled": "_ZN5CStep5JudgeEi", "prototype": "int CStep::Judge(int)",
     "pseudocode": "int CStep::Judge(int a) {\n  return a > 5;\n}"},
    {"name": "sub_8048300", "address": dec(0x8048300),
     "pseudocode": "void f() { g(); }"},
    {"name": "CDeleted::Gone", "address": dec(0x8048400),
     "pseudocode": "void gone() {}"},
]

SECONDARY_ROWS = [
    {"name": "sub_9000100", "address": dec(0x9000100),
     "pseudocode": "void sub_9000100() {\n  tick();\n  draw();\n}"},
    {"name": "sub_9000200", "address": dec(0x9000200),
     "pseudocode": "int sub_9000200(int a) {\n  return a > 7;\n}"},
    {"name": "sub_9000300", "address": dec(0x9000300),
     "pseudocode": "void f() { g(); }"},
    {"name": "sub_9000500", "address": dec(0x9000500),
     "pseudocode": "void brand_new() {}"},
]

MATCHES = [
    # type, addr1, name1, addr2, name2, ratio, heuristic
    ("best", hexs(0x8048100), "CPlayer::Update", hexs(0x9000100), "sub_9000100", 1.0,
     "Same pseudocode"),
    ("partial", hexs(0x8048200), "CStep::Judge", hexs(0x9000200), "sub_9000200", 0.82,
     "Pseudocode fuzzy hash"),
    ("unreliable", hexs(0x8048300), "sub_8048300", hexs(0x9000300), "sub_9000300", 0.55,
     "Small primes product"),
]
UNMATCHED = [("primary", hexs(0x8048400), "CDeleted::Gone"),
             ("secondary", hexs(0x9000500), "sub_9000500")]


class StemTest(unittest.TestCase):
    """Version-numbered build names must survive cache-filename derivation."""

    def setUp(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("diaphora_run", RUNNER)
        self.mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.mod)

    def test_version_suffixes_are_preserved(self):
        self.assertEqual(self.mod.stem("/x/piu-1.08-unstripped"), "piu-1.08-unstripped")
        self.assertEqual(self.mod.stem("/x/app-2.3.1"), "app-2.3.1")
        self.assertEqual(self.mod.stem("/x/piu-40316"), "piu-40316")

    def test_known_extensions_are_stripped(self):
        self.assertEqual(self.mod.stem("/x/piu-1.03.i64"), "piu-1.03")
        self.assertEqual(self.mod.stem("/x/game.EXE"), "game")


class NormalizeTest(unittest.TestCase):
    """Decompiler bookkeeping must not read as a source change."""

    def setUp(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("diaphora_norm", RUNNER)
        self.mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.mod)

    def norm(self, text, token_map=None):
        return self.mod.normalize_pseudocode(text, token_map)

    def test_strips_allocation_comments(self):
        self.assertEqual(self.norm("  v3 = f(a1); // eax"), ["  v1 = f(a1);"])
        self.assertEqual(self.norm("  return g(); // [esp+32h] [ebp-12h]"),
                         ["  return g();"])

    def test_keeps_double_slash_inside_string_literals(self):
        line = '  strcpy(dest, "http://example.com");'
        self.assertEqual(self.norm(line), [line])

    def test_local_renumbering_is_canonicalised(self):
        # Same code, different Hex-Rays numbering — must normalise identically.
        a = "int f() {\n  int v3 = 1;\n  int v7 = v3;\n  return v7;\n}"
        b = "int f() {\n  int v2 = 1;\n  int v9 = v2;\n  return v9;\n}"
        self.assertEqual(self.norm(a), self.norm(b))
        self.assertIn("  int v1 = 1;", self.norm(a))

    def test_argument_numbering_is_preserved(self):
        # a1/a2 order is a real signature fact — normalising it would hide changes.
        self.assertEqual(self.norm("f(a2, a1);"), ["f(a2, a1);"])
        self.assertNotEqual(self.norm("f(a1, a2);"), self.norm("f(a2, a1);"))

    def test_matched_callees_collapse_to_a_shared_token(self):
        matches = [{"address": "08098f20", "address2": "080a2e40",
                    "name": "CPlayer::Tick"}]
        map1, map2 = self.mod.build_token_map(matches)
        left = self.norm("  x = sub_8098F20(y);", map1)
        right = self.norm("  x = sub_80A2E40(y);", map2)
        self.assertEqual(left, right)
        self.assertIn("CPlayer::Tick", left[0])

    def test_unmatched_callees_stay_visible(self):
        # No match means we cannot claim the callees are the same; leave them
        # verbatim so a genuine difference is not silently normalised away.
        map1, map2 = self.mod.build_token_map([])
        self.assertNotEqual(self.norm("  sub_8098F20();", map1),
                            self.norm("  sub_80A2E40();", map2))

    def test_anonymous_matched_callee_still_collapses(self):
        matches = [{"address": "08098f20", "address2": "080a2e40",
                    "name": "sub_8098F20"}]
        map1, map2 = self.mod.build_token_map(matches)
        self.assertEqual(self.norm("  sub_8098F20();", map1),
                         self.norm("  sub_80A2E40();", map2))

    def test_declaration_reordering_is_not_a_difference(self):
        a = "{\n  int v1;\n  char *v2;\n  v1 = 1;\n  v2 = nullptr;\n}"
        b = "{\n  char *v2;\n  int v1;\n  v1 = 1;\n  v2 = nullptr;\n}"
        self.assertEqual(self.norm(a), self.norm(b))

    def test_declaration_block_collapses_to_a_count(self):
        a = "{\n  int v1;\n  v1 = 1;\n}"
        b = "{\n  int v1;\n  char *v2;\n  v1 = 1;\n}"
        self.assertIn("  // 1 local(s)", self.norm(a))
        self.assertIn("  // 2 local(s)", self.norm(b))
        self.assertNotEqual(self.norm(a), self.norm(b))

    def test_body_drives_local_numbering_not_declaration_order(self):
        # Same body, declarations listed in opposite order and numbered
        # differently — the statements must normalise identically.
        a = "{\n  int v7;\n  char *v3;\n  v3 = f();\n  v7 = 1;\n}"
        b = "{\n  char *v2;\n  int v9;\n  v2 = f();\n  v9 = 1;\n}"
        self.assertEqual(self.norm(a)[-3:], self.norm(b)[-3:])

    def test_data_references_are_normalised_too(self):
        matches = [{"address": "0812c324", "address2": "0813d440", "name": "g_state"}]
        map1, map2 = self.mod.build_token_map(matches)
        self.assertEqual(self.norm("  return dword_812C324;", map1),
                         self.norm("  return dword_813D440;", map2))


class ReportTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.db1 = self.tmp / "primary.sqlite"
        self.db2 = self.tmp / "secondary.sqlite"
        self.results = self.tmp / "results.sqlite"
        self.outdir = self.tmp / "out"
        make_export(self.db1, PRIMARY_ROWS)
        make_export(self.db2, SECONDARY_ROWS)
        make_results(self.results, MATCHES, UNMATCHED)
        self.addCleanup(self._tmp.cleanup)

    def report(self, *extra: str):
        proc = subprocess.run(
            [sys.executable, str(RUNNER), "report", str(self.db1), str(self.db2),
             str(self.outdir), "--results", str(self.results), *extra],
            capture_output=True, text=True)
        return proc

    def test_joins_across_diaphoras_two_address_spellings(self):
        """Export DBs store decimal addresses, results DBs zero-padded hex.

        Comparing them as raw strings joins nothing and degrades silently: no
        prototypes, no mangled names, no pseudocode diffs — but a cheerful
        summary. joinResolution exists to make that failure loud.
        """
        result = json.loads(self.report("--format", "json").stdout)
        self.assertEqual(result["counts"]["joinResolution"], 1.0)
        matches = json.loads((self.outdir / "matches.json").read_text())
        paired = matches["identical"] + matches["changed"]
        self.assertTrue(all(m["primary"]["prototype"] or m["primary"]["name"].startswith("sub_")
                            for m in paired))
        by_name = {m["primary"]["name"]: m for m in paired}
        self.assertEqual(by_name["CPlayer::Update"]["primary"]["mangled"],
                         "_ZN7CPlayer6UpdateEv")

    def test_distinct_counts_separate_rows_from_functions(self):
        result = json.loads(self.report("--format", "json").stdout)
        counts = result["counts"]
        self.assertEqual(counts["matched"], 3)  # result rows
        self.assertEqual(counts["matchedDistinctPrimary"], 3)
        self.assertEqual(counts["matchedDistinctSecondary"], 3)

    def test_name_map_carries_recovered_names_to_the_next_hop(self):
        """Hop 2's primary is still stripped; without a name map nothing chains."""
        # Baseline: 0x8048300 <-> 0x9000300 is sub_ on both sides, so unrecoverable.
        base = json.loads(self.report("--format", "json", "--min-ratio", "0.5",
                                      "--rename-types", "best,partial,unreliable").stdout)
        self.assertNotIn(hexs(0x9000300),
                         {r["address"] for r in base["topRenames"]})

        # An earlier hop recovered a name for that primary address; now it chains.
        name_map = self.tmp / "hop1-renames.json"
        name_map.write_text(json.dumps(
            [{"address": hexs(0x8048300), "newName": "CAudio::Mix"}]))
        chained = json.loads(self.report(
            "--format", "json", "--min-ratio", "0.5",
            "--rename-types", "best,partial,unreliable",
            "--name-map", str(name_map)).stdout)
        recovered = {r["address"]: r["newName"] for r in chained["topRenames"]}
        self.assertEqual(recovered.get(hexs(0x9000300)), "CAudio::Mix")

    def test_name_map_never_overrides_a_real_primary_name(self):
        name_map = self.tmp / "bad.json"
        name_map.write_text(json.dumps(
            [{"address": hexs(0x8048100), "newName": "WRONG"}]))
        result = json.loads(self.report("--format", "json",
                                        "--name-map", str(name_map)).stdout)
        names = {r["address"]: r["newName"] for r in result["topRenames"]}
        self.assertEqual(names[hexs(0x9000100)], "CPlayer::Update")

    def test_counts_and_classification(self):
        proc = self.report("--format", "json")
        self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
        result = json.loads(proc.stdout)
        counts = result["counts"]
        self.assertEqual(counts["matched"], 3)
        self.assertEqual(counts["identical"], 1)
        self.assertEqual(counts["changed"], 2)
        self.assertEqual(counts["byType"], {"best": 1, "partial": 1,
                                            "unreliable": 1, "multimatch": 0})
        self.assertEqual(counts["unmatchedPrimary"], 1)
        self.assertEqual(counts["unmatchedSecondary"], 1)
        self.assertEqual(counts["primaryFunctions"], 4)

    def test_recovers_names_only_where_useful(self):
        result = json.loads(self.report("--format", "json").stdout)
        names = {r["address"]: r["newName"] for r in result["topRenames"]}
        # best + partial with real primary names and auto secondary names
        self.assertEqual(names, {hexs(0x9000100): "CPlayer::Update",
                                 hexs(0x9000200): "CStep::Judge"})
        # the unreliable match is excluded by --rename-types, and its primary name
        # is autogenerated anyway — nothing to learn from porting sub_ -> sub_
        self.assertNotIn(hexs(0x9000300), names)
        recovered = json.loads((self.outdir / "renames.json").read_text())
        self.assertEqual(recovered[0]["mangled"], "_ZN7CPlayer6UpdateEv")
        self.assertEqual(recovered[0]["prototype"], "void CPlayer::Update(void)")

    def test_min_ratio_gates_name_recovery(self):
        result = json.loads(self.report("--format", "json", "--min-ratio", "0.9").stdout)
        self.assertEqual([r["newName"] for r in result["topRenames"]],
                         ["CPlayer::Update"])

    def test_rename_types_can_be_widened(self):
        result = json.loads(self.report(
            "--format", "json", "--min-ratio", "0.5",
            "--rename-types", "best,partial,unreliable").stdout)
        # widening reaches the unreliable match, but its primary name is still
        # autogenerated, so it contributes nothing
        self.assertEqual(len(result["topRenames"]), 2)

    def test_generates_reviewable_ida_script(self):
        result = json.loads(self.report("--format", "json").stdout)
        script = Path(result["renameScript"])
        self.assertTrue(script.is_file())
        body = script.read_text()
        self.assertIn("CPlayer::Update", body)
        self.assertIn(hexs(0x9000100), body)
        # the script parses these as hex — verify the round trip
        self.assertEqual(int(hexs(0x9000100), 16), 0x9000100)
        # must refuse to clobber names that already exist
        self.assertIn("already named", body)
        compile(body, str(script), "exec")  # generated script must be valid Python

    def test_pseudocode_diffs_for_changed_functions(self):
        result = json.loads(self.report("--format", "json").stdout)
        self.assertGreaterEqual(result["pseudoDiffCount"], 1)
        diffs = sorted((self.outdir / "pseudo").glob("*.diff"))
        self.assertTrue(diffs)
        text = "\n".join(p.read_text() for p in diffs)
        self.assertIn("-  return a > 5;", text)
        self.assertIn("+  return a > 7;", text)
        # the identical match must not produce a diff file
        self.assertNotIn("CPlayer::Update", "\n".join(p.name for p in diffs))

    def test_max_pseudo_diffs_caps_output(self):
        result = json.loads(self.report("--format", "json",
                                        "--max-pseudo-diffs", "1").stdout)
        self.assertEqual(result["pseudoDiffCount"], 1)

    def test_text_report(self):
        proc = self.report()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("names recoverable", proc.stdout)
        self.assertIn("CPlayer::Update", proc.stdout)
        self.assertIn("changed functions", proc.stdout)

    def test_report_requires_results_db(self):
        proc = subprocess.run(
            [sys.executable, str(RUNNER), "report", str(self.db1), str(self.db2),
             str(self.outdir)], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 2)
        self.assertIn("--results", json.loads(proc.stdout)["error"])

    def test_missing_diaphora_runtime_is_honest(self):
        # Asserted in-process against a runtime dir that does not exist, so the
        # result does not depend on whether this checkout has run `rekit install`.
        import importlib.util
        spec = importlib.util.spec_from_file_location("diaphora_run_missing", RUNNER)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        mod.DIAPHORA_DIR = str(self.tmp / "not-installed")
        with self.assertRaises(mod.StepError) as caught:
            mod._diaphora_script("diaphora.py")
        self.assertIn("vendored Diaphora not found", str(caught.exception))
        self.assertIn("rekit install diaphora-diff", caught.exception.hint)


if __name__ == "__main__":
    unittest.main()

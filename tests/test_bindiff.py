from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "skills" / "bindiff" / "scripts"
RUNNER = SKILL / "run.py"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, SKILL / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


binexport_read = _load("binexport_read")


# --------------------------------------------------------------------------- #
# Minimal BinExport2 protobuf encoder (test-side mirror of the reader)
# --------------------------------------------------------------------------- #

def _varint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def _tag(field: int, wire: int) -> bytes:
    return _varint((field << 3) | wire)


def _uint(field: int, value: int) -> bytes:
    return _tag(field, 0) + _varint(value)


def _bytes(field: int, payload: bytes) -> bytes:
    return _tag(field, 2) + _varint(len(payload)) + payload


def _str(field: int, text: str) -> bytes:
    return _bytes(field, text.encode("utf-8"))


def make_binexport_file(path: Path, name: str,
                        functions: list[tuple[int, int, str]]) -> None:
    """functions: (address, vertex_type, mangled_name)."""
    meta = _str(1, name) + _str(2, "id-" + name) + _str(3, "x86-64") + _uint(4, 1700000000)
    call_graph = b"".join(
        _bytes(1, _uint(1, addr) + _uint(2, vtype) + (_str(3, fname) if fname else b""))
        for addr, vtype, fname in functions
    )
    path.write_bytes(_bytes(1, meta) + _bytes(8, call_graph))


PRIMARY_FUNCS = [
    (0x1000, 0, "main"),
    (0x1100, 0, "check_license"),
    (0x1200, 0, "removed_helper"),
    (0x1300, 2, "printf"),          # imported: never listed as removed code
]
SECONDARY_FUNCS = [
    (0x2000, 0, "main"),
    (0x2100, 0, "verify_license"),  # renamed + changed
    (0x2200, 0, "new_telemetry"),   # added
    (0x2300, 2, "printf"),
]

MATCHES = [
    # address1, name1, address2, name2, similarity, confidence, algorithm id
    (0x1000, "main", 0x2000, "main", 1.0, 0.99, 1),
    (0x1100, "check_license", 0x2100, "verify_license", 0.62, 0.88, 2),
]


def fake_bindiff(directory: Path) -> Path:
    """A stand-in `bindiff` that writes a real-schema .BinDiff result database."""
    executable = directory / "bindiff"
    matches = json.dumps(MATCHES)
    executable.write_text(
        textwrap.dedent(
            f"""\
            #!{sys.executable}
            import os, sqlite3, sys

            if "--print_config" in sys.argv[1:]:
                print('{{"version": 8}}')  # health check used by `rekit doctor`
                raise SystemExit(0)

            flags = {{}}
            for arg in sys.argv[1:]:
                if arg.startswith("--") and "=" in arg:
                    key, _, value = arg[2:].partition("=")
                    flags[key] = value
            out = os.path.join(
                flags["output_dir"],
                os.path.splitext(os.path.basename(flags["primary"]))[0] + "_vs_" +
                os.path.splitext(os.path.basename(flags["secondary"]))[0] + ".BinDiff")
            db = sqlite3.connect(out)
            db.executescript(
                "CREATE TABLE functionalgorithm (id SMALLINT PRIMARY KEY, name TEXT);"
                "CREATE TABLE basicblockalgorithm (id SMALLINT PRIMARY KEY, name TEXT);"
                "CREATE TABLE file (id INT, filename TEXT, exefilename TEXT, hash CHARACTER(40),"
                " functions INT, libfunctions INT, calls INT, basicblocks INT,"
                " libbasicblocks INT, edges INT, libedges INT, instructions INT,"
                " libinstructions INT);"
                "CREATE TABLE metadata (version TEXT, file1 INT, file2 INT, description TEXT,"
                " created DATE, modified DATE, similarity DOUBLE PRECISION,"
                " confidence DOUBLE PRECISION);"
                "CREATE TABLE function (id INT, address1 BIGINT, name1 TEXT, address2 BIGINT,"
                " name2 TEXT, similarity DOUBLE PRECISION, confidence DOUBLE PRECISION,"
                " flags INTEGER, algorithm SMALLINT, evaluate BOOLEAN,"
                " commentsported BOOLEAN, basicblocks INTEGER, edges INTEGER,"
                " instructions INTEGER);")
            db.executemany("INSERT INTO functionalgorithm VALUES (?,?)",
                           [(1, "function: name hash matching"),
                            (2, "function: MD index matching")])
            db.execute("INSERT INTO file VALUES (1,'a','a.exe','h1',3,0,0,9,0,0,0,40,0)")
            db.execute("INSERT INTO file VALUES (2,'b','b.exe','h2',3,0,0,9,0,0,0,44,0)")
            db.execute("INSERT INTO metadata VALUES ('8.0',1,2,'',date('now'),date('now'),"
                       "0.81,0.93)")
            for i, m in enumerate({matches}):
                db.execute("INSERT INTO function VALUES (?,?,?,?,?,?,?,0,?,1,0,4,5,20)",
                           (i, m[0], m[1], m[2], m[3], m[4], m[5], m[6]))
            db.commit()
            db.close()
            print("Diffing done")
            """
        )
    )
    executable.chmod(0o755)
    return executable


class BinExportReaderTest(unittest.TestCase):
    def test_parses_meta_and_call_graph(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "a.BinExport"
            make_binexport_file(path, "sample.exe", PRIMARY_FUNCS)
            parsed = binexport_read.read(str(path))
        self.assertEqual(parsed["meta"]["executable_name"], "sample.exe")
        self.assertEqual(parsed["meta"]["architecture"], "x86-64")
        self.assertEqual(len(parsed["functions"]), 4)
        by_address = {fn["address"]: fn for fn in parsed["functions"]}
        self.assertEqual(by_address[0x1100]["name"], "check_license")
        self.assertEqual(by_address[0x1100]["type"], "normal")
        self.assertEqual(by_address[0x1300]["type"], "imported")

    def test_unknown_fields_are_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "a.BinExport"
            make_binexport_file(path, "sample.exe", PRIMARY_FUNCS)
            data = path.read_bytes() + _bytes(999, b"future field") + _uint(998, 12345)
            parsed = binexport_read.parse(data)
        self.assertEqual(len(parsed["functions"]), 4)

    def test_rejects_garbage(self):
        with self.assertRaises(binexport_read.BinExportError):
            binexport_read.parse(b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff")

    def test_label_falls_back_to_sub_address(self):
        self.assertEqual(
            binexport_read.label({"address": 0x401000, "name": "", "demangled": ""}),
            "sub_401000")
        self.assertEqual(
            binexport_read.label({"address": 1, "name": "m", "demangled": "d"}), "d")


class StemTest(unittest.TestCase):
    """Version-numbered build names must survive .BinExport filename derivation."""

    def setUp(self):
        self.mod = _load("run")

    def test_version_suffixes_are_preserved(self):
        self.assertEqual(self.mod._stem("/x/piu-1.08-unstripped"), "piu-1.08-unstripped")
        self.assertEqual(self.mod._stem("/x/app-2.3.1"), "app-2.3.1")

    def test_known_extensions_are_stripped(self):
        self.assertEqual(self.mod._stem("/x/old.BinExport"), "old")
        self.assertEqual(self.mod._stem("/x/game.exe"), "game")


class RunnerTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.bin_dir = self.tmp / "bin"
        self.bin_dir.mkdir()
        self.outdir = self.tmp / "out"
        self.primary = self.tmp / "old.BinExport"
        self.secondary = self.tmp / "new.BinExport"
        make_binexport_file(self.primary, "old.exe", PRIMARY_FUNCS)
        make_binexport_file(self.secondary, "new.exe", SECONDARY_FUNCS)
        self.addCleanup(self._tmp.cleanup)

    def run_runner(self, *args: str, path_has_bindiff: bool = True):
        env = dict(os.environ)
        env["PATH"] = str(self.bin_dir) if path_has_bindiff else str(self.tmp / "empty")
        return subprocess.run(
            [sys.executable, str(RUNNER), str(self.primary), str(self.secondary),
             str(self.outdir), "--backend", "none", *args],
            capture_output=True, text=True, env=env)

    def test_end_to_end_json_report(self):
        fake_bindiff(self.bin_dir)
        proc = self.run_runner("--format", "json")
        self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
        result = json.loads(proc.stdout)
        self.assertTrue(result["ok"])
        self.assertEqual(result["backend"], "none")
        self.assertAlmostEqual(result["similarity"], 0.81)
        counts = result["counts"]
        self.assertEqual(counts["matched"], 2)
        self.assertEqual(counts["identical"], 1)
        self.assertEqual(counts["changed"], 1)
        self.assertEqual(counts["renamed"], 1)
        # imports are excluded from added/removed; 0x1200 and 0x2200 remain
        self.assertEqual(counts["removed"], 1)
        self.assertEqual(counts["added"], 1)
        self.assertEqual([f["name"] for f in result["added"]], ["new_telemetry"])
        self.assertEqual([f["name"] for f in result["removed"]], ["removed_helper"])
        self.assertEqual(result["topChanged"][0]["name2"], "verify_license")

        written = json.loads(Path(result["matchesFile"]).read_text())
        self.assertEqual(len(written["matches"]), 2)
        unmatched = json.loads(Path(result["unmatchedFile"]).read_text())
        self.assertEqual(len(unmatched["added"]), 1)
        self.assertTrue(Path(result["resultDb"]).is_file())
        self.assertTrue(Path(result["summaryFile"]).is_file())

    def test_text_report_lists_sections(self):
        fake_bindiff(self.bin_dir)
        proc = self.run_runner("--format", "text")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("changed functions", proc.stdout)
        self.assertIn("verify_license", proc.stdout)
        self.assertIn("added in secondary", proc.stdout)
        self.assertIn("removed from primary", proc.stdout)

    def test_identical_threshold_reclassifies(self):
        fake_bindiff(self.bin_dir)
        proc = self.run_runner("--format", "json", "--identical-threshold", "0.5")
        result = json.loads(proc.stdout)
        self.assertEqual(result["counts"]["identical"], 2)
        self.assertEqual(result["counts"]["changed"], 0)

    def test_missing_bindiff_is_honest(self):
        proc = self.run_runner(path_has_bindiff=False)
        self.assertEqual(proc.returncode, 3)
        result = json.loads(proc.stdout)
        self.assertFalse(result["ok"])
        self.assertIn("bindiff not found", result["error"])
        self.assertIn("github.com/google/bindiff", result["hint"])

    def test_backend_none_rejects_raw_binary(self):
        fake_bindiff(self.bin_dir)
        raw = self.tmp / "raw.bin"
        raw.write_bytes(b"\x7fELF")
        env = dict(os.environ)
        env["PATH"] = str(self.bin_dir)
        proc = subprocess.run(
            [sys.executable, str(RUNNER), str(raw), str(self.secondary),
             str(self.outdir), "--backend", "none"],
            capture_output=True, text=True, env=env)
        self.assertEqual(proc.returncode, 1)
        result = json.loads(proc.stdout)
        self.assertFalse(result["ok"])
        self.assertIn("requires .BinExport inputs", result["error"])

    def test_missing_input_file(self):
        fake_bindiff(self.bin_dir)
        env = dict(os.environ)
        env["PATH"] = str(self.bin_dir)
        proc = subprocess.run(
            [sys.executable, str(RUNNER), str(self.tmp / "nope.BinExport"),
             str(self.secondary), str(self.outdir), "--backend", "none"],
            capture_output=True, text=True, env=env)
        self.assertEqual(proc.returncode, 2)
        self.assertIn("file not found", json.loads(proc.stdout)["error"])


if __name__ == "__main__":
    unittest.main()

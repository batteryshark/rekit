from __future__ import annotations

import importlib.util
import json
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "skills" / "bin-table-diff" / "scripts" / "run.py"

spec = importlib.util.spec_from_file_location("bin_table_diff", RUNNER)
BT = importlib.util.module_from_spec(spec)
spec.loader.exec_module(BT)

BASE = 0x8048000


def build_elf(records: list[dict], stride: int = 32, pad_records: int = 2) -> bytes:
    """Synthesise a 32-bit ELF with a string blob and a record table.

    Mirrors the real shape: a leading run of zeros before the table, string
    pointers as absolute VAs, and trailing non-table bytes.
    """
    header = bytearray(0x34 + 0x20)
    header[0:4] = b"\x7fELF"
    header[4] = 1   # 32-bit
    header[5] = 1   # little endian
    struct.pack_into("<I", header, 0x1C, 0x34)      # e_phoff
    struct.pack_into("<HH", header, 0x2A, 0x20, 1)  # phentsize, phnum

    strings = bytearray()
    offsets: dict = {}

    def intern(text: str) -> int:
        if text not in offsets:
            offsets[text] = len(strings)
            strings.extend(text.encode("utf-8") + b"\0")
        return offsets[text]

    for record in records:
        for value in record["strings"]:
            intern(value)

    body = bytearray()
    body.extend(b"\0" * (stride * pad_records))          # padding before table
    table_start = len(body)
    for record in records:
        row = bytearray(stride)
        for i, text in enumerate(record["strings"]):
            row[i * 4:i * 4 + 4] = b"\0\0\0\0"           # patched below
        body.extend(row)
    table_bytes = len(body) - table_start
    body.extend(b"\xAB" * 64)                            # trailing non-table data
    string_base = len(body)
    body.extend(strings)

    file_data = bytearray(header + body)
    seg_start = len(header)
    # Patch pointers now that the string blob's file position is known.
    for index, record in enumerate(records):
        row_off = len(header) + table_start + index * stride
        for i, text in enumerate(record["strings"]):
            vaddr = BASE + len(header) + string_base + offsets[text]
            struct.pack_into("<I", file_data, row_off + i * 4, vaddr)
        for field, value in record.get("ints", {}).items():
            struct.pack_into("<I", file_data, row_off + field, value)

    # One PT_LOAD covering everything after the headers, mapped so that
    # file offset X lives at BASE + X.
    struct.pack_into("<I", file_data, 0x34, 1)                    # PT_LOAD
    struct.pack_into("<I", file_data, 0x34 + 0x04, seg_start)     # p_offset
    struct.pack_into("<I", file_data, 0x34 + 0x08, BASE + seg_start)  # p_vaddr
    struct.pack_into("<I", file_data, 0x34 + 0x10, len(file_data) - seg_start)
    return bytes(file_data)


def songs(entries: list[tuple[str, str, int]]) -> list[dict]:
    # Three string columns, because detection anchors on a run of three
    # consecutive string pointers — exactly as the real tables are shaped.
    return [{"strings": [artist, title, f"{100 + level} BPM"],
             "ints": {12: level, 16: 0x1234}}
            for artist, title, level in entries]


SET_A = songs([("Banya", "Money", 12), ("Banya", "Beethoven Virus", 14),
               ("CLON", "Come on Please", 9), ("Yahpp", "Solitary", 17),
               ("Banya", "Money", 8), ("Taiji", "Come Back Home", 11),
               ("Fin.K.L", "Forever Love", 5), ("Yahpp", "Pumptris", 13),
               ("CLON", "Funky Tonight", 7), ("Banya", "Extravaganza", 15)])


class DetectionTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def write(self, name: str, records, **kw) -> str:
        path = self.tmp / name
        path.write_bytes(build_elf(records, **kw))
        return str(path)

    def test_finds_table_with_correct_stride_and_count(self):
        path = self.write("a.elf", SET_A, stride=32)
        image = BT.Image(path)
        tables = BT.find_tables(image, min_records=4)
        self.assertTrue(tables)
        self.assertEqual(tables[0]["stride"], 32)
        self.assertEqual(tables[0]["records"], len(SET_A))

    def test_zero_padding_is_not_absorbed_as_records(self):
        # Leading zero rows are plausible pointer-wise (nulls are skipped), so
        # without an "at least one populated pointer" rule the walk runs off the
        # front of the table and invents empty records.
        path = self.write("b.elf", SET_A, stride=32, pad_records=6)
        image = BT.Image(path)
        self.assertEqual(BT.find_tables(image, min_records=4)[0]["records"],
                         len(SET_A))

    def test_types_columns_from_the_data(self):
        path = self.write("c.elf", SET_A, stride=32)
        image = BT.Image(path)
        table = BT.find_tables(image, min_records=4)[0]
        kinds = {c["field"]: c["kind"] for c in BT.infer_layout(image, table)}
        self.assertEqual(kinds[0], "string")
        self.assertEqual(kinds[4], "string")
        self.assertEqual(kinds[8], "string")
        self.assertEqual(kinds[12], "small")  # level values fit in a byte

    def test_address_translation_uses_program_headers(self):
        path = self.write("d.elf", SET_A)
        image = BT.Image(path)
        self.assertIsNone(image.to_offset(0x1000))       # outside any segment
        self.assertIsNotNone(image.to_offset(BASE + 0x100))  # inside PT_LOAD

    def test_rejects_non_elf(self):
        path = self.tmp / "not.elf"
        path.write_bytes(b"MZ\x90\x00" * 40)
        with self.assertRaises(BT.TableError):
            BT.Image(str(path))


class DiffTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def run_diff(self, a, b, *extra):
        pa, pb = self.tmp / "a.elf", self.tmp / "b.elf"
        pa.write_bytes(build_elf(a)); pb.write_bytes(build_elf(b))
        out = self.tmp / "out"
        proc = subprocess.run(
            [sys.executable, str(RUNNER), "diff", str(pa), str(pb), str(out),
             "--min-records", "4", "--format", "json", *extra],
            capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
        return json.loads(proc.stdout), out

    def test_identical_tables_report_no_change(self):
        result, _ = self.run_diff(SET_A, SET_A)
        self.assertEqual((result["added"], result["removed"], result["changed"]),
                         (0, 0, 0))

    def test_added_entry_is_detected(self):
        extended = SET_A + songs([("New Artist", "Brand New Song", 10)])
        result, _ = self.run_diff(SET_A, extended)
        self.assertEqual(result["added"], 1)
        self.assertEqual(result["removed"], 0)

    def test_insertion_does_not_shift_every_later_record(self):
        # The point of key-based matching: inserting near the front must not
        # report everything after it as changed.
        inserted = songs([("Zed", "Inserted", 3)]) + SET_A
        result, _ = self.run_diff(SET_A, inserted)
        self.assertEqual(result["added"], 1)
        self.assertEqual(result["changed"], 0)

    def test_changed_value_is_reported_with_before_and_after(self):
        rebalanced = [dict(r) for r in SET_A]
        rebalanced[3] = {"strings": ["Yahpp", "Solitary", "117 BPM"],
                         "ints": {12: 19, 16: 0x1234}}
        result, out = self.run_diff(SET_A, rebalanced)
        self.assertEqual(result["changed"], 1)
        detail = json.loads((out / "table-diff.json").read_text())
        fields = detail["diff"]["changed"][0]["fields"]
        self.assertEqual(fields["f0C"], [17, 19])

    def test_duplicate_keys_are_disambiguated(self):
        # SET_A intentionally lists "Banya | Money" twice at different levels.
        result, out = self.run_diff(SET_A, SET_A)
        detail = json.loads((out / "table-diff.json").read_text())
        self.assertEqual(detail["diff"]["changed"], [])
        self.assertIn("+", detail["diff"]["key"])

    def test_key_override(self):
        result, out = self.run_diff(SET_A, SET_A, "--key", "f04")
        detail = json.loads((out / "table-diff.json").read_text())
        self.assertEqual(detail["diff"]["key"], "f04")


class DecodeTest(unittest.TestCase):
    def test_utf8_preferred(self):
        self.assertEqual(BT.decode("Money".encode("utf-8")), ("Money", "utf-8"))

    def test_korean_falls_back_to_euc_kr(self):
        text, encoding = BT.decode("클론".encode("euc-kr"))
        self.assertEqual(text, "클론")
        self.assertEqual(encoding, "euc-kr")

    def test_pinned_encoding_wins(self):
        raw = "脫掉".encode("big5")
        self.assertEqual(BT.decode(raw, "big5"), ("脫掉", "big5"))

    def test_never_raises_on_undecodable_bytes(self):
        # Single-byte codepages accept any byte sequence, so this lands on one of
        # them rather than the latin-1 backstop. What matters is that a table
        # string can never abort an extraction.
        text, encoding = BT.decode(b"\xff\xfe\xfd")
        self.assertTrue(text)
        self.assertIn(encoding, BT.TEXT_ENCODINGS + ("latin-1",))


class StrideMismatchTest(unittest.TestCase):
    """A struct that changed size must not be reported as wholly changed."""

    def test_mismatched_stride_is_flagged(self):
        # NX 1.00 -> 1.04 grew the song struct 68 -> 72 bytes, which shifts every
        # column after the new field and made all 194 records look changed.
        with tempfile.TemporaryDirectory() as directory:
            tmp = Path(directory)
            (tmp / "a.elf").write_bytes(build_elf(SET_A, stride=32))
            (tmp / "b.elf").write_bytes(build_elf(SET_A, stride=36))
            proc = subprocess.run(
                [sys.executable, str(RUNNER), "diff", str(tmp / "a.elf"),
                 str(tmp / "b.elf"), str(tmp / "out"), "--min-records", "4",
                 "--format", "json"], capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            result = json.loads(proc.stdout)
            self.assertIsNotNone(result["strideMismatch"])
            self.assertEqual(result["strideMismatch"]["primary"], 32)
            self.assertEqual(result["strideMismatch"]["secondary"], 36)

    def test_matching_stride_sets_no_flag(self):
        with tempfile.TemporaryDirectory() as directory:
            tmp = Path(directory)
            (tmp / "a.elf").write_bytes(build_elf(SET_A, stride=32))
            (tmp / "b.elf").write_bytes(build_elf(SET_A, stride=32))
            proc = subprocess.run(
                [sys.executable, str(RUNNER), "diff", str(tmp / "a.elf"),
                 str(tmp / "b.elf"), str(tmp / "out"), "--min-records", "4",
                 "--format", "json"], capture_output=True, text=True)
            self.assertIsNone(json.loads(proc.stdout)["strideMismatch"])


if __name__ == "__main__":
    unittest.main()

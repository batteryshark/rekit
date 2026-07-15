from __future__ import annotations

import json
import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REKIT = ROOT / "bin" / "rekit"
MCP_SPEC = importlib.util.spec_from_file_location("rekit_intellidiff_mcp", ROOT / "scripts/rekit_mcp.py")
assert MCP_SPEC and MCP_SPEC.loader
MCP = importlib.util.module_from_spec(MCP_SPEC)
MCP_SPEC.loader.exec_module(MCP)


def run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([str(REKIT), "run", "intellidiff", *args], cwd=ROOT,
                          capture_output=True, text=True, check=False)


class IntelliDiffTests(unittest.TestCase):
    def test_mcp_schema_and_call_preserve_optional_second_path(self) -> None:
        skill = next(item for item in MCP.load_catalog() if item["id"] == "intellidiff")
        tool = MCP.skill_to_tool(skill, "", {"ready": True}, False)
        self.assertEqual(tool["inputSchema"]["properties"]["op"]["enum"][0], "compare")
        call = MCP.build_call_args(skill, {"op": "hash", "target": "sample.bin"})
        self.assertEqual(call, ["hash", "sample.bin", "--format", "json"])

    def test_compare_without_second_path_is_structured_error(self) -> None:
        proc = run("compare", str(ROOT / "README.md"))
        self.assertEqual(proc.returncode, 1)
        result = json.loads(proc.stdout)
        self.assertFalse(result["ok"])
        self.assertIn("other is required", result["error"])

    def test_smart_compare_normalizes_requested_differences(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            left, right = root / "left.txt", root / "right.txt"
            left.write_text("Hello  \n\nWorld\n", encoding="utf-8")
            right.write_text("hello\nworld\n", encoding="utf-8")
            proc = run("compare", str(left), str(right), "--mode", "smart",
                       "--ignore-whitespace", "--ignore-blank", "--ignore-case")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertTrue(json.loads(proc.stdout)["identical"])

    def test_folder_compare_and_duplicates_include_binary_content(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            left, right = root / "left", root / "right"
            left.mkdir(); right.mkdir()
            (left / "same.bin").write_bytes(b"\x00same")
            (right / "same.bin").write_bytes(b"\x00same")
            (left / "only.txt").write_text("copy", encoding="utf-8")
            (left / "copy.txt").write_text("copy", encoding="utf-8")
            compared = run("folder-compare", str(left), str(right), "--binary")
            duplicates = run("duplicates", str(left))
        self.assertEqual(json.loads(compared.stdout)["identical"], ["same.bin"])
        self.assertEqual(json.loads(duplicates.stdout)["duplicateGroupCount"], 1)

    def test_lines_returns_selection_and_context(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "lines.txt"
            path.write_text("one\ntwo\nthree\nfour\n", encoding="utf-8")
            proc = run("lines", str(path), "--start", "2", "--end", "3", "--context", "1")
        result = json.loads(proc.stdout)
        self.assertEqual([line["number"] for line in result["lines"]], [1, 2, 3, 4])
        self.assertEqual([line["selected"] for line in result["lines"]], [False, True, True, False])


if __name__ == "__main__":
    unittest.main()

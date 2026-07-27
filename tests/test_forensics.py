from __future__ import annotations

import contextlib
import binascii
import importlib.util
import io
import json
import struct
import subprocess
import sys
import tempfile
import unittest
import uuid
import zipfile
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
REKIT = ROOT / "bin" / "rekit"


def load_script(name: str, relative_path: str):
    path = ROOT / relative_path
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


RECOVER = load_script(
    "rekit_filesystem_recover", "skills/filesystem-recover/scripts/run.py"
)


def run_rekit(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(REKIT), "run", *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


def sample_zip() -> bytes:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("src/main.c", "int main(void) { return 0; }\n")
        archive.writestr("README.txt", "recovered fixture\n")
    return stream.getvalue()


def write_ext_superblock(image: bytearray, filesystem_start: int) -> None:
    superblock = bytearray(1024)
    struct.pack_into("<I", superblock, 0, 128)  # inodes
    struct.pack_into("<I", superblock, 4, 1024)  # blocks
    struct.pack_into("<I", superblock, 12, 800)  # free blocks
    struct.pack_into("<I", superblock, 16, 100)  # free inodes
    struct.pack_into("<I", superblock, 20, 1)  # first data block
    struct.pack_into("<I", superblock, 24, 0)  # 1024-byte blocks
    struct.pack_into("<I", superblock, 32, 8192)  # blocks per group
    struct.pack_into("<I", superblock, 40, 128)  # inodes per group
    struct.pack_into("<H", superblock, 56, 0xEF53)
    struct.pack_into("<H", superblock, 58, 1)
    struct.pack_into("<I", superblock, 76, 1)
    struct.pack_into("<H", superblock, 88, 256)
    struct.pack_into("<H", superblock, 90, 0)
    superblock[104:120] = bytes(range(16))
    superblock[120:127] = b"EVIDENCE"
    offset = filesystem_start + 1024
    image[offset : offset + len(superblock)] = superblock


def make_image(path: Path) -> tuple[int, bytes]:
    data = bytearray(4 * 1024 * 1024)
    partition_start_lba = 2048
    partition_sectors = 2048
    entry = bytearray(16)
    entry[4] = 0x83
    struct.pack_into("<II", entry, 8, partition_start_lba, partition_sectors)
    data[446:462] = entry
    data[510:512] = b"\x55\xaa"
    write_ext_superblock(data, partition_start_lba * 512)
    archive = sample_zip()
    archive_offset = 3 * 1024 * 1024 + 123
    data[archive_offset : archive_offset + len(archive)] = archive
    path.write_bytes(data)
    return archive_offset, archive


def make_gpt_image(path: Path) -> None:
    sector_size = 512
    sectors = 4096
    data = bytearray(sectors * sector_size)
    protective = bytearray(16)
    protective[4] = 0xEE
    struct.pack_into("<II", protective, 8, 1, sectors - 1)
    data[446:462] = protective
    data[510:512] = b"\x55\xaa"

    entries = bytearray(4 * 128)
    entries[0:16] = uuid.UUID("0fc63daf-8483-4772-8e79-3d69d8477de4").bytes_le
    entries[16:32] = uuid.UUID("11111111-2222-3333-4444-555555555555").bytes_le
    struct.pack_into("<QQQ", entries, 32, 2048, 3000, 0)
    name = "evidence".encode("utf-16le")
    entries[56 : 56 + len(name)] = name
    data[2 * sector_size : 2 * sector_size + len(entries)] = entries

    header = bytearray(sector_size)
    header[:8] = b"EFI PART"
    struct.pack_into("<II", header, 8, 0x00010000, 92)
    struct.pack_into("<QQQQ", header, 24, 1, sectors - 1, 34, sectors - 34)
    header[56:72] = uuid.UUID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").bytes_le
    struct.pack_into("<QIII", header, 72, 2, 4, 128, binascii.crc32(entries) & 0xFFFFFFFF)
    checksum = binascii.crc32(header[:92]) & 0xFFFFFFFF
    struct.pack_into("<I", header, 16, checksum)
    data[sector_size : 2 * sector_size] = header
    path.write_bytes(data)


class DiskImageForensicsTests(unittest.TestCase):
    def test_scan_maps_partition_filesystem_and_archive_offsets(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image = root / "evidence.img"
            archive_offset, _ = make_image(image)
            output = root / "scan"
            process = run_rekit(
                "disk-image-scan", str(image), str(output), "--chunk-mib", "1"
            )
            result = json.loads(process.stdout)
            hits = [
                json.loads(line)
                for line in (output / "scan.jsonl").read_text(encoding="utf-8").splitlines()
            ]

        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertTrue(result["ok"])
        self.assertEqual(result["partitionMap"]["scheme"], "mbr")
        self.assertEqual(
            result["partitionMap"]["partitions"][0]["startLba"], 2048
        )
        ext = next(hit for hit in hits if hit["kind"] == "extFilesystem")
        self.assertEqual(ext["inferredStartLba"], 2048)
        local = next(hit for hit in hits if hit["kind"] == "zipLocal")
        self.assertEqual(local["offset"], archive_offset)
        self.assertIn("imageSha256", result)

    def test_scan_validates_gpt_header_entries_and_partition_name(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image = root / "gpt.img"
            make_gpt_image(image)
            output = root / "scan"
            process = run_rekit("disk-image-scan", str(image), str(output))
            partition_map = json.loads(process.stdout)["partitionMap"]

        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(partition_map["scheme"], "gpt")
        self.assertTrue(partition_map["headerCrcValid"])
        self.assertTrue(partition_map["entriesCrcValid"])
        self.assertEqual(partition_map["partitions"][0]["name"], "evidence")
        self.assertEqual(partition_map["partitions"][0]["startLba"], 2048)

    def test_carver_recovers_exact_zip_and_records_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image = root / "evidence.img"
            archive_offset, archive = make_image(image)
            scan = root / "scan"
            scanned = run_rekit("disk-image-scan", str(image), str(scan))
            carved = root / "carved"
            process = run_rekit(
                "forensic-archive-carve",
                str(image),
                str(carved),
                "--hits",
                str(scan / "scan.jsonl"),
            )
            result = json.loads(process.stdout)
            records = [
                json.loads(line)
                for line in (carved / "manifest.jsonl")
                .read_text(encoding="utf-8")
                .splitlines()
            ]
            recovered = Path(records[0]["file"]).read_bytes()

        self.assertEqual(scanned.returncode, 0, scanned.stderr)
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(result["candidateCount"], 1)
        self.assertEqual(records[0]["start"], archive_offset)
        self.assertEqual(records[0]["validation"], "eocd-central-directory-local-headers")
        self.assertEqual(recovered, archive)

    def test_scan_hit_limit_is_explicit_and_bounds_the_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image = root / "many-signatures.img"
            image.write_bytes(b"PK\x03\x04" * 32)
            output = root / "scan"
            process = run_rekit(
                "disk-image-scan",
                str(image),
                str(output),
                "--max-hits",
                "3",
                "--chunk-mib",
                "1",
            )
            result = json.loads(process.stdout)
            records = (output / "scan.jsonl").read_text(encoding="utf-8").splitlines()

        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertTrue(result["hitLimitReached"])
        self.assertEqual(result["reportedHits"], 3)
        self.assertEqual(len(records), 3)

    def test_carver_rejects_forged_eocd_without_central_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image = root / "forged.img"
            fake = struct.pack("<4sHHHHIIH", b"PK\x05\x06", 0, 0, 1, 1, 46, 0, 0)
            image.write_bytes(b"\0" * 128 + fake)
            output = root / "carved"
            process = run_rekit("forensic-archive-carve", str(image), str(output))
            result = json.loads(process.stdout)

        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(result["candidateCount"], 0)
        self.assertEqual(result["rejections"]["invalid-central-directory"], 1)

    def test_recovery_command_keeps_sector_units_and_mode_explicit(self) -> None:
        command = RECOVER.build_command(
            "/usr/bin/tsk_recover",
            Path("image.dd"),
            Path("recovered"),
            4096,
            "all",
            4096,
            "ntfs",
        )
        self.assertEqual(command[1:8], ["-e", "-b", "4096", "-o", "4096", "-f", "ntfs"])

    def test_fls_command_and_parser_preserve_ntfs_mft_address(self) -> None:
        command = RECOVER.build_fls_command(
            "/usr/bin/fls", Path("image.dd"), 2048, 512, "ntfs"
        )
        entry = RECOVER.parse_fls_entry(
            "-/r * 1304-128-1:\tUsers/Alice/deleted report.docx"
        )

        self.assertEqual(
            command[1:9], ["-r", "-p", "-b", "512", "-o", "2048", "-f", "ntfs"]
        )
        self.assertEqual(entry["metadataAddress"], "1304-128-1")
        self.assertEqual(entry["metadataRecord"], "1304")
        self.assertTrue(entry["deleted"])
        self.assertEqual(entry["path"], "Users/Alice/deleted report.docx")

    def test_mft_rename_refuses_ambiguous_or_unsafe_names(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            orphan_dir = root / "$OrphanFiles"
            orphan_dir.mkdir()
            source = orphan_dir / "OrphanFile-42"
            source.write_bytes(b"evidence")
            log = root / "renames.jsonl"
            candidates = {
                "42": [
                    {
                        "types": "-/r",
                        "deleted": True,
                        "metadataAddress": "42-128-1",
                        "metadataRecord": "42",
                        "reallocated": False,
                        "path": "Users/Alice/one.docx",
                    },
                    {
                        "types": "-/r",
                        "deleted": True,
                        "metadataAddress": "42-128-1",
                        "metadataRecord": "42",
                        "reallocated": False,
                        "path": "../../escape.docx",
                    },
                    {
                        "types": "-/r",
                        "deleted": True,
                        "metadataAddress": "42-128-1",
                        "metadataRecord": "42",
                        "reallocated": False,
                        "path": "Users/Alice/two.docx",
                    },
                ]
            }
            result = RECOVER.apply_metadata_renames(
                root, {"42": [source]}, candidates, log
            )
            record = json.loads(log.read_text(encoding="utf-8"))
            source_still_exists = source.exists()

        self.assertTrue(source_still_exists)
        self.assertEqual(result["metadataRenamedCount"], 0)
        self.assertEqual(record["status"], "ambiguous")
        self.assertNotIn("../../escape.docx", record["candidatePaths"])

    def test_recovery_renames_orphan_from_unique_mft_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image = root / "image.dd"
            image.write_bytes(b"\0" * 4096)
            fake_recover = root / "tsk_recover"
            fake_recover.write_text(
                "#!/bin/sh\n"
                "for argument do output=$argument; done\n"
                "mkdir -p \"$output/\\$OrphanFiles\"\n"
                "printf evidence > \"$output/\\$OrphanFiles/OrphanFile-42\"\n"
                "printf 'Files Recovered: 1\\n'\n",
                encoding="utf-8",
            )
            fake_recover.chmod(0o755)
            fake_fls = root / "fls"
            fake_fls.write_text(
                "#!/bin/sh\n"
                "printf '%s\\n' '-/r * 42-128-1: Users/Alice/report.docx'\n",
                encoding="utf-8",
            )
            fake_fls.chmod(0o755)
            output = root / "recovered"

            def fake_which(name: str):
                return str(fake_recover if name == "tsk_recover" else fake_fls)

            stdout = io.StringIO()
            with mock.patch.object(RECOVER.shutil, "which", side_effect=fake_which):
                with contextlib.redirect_stdout(stdout):
                    code = RECOVER.main(
                        [
                            str(image),
                            str(output),
                            "--offset",
                            "0",
                            "--mode",
                            "deleted",
                            "--no-hash",
                        ]
                    )
            result = json.loads(stdout.getvalue())
            renamed = output / "files" / "Users" / "Alice" / "report.docx"
            renamed_bytes = renamed.read_bytes()
            placeholder_exists = (
                output / "files" / "$OrphanFiles" / "OrphanFile-42"
            ).exists()

        self.assertEqual(code, 0, result)
        self.assertTrue(result["ok"])
        self.assertEqual(result["metadataRenamedCount"], 1)
        self.assertEqual(renamed_bytes, b"evidence")
        self.assertFalse(placeholder_exists)

    def test_recovery_reports_missing_sleuth_kit_without_creating_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image = root / "image.dd"
            image.write_bytes(b"\0" * 1024)
            output = root / "recovered"
            stdout = io.StringIO()
            with mock.patch.object(RECOVER.shutil, "which", return_value=None):
                with contextlib.redirect_stdout(stdout):
                    code = RECOVER.main(
                        [str(image), str(output), "--offset", "0", "--mode", "deleted"]
                    )
            result = json.loads(stdout.getvalue())

        self.assertEqual(code, 3)
        self.assertFalse(result["ok"])
        self.assertIn("tsk_recover is not on PATH", result["error"])
        self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()

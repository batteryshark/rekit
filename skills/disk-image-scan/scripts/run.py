#!/usr/bin/env python3
"""Read-only partition, filesystem, and signature inventory for disk images."""

from __future__ import annotations

import argparse
import binascii
import hashlib
import json
import os
import struct
import sys
import time
import uuid
from collections import Counter
from pathlib import Path
from typing import BinaryIO, Dict, List, Optional, Tuple


SIGNATURES = {
    "zipLocal": b"PK\x03\x04",
    "zipEocd": b"PK\x05\x06",
    "zip64Eocd": b"PK\x06\x06",
    "rar4": b"Rar!\x1a\x07\x00",
    "rar5": b"Rar!\x1a\x07\x01\x00",
    "sevenZip": b"7z\xbc\xaf\x27\x1c",
    "gzip": b"\x1f\x8b\x08",
    "bzip2": b"BZh",
    "xz": b"\xfd7zXZ\x00",
    "pdf": b"%PDF-",
    "png": b"\x89PNG\r\n\x1a\n",
    "jpeg": b"\xff\xd8\xff",
    "sqlite": b"SQLite format 3\x00",
    "gitPack": b"PACK",
    "gitIndex": b"DIRC",
}
PROBE_SIGNATURES = {
    "ext": b"\x53\xef",
    "ntfs": b"NTFS    ",
    "fat32": b"FAT32   ",
    "fat16": b"FAT16   ",
    "fat12": b"FAT12   ",
    "iso9660": b"CD001",
}
VALID_SECTOR_SIZES = (512, 1024, 2048, 4096)


def read_at(handle: BinaryIO, offset: int, length: int) -> bytes:
    if offset < 0:
        return b""
    handle.seek(offset)
    return handle.read(length)


def u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def u64(data: bytes, offset: int) -> int:
    return struct.unpack_from("<Q", data, offset)[0]


def clean_ascii(data: bytes) -> str:
    return "".join(chr(value) if 32 <= value < 127 else "." for value in data)


def plausible_signature(kind: str, data: bytes, index: int) -> bool:
    if kind in ("gitPack", "gitIndex"):
        if index + 12 > len(data):
            return False
        version, count = struct.unpack_from(">II", data, index + 4)
        allowed = (2, 3) if kind == "gitPack" else (2, 3, 4)
        return version in allowed and count < 100_000_000
    if kind == "gzip":
        return index + 4 <= len(data) and data[index + 3] <= 0x1F
    if kind == "jpeg":
        return index + 4 <= len(data) and data[index + 3] not in (0x00, 0xFF)
    return True


def validate_ext(handle: BinaryIO, magic_offset: int, image_size: int) -> Optional[dict]:
    super_offset = magic_offset - 56
    block = read_at(handle, super_offset, 1024)
    if len(block) != 1024 or u16(block, 56) != 0xEF53:
        return None
    inodes, blocks = u32(block, 0), u32(block, 4)
    free_blocks, free_inodes = u32(block, 12), u32(block, 16)
    first_data, log_block_size = u32(block, 20), u32(block, 24)
    blocks_per_group, inodes_per_group = u32(block, 32), u32(block, 40)
    revision = u32(block, 76)
    inode_size = u16(block, 88) if revision else 128
    block_group = u16(block, 90)
    if not inodes or not blocks or log_block_size > 6:
        return None
    if not (8 <= blocks_per_group <= 0x1000000):
        return None
    if not (1 <= inodes_per_group <= inodes):
        return None
    if inode_size < 128 or inode_size > 4096 or inode_size & (inode_size - 1):
        return None
    if free_blocks > blocks or free_inodes > inodes:
        return None
    block_size = 1024 << log_block_size
    if block_group == 0:
        inferred_start = super_offset - 1024
    else:
        group_block = block_group * blocks_per_group + first_data
        inferred_start = super_offset - group_block * block_size
    if inferred_start < 0 or inferred_start >= image_size:
        return None
    return {
        "kind": "extFilesystem",
        "offset": super_offset,
        "magicOffset": magic_offset,
        "lba512": super_offset // 512,
        "inferredStart": inferred_start,
        "inferredStartLba": inferred_start // 512 if inferred_start % 512 == 0 else None,
        "backupGroup": block_group,
        "blockSize": block_size,
        "blocks": blocks,
        "inodes": inodes,
        "inodeSize": inode_size,
        "uuid": block[104:120].hex(),
        "volumeName": block[120:136].split(b"\0", 1)[0].decode("utf-8", "replace"),
        "validation": "ext-superblock-fields",
    }


def validate_ntfs(handle: BinaryIO, boot_offset: int, image_size: int) -> Optional[dict]:
    sector = read_at(handle, boot_offset, 512)
    if len(sector) != 512 or sector[3:11] != b"NTFS    " or sector[510:] != b"\x55\xaa":
        return None
    bytes_per_sector, sectors_per_cluster = u16(sector, 11), sector[13]
    total_sectors, mft_lcn, mirror_lcn = u64(sector, 40), u64(sector, 48), u64(sector, 56)
    if sector[0] not in (0xE9, 0xEB) or bytes_per_sector not in VALID_SECTOR_SIZES:
        return None
    if (
        not sectors_per_cluster
        or sectors_per_cluster & (sectors_per_cluster - 1)
        or sectors_per_cluster > 128
        or not total_sectors
    ):
        return None
    clusters = total_sectors // sectors_per_cluster
    size = total_sectors * bytes_per_sector
    if not clusters or mft_lcn >= clusters or mirror_lcn >= clusters:
        return None
    if boot_offset + size > image_size + bytes_per_sector:
        return None
    return {
        "kind": "ntfsFilesystem",
        "offset": boot_offset,
        "lba512": boot_offset // 512,
        "bytesPerSector": bytes_per_sector,
        "sectorsPerCluster": sectors_per_cluster,
        "sizeBytes": size,
        "mftLcn": mft_lcn,
        "serial": "{:016x}".format(u64(sector, 72)),
        "validation": "ntfs-boot-sector-fields",
    }


def validate_fat(
    handle: BinaryIO, boot_offset: int, image_size: int, fat_kind: str
) -> Optional[dict]:
    sector = read_at(handle, boot_offset, 512)
    label_offset = 82 if fat_kind == "fat32" else 54
    expected = b"FAT32   " if fat_kind == "fat32" else (b"FAT16   ", b"FAT12   ")
    label = sector[label_offset : label_offset + 8] if len(sector) == 512 else b""
    if isinstance(expected, tuple):
        type_matches = label in expected
    else:
        type_matches = label == expected
    if (
        len(sector) != 512
        or not type_matches
        or sector[510:] != b"\x55\xaa"
        or sector[0] not in (0xE9, 0xEB)
    ):
        return None
    bytes_per_sector, sectors_per_cluster = u16(sector, 11), sector[13]
    reserved, fat_count = u16(sector, 14), sector[16]
    total_sectors = u16(sector, 19) or u32(sector, 32)
    fat_size = u32(sector, 36) if fat_kind == "fat32" else u16(sector, 22)
    if bytes_per_sector not in VALID_SECTOR_SIZES:
        return None
    if not sectors_per_cluster or sectors_per_cluster & (sectors_per_cluster - 1):
        return None
    if sectors_per_cluster > 128 or not reserved or fat_count not in (1, 2):
        return None
    size = total_sectors * bytes_per_sector
    if not total_sectors or not fat_size or boot_offset + size > image_size + bytes_per_sector:
        return None
    volume_slice = sector[71:82] if fat_kind == "fat32" else sector[43:54]
    return {
        "kind": "{}Filesystem".format(fat_kind),
        "offset": boot_offset,
        "lba512": boot_offset // 512,
        "bytesPerSector": bytes_per_sector,
        "sectorsPerCluster": sectors_per_cluster,
        "sizeBytes": size,
        "volumeLabel": volume_slice.decode("ascii", "replace").strip(),
        "validation": "fat-boot-sector-fields",
    }


def validate_iso(handle: BinaryIO, magic_offset: int, image_size: int) -> Optional[dict]:
    descriptor_offset = magic_offset - 1
    start = descriptor_offset - 16 * 2048
    descriptor = read_at(handle, descriptor_offset, 2048)
    if start < 0 or start % 2048:
        return None
    if (
        len(descriptor) != 2048
        or descriptor[0] != 1
        or descriptor[1:6] != b"CD001"
        or descriptor[6] != 1
    ):
        return None
    blocks, block_size = u32(descriptor, 80), u16(descriptor, 128)
    size = blocks * block_size
    if block_size not in VALID_SECTOR_SIZES or not blocks:
        return None
    if start + size > image_size + block_size:
        return None
    return {
        "kind": "iso9660Filesystem",
        "offset": start,
        "lba512": start // 512,
        "sizeBytes": size,
        "logicalBlockSize": block_size,
        "volumeId": descriptor[40:72].decode("ascii", "replace").strip(),
        "validation": "iso-primary-volume-descriptor",
    }


def parse_mbr(handle: BinaryIO, image_size: int, sector_size: int) -> Optional[dict]:
    sector = read_at(handle, 0, 512)
    if len(sector) != 512 or sector[510:] != b"\x55\xaa":
        return None
    partitions = []
    for index in range(4):
        entry = sector[446 + index * 16 : 462 + index * 16]
        status, type_code = entry[0], entry[4]
        start_lba, sectors = u32(entry, 8), u32(entry, 12)
        if not type_code or not sectors:
            continue
        partitions.append(
            {
                "index": index + 1,
                "status": status,
                "typeCode": "0x{:02x}".format(type_code),
                "startLba": start_lba,
                "sectors": sectors,
                "startByte": start_lba * sector_size,
                "sizeBytes": sectors * sector_size,
                "withinImage": (start_lba + sectors) * sector_size <= image_size,
            }
        )
    return {
        "scheme": "mbr",
        "signature": "{:08x}".format(u32(sector, 440)),
        "sectorSize": sector_size,
        "limitations": ["primary MBR entries only; EBR chains are not parsed"],
        "partitions": partitions,
    }


def parse_gpt(handle: BinaryIO, image_size: int, sector_size: int) -> Optional[dict]:
    header = read_at(handle, sector_size, sector_size)
    if len(header) < 92 or header[:8] != b"EFI PART":
        return None
    header_size, stored_crc = u32(header, 12), u32(header, 16)
    if header_size < 92 or header_size > len(header):
        return None
    crc_data = bytearray(header[:header_size])
    crc_data[16:20] = b"\0\0\0\0"
    header_crc_valid = binascii.crc32(crc_data) & 0xFFFFFFFF == stored_crc
    entry_lba, entry_count, entry_size, entries_crc = (
        u64(header, 72),
        u32(header, 80),
        u32(header, 84),
        u32(header, 88),
    )
    total_entry_bytes = entry_count * entry_size
    if (
        not entry_count
        or entry_count > 16384
        or entry_size < 128
        or entry_size > 4096
        or total_entry_bytes > 64 * 1024 * 1024
    ):
        return {
            "scheme": "gpt",
            "sectorSize": sector_size,
            "headerCrcValid": header_crc_valid,
            "error": "unsafe or invalid partition-entry dimensions",
            "partitions": [],
        }
    entries = read_at(handle, entry_lba * sector_size, total_entry_bytes)
    entries_crc_valid = (
        len(entries) == total_entry_bytes
        and binascii.crc32(entries) & 0xFFFFFFFF == entries_crc
    )
    partitions = []
    if len(entries) == total_entry_bytes:
        for index in range(entry_count):
            entry = entries[index * entry_size : (index + 1) * entry_size]
            if entry[:16] == b"\0" * 16:
                continue
            first_lba, last_lba = u64(entry, 32), u64(entry, 40)
            if last_lba < first_lba:
                continue
            partitions.append(
                {
                    "index": index + 1,
                    "typeGuid": str(uuid.UUID(bytes_le=entry[:16])),
                    "uniqueGuid": str(uuid.UUID(bytes_le=entry[16:32])),
                    "startLba": first_lba,
                    "endLbaInclusive": last_lba,
                    "startByte": first_lba * sector_size,
                    "sizeBytes": (last_lba - first_lba + 1) * sector_size,
                    "attributes": u64(entry, 48),
                    "name": entry[56:entry_size]
                    .decode("utf-16le", "replace")
                    .split("\0", 1)[0],
                    "withinImage": (last_lba + 1) * sector_size <= image_size,
                }
            )
    return {
        "scheme": "gpt",
        "sectorSize": sector_size,
        "headerCrcValid": header_crc_valid,
        "entriesCrcValid": entries_crc_valid,
        "diskGuid": str(uuid.UUID(bytes_le=header[56:72])),
        "currentLba": u64(header, 24),
        "backupLba": u64(header, 32),
        "firstUsableLba": u64(header, 40),
        "lastUsableLba": u64(header, 48),
        "partitions": partitions,
    }


def partition_map(handle: BinaryIO, image_size: int, sector_size: int) -> Optional[dict]:
    mbr = parse_mbr(handle, image_size, sector_size)
    if mbr and any(item["typeCode"] == "0xee" for item in mbr["partitions"]):
        gpt = parse_gpt(handle, image_size, sector_size)
        if gpt:
            gpt["protectiveMbr"] = mbr
            return gpt
    return mbr


def validate_probe(
    kind: str, handle: BinaryIO, magic_offset: int, image_size: int
) -> Optional[dict]:
    if kind == "ext":
        return validate_ext(handle, magic_offset, image_size)
    if kind == "ntfs":
        return validate_ntfs(handle, magic_offset - 3, image_size)
    if kind == "fat32":
        return validate_fat(handle, magic_offset - 82, image_size, "fat32")
    if kind in ("fat16", "fat12"):
        return validate_fat(handle, magic_offset - 54, image_size, kind)
    return validate_iso(handle, magic_offset, image_size)


def scan(
    image: Path,
    outdir: Path,
    start: int,
    length: int,
    chunk_size: int,
    max_hits: int,
    sector_size: int,
) -> dict:
    image_size = image.stat().st_size
    end = start + length
    overlap = 4096
    seen = set()
    counts = Counter()
    hasher = hashlib.sha256()
    hit_limit_reached = False
    started = time.monotonic()
    output_path = outdir / "scan.jsonl"
    if outdir.exists():
        if not outdir.is_dir():
            raise ValueError("output exists and is not a directory: {}".format(outdir))
        if any(outdir.iterdir()):
            raise ValueError("output directory must be empty: {}".format(outdir))
    else:
        outdir.mkdir(parents=True)

    with image.open("rb", buffering=0) as stream, image.open("rb", buffering=0) as probe:
        partitions = partition_map(probe, image_size, sector_size)
        stream.seek(start)
        carry = b""
        absolute = start
        with output_path.open("w", encoding="utf-8", newline="\n") as output:
            while absolute < end:
                chunk = stream.read(min(chunk_size, end - absolute))
                if not chunk:
                    break
                hasher.update(chunk)
                data = carry + chunk
                base = absolute - len(carry)
                for kind, signature in SIGNATURES.items():
                    position = 0
                    while True:
                        index = data.find(signature, position)
                        if index < 0:
                            break
                        offset = base + index
                        key = (kind, offset)
                        if (
                            start <= offset < end
                            and key not in seen
                            and plausible_signature(kind, data, index)
                        ):
                            if len(seen) < max_hits:
                                seen.add(key)
                                context_start = max(0, index - 48)
                                context_end = min(len(data), index + len(signature) + 48)
                                record = {
                                    "kind": kind,
                                    "offset": offset,
                                    "lba512": offset // 512,
                                    "contextAscii": clean_ascii(data[context_start:context_end]),
                                    "validation": "signature-and-basic-fields",
                                }
                                output.write(json.dumps(record, sort_keys=True) + "\n")
                                counts[kind] += 1
                            else:
                                hit_limit_reached = True
                        position = index + 1
                for probe_kind, signature in PROBE_SIGNATURES.items():
                    position = 0
                    while True:
                        index = data.find(signature, position)
                        if index < 0:
                            break
                        magic_offset = base + index
                        candidate = validate_probe(probe_kind, probe, magic_offset, image_size)
                        if candidate:
                            candidate_offset = int(candidate["offset"])
                            key = (candidate["kind"], candidate_offset)
                            if start <= candidate_offset < end and key not in seen:
                                if len(seen) < max_hits:
                                    seen.add(key)
                                    output.write(json.dumps(candidate, sort_keys=True) + "\n")
                                    counts[candidate["kind"]] += 1
                                else:
                                    hit_limit_reached = True
                        position = index + 1
                absolute += len(chunk)
                carry = data[-overlap:]

    elapsed = time.monotonic() - started
    digest_key = "imageSha256" if start == 0 and length == image_size else "rangeSha256"
    stat = image.stat()
    result = {
        "ok": True,
        "tool": "disk-image-scan",
        "image": str(image.resolve()),
        "imageSize": image_size,
        "modifiedNs": stat.st_mtime_ns,
        "range": {"start": start, "length": length, "endExclusive": end},
        digest_key: hasher.hexdigest(),
        "partitionMap": partitions,
        "counts": dict(sorted(counts.items())),
        "reportedHits": sum(counts.values()),
        "hitLimitReached": hit_limit_reached,
        "maxHits": max_hits,
        "scanFile": str(output_path.resolve()),
        "summaryFile": str((outdir / "summary.json").resolve()),
        "elapsedSeconds": round(elapsed, 3),
    }
    (outdir / "summary.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return result


def fail(message: str, code: int = 2) -> int:
    print(json.dumps({"ok": False, "tool": "disk-image-scan", "error": message}))
    return code


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("outdir", type=Path)
    parser.add_argument("--start", type=int, default=0, help="start byte offset")
    parser.add_argument("--length", type=int, help="bytes to scan; default is through EOF")
    parser.add_argument("--chunk-mib", type=int, default=64)
    parser.add_argument("--max-hits", type=int, default=100_000)
    parser.add_argument("--sector-size", type=int, default=512)
    args = parser.parse_args(argv)
    if not args.input.is_file():
        return fail("input is not a regular file: {}".format(args.input))
    image_size = args.input.stat().st_size
    length = image_size - args.start if args.length is None else args.length
    if args.start < 0 or args.start >= image_size:
        return fail("--start is outside the image")
    if length <= 0 or args.start + length > image_size:
        return fail("--length must select bytes within the image")
    if args.chunk_mib < 1 or args.chunk_mib > 1024:
        return fail("--chunk-mib must be between 1 and 1024")
    if args.max_hits < 1 or args.max_hits > 10_000_000:
        return fail("--max-hits must be between 1 and 10000000")
    if args.sector_size not in VALID_SECTOR_SIZES:
        return fail("--sector-size must be one of 512, 1024, 2048, 4096")
    try:
        result = scan(
            args.input,
            args.outdir,
            args.start,
            length,
            args.chunk_mib * 1024 * 1024,
            args.max_hits,
            args.sector_size,
        )
    except (OSError, ValueError, struct.error) as exc:
        return fail("scan failed: {}".format(exc), 1)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

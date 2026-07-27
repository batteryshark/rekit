---
name: disk-image-scan
description: "Read-only forensic inventory of raw disk images and large media blobs: hash a selected byte range, parse MBR/GPT partition maps, validate ext/NTFS/FAT/ISO filesystem candidates, and locate archive and evidence signatures with absolute byte and LBA offsets. Use before carving or filesystem recovery to map evidence-bearing regions. Pure Python; never mounts or modifies the image."
---

# Disk Image Scanner

Inventory an image before recovery. Keep the source image read-only and write a
machine-readable `scan.jsonl` plus `summary.json` beneath a new or empty output directory.

## Workflow

1. Record the source path, size, timestamps, selected range, and SHA-256.
2. Parse MBR or GPT metadata when present; do not infer partitions from filenames.
3. Stream the selected range and validate filesystem structures rather than trusting a
   bare magic string.
4. Use the emitted offsets to choose the next action:
   - pass `scan.jsonl` to `forensic-archive-carve`;
   - pass a validated filesystem `lba512` or `inferredStartLba` to
     `filesystem-recover`;
   - use `binwalk-carve` for firmware filesystems and heterogeneous embedded payloads.
5. Preserve `summary.json` with the recovery output. A full-image scan records
   `imageSha256`; a partial scan records `rangeSha256` and must not be represented as a
   whole-image hash.

## Usage

```bash
bin/rekit run disk-image-scan evidence.img ./forensics/scan
bin/rekit run disk-image-scan evidence.img ./forensics/tail \
  --start 11836177920 --length 28183404544
```

Use `--sector-size` for GPT media whose logical sectors are not 512 bytes. Tune
`--chunk-mib` for throughput. `--max-hits` bounds report growth; if the limit is reached,
the summary marks the scan truncated. MBR inventory covers the four primary entries;
filesystem scanning can still find candidates inside regions not described there, but
extended-partition EBR chains are not parsed.

The runner opens the image only as `rb`. It never mounts the image, repairs metadata, or
executes content.

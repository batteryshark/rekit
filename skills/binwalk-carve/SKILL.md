---
name: binwalk-carve
description: "Carve and recursively extract embedded files from a firmware image or blob (filesystems, bootloaders, nested archives) with binwalk. The heavy sibling of bin-triage's embedded-signature preview. Prereq-gated on binwalk; honest blind spot with an install hint when absent."
---

# Firmware Carver (binwalk)

Carve and recursively extract embedded files from a firmware image or blob with
[binwalk](https://github.com/ReFirmLabs/binwalk) — filesystems (SquashFS/JFFS2/…),
bootloaders, kernels, and nested archives.

## When to use

An IoT/router/embedded firmware dump, or any large blob `bin-triage` flagged as
containing embedded signatures. `bin-triage` *previews* embedded content; this
actually **extracts** it so you can walk the recovered filesystem and analyse it.

## What it does

Runs `binwalk -e <input>` (with cwd = your output dir, so the carved tree lands there
on both binwalk v2 and v3), then reports the file count and the signature scan.
binwalk scans signatures and runs extractors (decompress/unpack) — it does **not**
run the firmware.

## Prerequisites

- **python3** (runner) and **`binwalk`** on PATH. binwalk (v3 is a single Rust binary)
  pulls a whole ecosystem of extractors (`unsquashfs`, `jefferson`, `sasquatch`, …),
  so it is **not bundled** — install it and put it on PATH. Until then `doctor` marks
  the skill not-ready and `run` reports the honest gap with an install hint.

## Usage

```bash
rekit run binwalk-carve ./firmware.bin ./out
# then analyse the recovered tree, e.g.:
rekit run bin-triage ./out/<carved-file>
```

Run this **sandboxed** (no network, writable output dir only) — firmware extractors
are a broad attack surface over untrusted input.

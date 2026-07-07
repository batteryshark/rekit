# Hex Viewer

Non-interactive hex dump of a file or byte range — offset + hex + ASCII, with the
file's total size and sha256. Pure-Python stdlib, no dependencies.

## When to use

You need to look at raw bytes: identify a file by its magic (`7f 45 4c 46` = ELF,
`4d 5a` = PE/MZ, `50 4b` = ZIP/JAR, `de c0` variants, etc.), inspect a header or a
suspicious offset, confirm an embedded payload, or pull a byte snippet into a report.
This is a **viewer**, not an interactive editor — it prints offsets and snippets so
a human or an agent can reason about them without opening a TUI.

## What it does

Reads a slice of the file and prints a classic hexdump, or a structured JSON of the
same rows. It is strictly **read-only**: it never imports, parses as code, or
executes the input — safe on hostile binaries.

## Usage

```bash
rekit run hex-view ./suspicious.bin                       # first 256 bytes
rekit run hex-view ./suspicious.bin --offset 512 --length 128
rekit run hex-view ./suspicious.bin --length 0            # whole file (capped 1 MiB)
rekit run hex-view ./suspicious.bin --format json         # structured rows for tooling
```

Text mode (the view is the output):

```
file: suspicious.bin  size: 40 bytes  sha256: 9f2c...
showing 40 byte(s) at offset 0 (0x0)
00000000  7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00  |.ELF............|
00000010  02 00 3e 00 01 00 00 00 68 65 6c 6c 6f 20 65 76  |..>.....hello ev|
```

JSON mode prints `{ok, path, offset, length, totalBytes, sha256, truncated, rows:[{offset, hex, ascii}]}`
— handy for embedding byte snippets (with offsets) into a report.

## Prerequisites

- **python3 ≥ 3.8** — the only requirement, and it's pure stdlib, so there is no
  `runtime/` to vendor and no build step.

## Options

`--offset` (negative = from end) · `--length` (`0` = whole file, capped at 1 MiB) ·
`--width` (bytes per row, default 16) · `--format text|json`.

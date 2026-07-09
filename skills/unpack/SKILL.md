---
name: unpack
description: "Recursively extract archives to a fixpoint: zip / tar(.gz/.bz2/.xz) / gz / bz2 / xz / asar (Electron) / ar / .deb with the pure-stdlib core, 7z and RAR via an external CLI (7z/7za/7zz, unar) when present. Walks the output for nested archives and extracts those too. Guards against zip-slip (path traversal) and decompression bombs (byte budget). Extraction is not execution — contents are written, never run."
---

# Archive Unpacker (recursive, safe)

Recursively extract archives to a fixpoint — safely, on untrusted input. Pure-stdlib
core; `.7z`/`.rar` via a CLI when present.

## When to use

Malicious code hides behind packing: a dropped `.zip` holds a `.tar.gz` holds the
payload; an npm tarball wraps the install script. Extract first, then scan/decompile
the revealed tree (`pyc-decompile`, the `*-analyze` skills, `js-covert-scan`, …).

## What it does

- **Formats** — `zip`, `tar` (+`.gz`/`.bz2`/`.xz`), plain `gz`/`bz2`/`xz`, **`asar`**
  (Electron `app.asar`), and **`ar`/`.deb`** (the inner control/data tarballs are then
  recursed into) with the standard library (portable, no deps). `7z` and `rar` shell
  out to `7z`/`7za`/`7zz`
  or `unar`/`unrar` **if on PATH**; if not, they're reported in `toolsMissing`
  (honest gap — nothing silently skipped).
- **Recursive** — after extracting, it walks the output for nested archives and
  extracts those too, up to a depth cap, deduping by content hash.

## Safety (this extracts untrusted archives)

- **Zip-slip / path traversal** — every member must resolve *inside* the output dir;
  absolute paths, `..`, and out-of-tree symlinks are skipped (tar uses the stdlib
  `data` filter on Python 3.12+).
- **Decompression bombs** — a total-bytes budget (default 512 MiB) and per-file cap
  stop runaway output; over-budget members land in `skipped`.
- Extraction is **not** execution — contents are written to disk, never run.

## Usage

```bash
rekit run unpack ./suspicious.tgz ./out
rekit run unpack ./dropper.zip ./out --max-depth 12 --max-bytes 1073741824
```

Returns JSON: `{format, extractedTo, fileCount, nestedArchives, skipped, toolsMissing}`.

## Prerequisites

- **python3 ≥ 3.8** (3.12+ for the safe tar `data` filter). Pure stdlib.
- *Optional:* `7z`/`7za`/`7zz` for `.7z`, `unar`/`unrar` for `.rar` — only needed if
  you hit those formats.

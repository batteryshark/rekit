---
name: intellidiff
description: "Compare files exactly or with deliberate text normalization, compare directory trees, find duplicate files, calculate SHA-256 and CRC32 identities, and read bounded line ranges. Use for change analysis, duplicate/orphan discovery, checksum verification, or focused source inspection. Pure-stdlib and read-only; never executes input or follows symlinks."
---

# IntelliDiff

Use one read-only, pure-stdlib runner to compare files or directory trees, find duplicate
files, calculate file identities, and retrieve bounded line ranges. Every operation emits
one JSON object by default; pass `--format text` for human-readable output.

## Operations

| Operation | Purpose |
|---|---|
| `compare target other` | Compare two files exactly or as normalized text. |
| `folder-compare target other` | Compare relative file paths and content identities in two trees. |
| `duplicates target` | Group duplicate files in one tree and report wasted bytes. |
| `hash target` | Return SHA-256, CRC32, size, file type, and timestamps. |
| `lines target` | Return a numbered line range with optional surrounding context. |

Invoke through Rekit:

```bash
bin/rekit run intellidiff compare old.txt new.txt --mode smart --ignore-whitespace
bin/rekit run intellidiff folder-compare old-tree new-tree --binary --depth 20
bin/rekit run intellidiff duplicates artifacts --include-hidden
bin/rekit run intellidiff hash sample.bin
bin/rekit run intellidiff lines parser.py --start 40 --end 80 --context 3
```

## Comparison choices

- Use the default `--mode exact` for byte identity. The runner streams both SHA-256 and
  CRC32; SHA-256 determines identity.
- Use `--mode smart` only for text. Add `--ignore-blank`, `--ignore-newlines`,
  `--ignore-whitespace`, `--ignore-case`, `--normalize-tabs`, or `--unicode-normalize`
  when those differences are intentionally irrelevant.
- Unified diffs are capped at 2,000 lines by default. Adjust `--max-diff-lines` when a
  larger result is genuinely useful.
- Folder comparison skips binary files unless `--binary` is passed. Tree operations skip
  hidden paths unless `--include-hidden` is passed, never follow symlinks, and default to
  a recursion depth of 10.

## Interpret results

Treat CRC32 as a quick compatibility checksum, not proof of identity. Use `sha256` for
identity and integrity decisions. Smart comparison decodes as UTF-8 with replacement for
invalid sequences; it is intended for readable source and configuration files, not exact
forensic byte comparison.

---
name: bin-table-diff
description: "Find fixed-stride record tables compiled into a binary (song lists, level tables, item stats), infer each column's type from the data, extract them to JSON/CSV, and diff two builds record by record. Use when content lives in static tables rather than data files and a function-level diff would miss it entirely — added or removed entries, rebalanced values, regional catalogue swaps. Pure stdlib and read-only; never executes the input."
---

# Binary Record Table Diff

Find the fixed-stride record tables compiled into a binary, extract them, and diff two
builds record by record.

## When to use

Software of a certain era compiles its content straight into the executable: song lists,
level and difficulty tables, item stats, string catalogues. **A function-level diff is
blind to all of it** — an added track or a rebalanced difficulty changes no code at all.
If you are documenting what changed between two builds and only diffing code, you are
missing whatever lives in these tables.

Pair it with `diaphora-diff` or `bindiff`: those tell you which functions changed, this
tells you which content did.

## Usage

```bash
rekit run bin-table-diff find    ./game-1.0                        # locate tables
rekit run bin-table-diff extract ./game-1.0 ./out                  # JSON + CSV
rekit run bin-table-diff diff    ./game-1.0 ./game-1.1 ./out       # record-level diff
```

## How detection works, and what it can't know

A table is found by a signal that is hard to counterfeit: a run of records at a fixed
stride where the same position in every record holds a pointer into the binary's own
string data. Nothing about the layout is assumed — stride, extent, and column types all
come from the bytes, so it works across eras and games whose structs differ.

Virtual addresses are translated through the binary's `PT_LOAD` headers rather than an
assumed load base, so it is not tied to any one platform convention.

**Offsets are anchor-relative.** Where the pointer block sits inside the struct cannot be
recovered from pointer validity alone — every candidate alignment describes the same
bytes, so testing them proves nothing. The pointer block is therefore treated as column
0 and every column labelled relative to it. Extraction stays self-consistent and two
builds diff correctly, because both are detected identically. Columns are named by their
offset from that anchor (`f00`, `f04`, …), not by any inferred meaning. Pass
`--offset/--stride/--records` when you know the true struct start and want
struct-relative columns.

## Column typing

Each 4-byte column is typed by how its values behave across every record:

| Kind | Test |
|---|---|
| `string` | >90% of non-null values point at printable NUL-terminated data |
| `pointer` | >90% point *somewhere* in the image but not at a string |
| `float` | >90% reinterpret as finite floats in a sane magnitude range |
| `byte` / `small` | all values fit in a byte (or are `-1`) |
| `int` | everything else |

`pointer` columns are compared as present/absent, never by value: the address shifts
between builds even when the pointed-to content is identical, so comparing raw values
would report changes that did not happen.

## Record identity

Diffing by position would report every record after an insertion as changed, so records
are matched by a **key**: the two most distinctive string columns joined together, with
repeats numbered. A single column is rarely unique on its own — the same title appears
once per difficulty, the same artist many times over — and requiring uniqueness from one
column makes identification fail exactly where it matters. Override with `--key f08+f0C`.

If no usable string column exists the diff falls back to positional comparison and says
so in the output. Treat those results with suspicion: a single inserted row shifts
everything after it.

## Text encoding

Regional builds store catalogues in the local codepage, so a corpus spans several. Each
string is decoded by trying UTF-8 first (it rejects almost anything that is not genuinely
UTF-8), then the CJK codepages. **These overlap** — EUC-KR will happily decode Big5 bytes
into the wrong glyphs — so a decoded string from a foreign-market build is a best guess.
Pass `--encoding big5` to pin it when you know the market.

## Interpret results

- `added` / `removed` are entries whose key appears on only one side; `changed` lists
  per-field before/after values.
- **A detected table is not necessarily the one you want.** `find` lists candidates
  largest first; check that the strings look like your content before trusting a diff,
  and use `extract` to eyeball a table in full.
- The backward walk can absorb a row or two of an adjacent structure that happens to
  share the stride and have string pointers. Those rows show up as spurious changes with
  pointer-valued fields — check the first and last records of an extraction.

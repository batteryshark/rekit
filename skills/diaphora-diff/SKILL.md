---
name: diaphora-diff
description: "Match functions between two builds of a program with Diaphora, recover symbol names from a build that has them onto stripped builds, and emit per-function pseudocode diffs documenting what changed. Use for version lineage archaeology, renaming stripped binaries from an unstripped sibling, and reconstructing undocumented source changes between releases. Export needs IDA; diffing and reporting are pure Python. Static — analyses and matches, never runs the targets."
---

# Diaphora Program Diff

Match functions between two builds of a program, **recover symbol names** from a build
that has them onto builds that don't, and emit per-function pseudocode diffs that
document what actually changed.

## When to use

- **Name recovery** — one build shipped unstripped (or you reversed it by hand); its
  siblings are stripped. Match them and carry the names across. This is the highest-value
  use and the reason to prefer Diaphora over `bindiff`: it keeps every function's
  pseudocode on both sides, so a match is reviewable rather than a bare address pair.
- **Version lineage** — a chain of releases with no source history. Diff each adjacent
  pair to establish what changed, when, and in which subsystem.
- **Source reconstruction** — recovered C++ mangled names carry `Class::method` plus
  parameter types, which maps binary functions back onto a source tree you're rebuilding.
- **Patch analysis** — the changed list, sorted by ascending ratio, is the worklist.

Reach for `bindiff` when you want a fast structural answer or you only have Ghidra;
reach for this when match *quality* matters or you need the pseudocode to read.

## The two halves

| Step | Needs IDA? | Cost |
|---|---|---|
| `export` | **yes** | slow — full IDA analysis, once per binary |
| `diff` / `report` | no | fast — pure Python over the exported SQLite |

Export is cached by binary hash, so a corpus of N builds costs N exports and then any
pairing is cheap. Export once, diff forever.

## Usage

```bash
# one-shot: export both (cached) then diff
rekit run diaphora-diff compare ./unstripped.bin ./stripped.bin ./out --decompiler

# or drive the halves yourself, sharing exports across many pairings
rekit run diaphora-diff export ./v1.01 ./cache/v1.01.sqlite --decompiler
rekit run diaphora-diff export ./v1.02 ./cache/v1.02.sqlite --decompiler
rekit run diaphora-diff diff ./cache/v1.01.sqlite ./cache/v1.02.sqlite ./out/1.01-1.02

# re-report an existing results database with different thresholds — no re-diffing
rekit run diaphora-diff report ./cache/v1.01.sqlite ./cache/v1.02.sqlite ./out \
    --results ./out/results.sqlite --min-ratio 0.9
```

**Direction matters.** `target` is the primary, `other` the secondary, and names flow
**primary → secondary**. Put the build that HAS symbols first.

Pass `--decompiler` unless you have a reason not to: Hex-Rays pseudocode makes Diaphora's
matching substantially better and turns the pseudocode diffs into something readable.

## Outputs

| File | Contents |
|---|---|
| `summary.json` | the object also printed under `--format json` |
| `renames.json` | recovered names: secondary address → name from the primary, with ratio, match type, mangled name and prototype |
| `apply_names.py` | **IDA script** applying those renames to the secondary's database — review it, then run it in IDA |
| `matches.json` | every matched pair split into `identical` and `changed` |
| `unmatched.json` | functions Diaphora could not pair on either side |
| `pseudo/<ratio>_<name>.diff` | unified pseudocode diff per changed function, filename-sorted by ratio so the biggest changes read first |
| `results.sqlite` | Diaphora's own results database |

`apply_names.py` never overwrites a function that already has a real name, so it is safe
to re-run as you recover more names from further pairings.

## Pseudocode normalization

Raw Hex-Rays output diffs badly: adding one local renumbers every later one, every
address shifts between builds, and each line carries a register-allocation comment. A
one-line source change can rewrite half a function's text. So `pseudo/*.diff` is
normalized by default:

- **trailing `// eax` / `// [esp+32h]` comments** are dropped;
- **call and data targets are rewritten to a token shared by both sides** whenever the
  referenced function is itself a matched pair — so a callee that merely moved reads as
  unchanged, while a call to a genuinely different function still stands out.
  *Addresses with no match are left verbatim*: without a match there is no evidence the
  two refer to the same thing, and collapsing them would hide a real difference. Global
  data is the common case here, since Diaphora matches functions, not globals;
- **locals are renumbered by first use in the body**, so declaration-order churn does
  not cascade through every statement;
- **the declaration block is collapsed to `// N local(s)`** — these are compiler
  temporaries whose order, types and numbering shift freely between builds. The count
  still moves when locals are added or removed.

Argument names (`a1`, `a2`) are deliberately left alone: their order is a real signature
fact. Pass `--raw-pseudo` for verbatim output when you need to see exactly what the
decompiler emitted.

On real adjacent builds this typically halves the diff; on the cleanest cases it cuts
39 changed lines to 15, leaving only the actual source change.

## Interpret results

- Diaphora grades every match: **best** > **partial** > **unreliable** > **multimatch**.
  Only `best,partial` feed name recovery by default (`--rename-types`), above
  `--min-ratio 0.75`. Widen deliberately, and review what you widen into.
- **`multimatch` means one function matched several candidates** — common with template
  instantiations, inlined helpers, and identical small accessors. Never auto-apply these;
  the name is probably right for *one* of them.
- **A match is evidence, not proof.** Ratio measures structural agreement, not semantic
  identity. Two different functions compiled from the same template match beautifully.
- Diffing across a **toolchain change** inflates the changed list — every function looks
  modified because the codegen moved. Check each build's `.comment` section for its GCC
  version first; if the compilers differ, treat low ratios as unremarkable and weight
  call-graph position over ratio.
- `unmatched` in the secondary is new code; `unmatched` in the primary is deleted code —
  but only once you trust the match rate. A low overall match count means the matcher
  struggled, not that the program was rewritten.

## Chaining name recovery across a corpus

With one named build and several stripped ones, recover transitively: match the named
build against its **closest** sibling first (same era, same toolchain), then use that
now-named build as the primary for the next hop. Each hop loses some names, so ordering
by closeness rather than by version number recovers materially more than going straight
to the most distant target.

`--name-map` is what makes a chain accumulate. Hop 2's primary export is still stripped,
so without it every hop restarts from `sub_*` and only functions named in the original
donor ever propagate. Feed each hop's `renames.json` into the next:

```bash
rekit run diaphora-diff diff donor.sqlite b.sqlite ./out/1
rekit run diaphora-diff diff b.sqlite c.sqlite ./out/2 --name-map ./out/1/renames.json
rekit run diaphora-diff diff c.sqlite d.sqlite ./out/3 --name-map ./out/2/renames.json
```

A name map never overrides a name the primary already has — recovered names only fill
gaps, so re-running a hop with a better map can add names but never lose them.

**Order the chain by toolchain, not by version number.** Check each build's `.comment`
section first: a hop within one compiler generation recovers far more than a hop across
a generation boundary, even when the version numbers are adjacent.

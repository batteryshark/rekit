# Technical changelog workflow

Use this workflow after `compare`, `diff`, or `report` when the deliverable is an
evidence-backed explanation of what changed between two program versions. The goal is
not a list of different functions. Produce a historical record that distinguishes
behavior changes, compiler or layout churn, verified non-changes, and unresolved areas.

## 1. Establish the comparison boundary

Record before interpreting the diff:

- exact primary and secondary filenames, versions, sizes, and cryptographic hashes;
- file format, architecture, image base, entry point, and relevant build metadata;
- compiler, linker, language-runtime, optimization, packing, and signing evidence when
  recoverable;
- section or segment sizes, imports/exports, dependencies, and referenced strings;
- external assets, resources, configuration, schemas, firmware, or databases that may
  carry behavior outside the compared binaries.

State which artifact is older and which is newer. Put a symbol-rich build first only for
name propagation; do not silently reverse chronological language in the changelog.

If the toolchain changed, establish a noise floor with a known-equivalent or closest
available pair when practical. Otherwise say that code-generation churn could not be
calibrated.

## 2. Produce and health-check the evidence

Prefer decompiler-enabled exports:

```bash
rekit run diaphora-diff compare ./old.bin ./new.bin ./out --decompiler --format json
```

Before analysis, inspect `summary.json`, `matches.json`, `unmatched.json`, and every
generated `pseudo/*.diff`:

1. When matches exist, require `counts.joinResolution == 1.0`. A lower value means some
   results did not join back to export rows; prototypes, names, and pseudocode are
   incomplete. Fix that before claiming complete coverage. With zero matches, treat the
   null value as no join evidence, not as success.
2. Calculate match coverage from distinct matched functions and export function totals.
   A low rate makes unmatched counts unreliable as evidence of added or removed code.
3. Review match types and ratios. Treat `unreliable` and `multimatch` as hypotheses, not
   identities. Reconcile them with callers, callees, strings, constants, prototypes, and
   control-flow position.
4. Ensure `--max-pseudo-diffs` did not truncate the changed worklist. Raise it or inspect
   the remaining functions directly.
5. Re-run selected functions with `--raw-pseudo` when normalization might hide a material
   declaration, cast, address, or decompiler detail.

Never use an address, `sub_<address>` name, function size, or similarity score as function
identity by itself. An address is a coordinate; a size is supporting evidence; a match is
evidence, not proof.

## 3. Build a complete accounting ledger

Create a scratch ledger with one row for every changed match and every unmatched function.
Track:

| Field | Record |
|---|---|
| identity | old/new address, name, prototype, match type, ratio |
| evidence | pseudocode diff, assembly if needed, callers/callees, strings, data references |
| classification | semantic change, cascade, compiler/layout churn, false unmatched, unresolved |
| group | the single logical change this row belongs to |
| confidence | verified, high-confidence inference, tentative, unresolved |
| changelog section | finding, accounting-only, verified negative, or blind spot |

Reconcile unmatched functions manually. A heavily rewritten function may appear as one
removed plus one added entry. Conversely, an unmatched function can be a compiler fragment,
thunk, alignment artifact, template clone, or import stub rather than net-new behavior.

Account for every ledger row in the final document, either under a substantive finding or
in a compact non-functional/unresolved table. Do not let inconvenient rows disappear.

## 4. Recover the logical changes

Read the lowest-ratio and unmatched candidates first, then review all remaining changed
functions. For each candidate:

- compare control flow, constants, call targets, arguments, return paths, data accesses,
  allocation sizes, field offsets, strings, error handling, initialization, cleanup, and
  synchronization;
- follow changed callees upward to their callers and changed data downward to its consumers;
- inspect adjacent functions or cross-references when the local diff does not explain the
  user-visible consequence;
- corroborate important layout or protocol claims against parsers, headers, symbols, debug
  information, shipped data, formats, documentation, or runtime observations when available;
- separate what the binary proves from the likely motivation. Do not label a change a bug
  fix, vulnerability fix, optimization, or feature unless evidence supports that label.

Group cascades. One structure growing can recompile dozens of accessors; one API signature
change can alter every caller; one string-pool move can touch many references. Report the
root change once and list its dependent functions as accounting, not as separate features.

Useful generic classifications include:

- functional logic or state-machine change;
- constant, threshold, timeout, bound, mask, or default change;
- call added, removed, reordered, or retargeted;
- input validation, error handling, cleanup, or security-hardening change;
- structure, allocation, field-layout, serialization, or ABI change;
- dependency, import/export, resource, path, protocol, or format change;
- data/content-only change outside executable code;
- compiler, linker, optimizer, register-allocation, inlining, padding, or relocation churn.

## 5. Verify meaningful negatives

Choose high-value subsystems implied by the product and the positive findings, then verify
them explicitly. Examples include protocol compatibility, file formats, persistence,
authentication, cryptography, update behavior, scoring, timing, device I/O, imports, or
embedded content.

Use precise language:

- **Verified unchanged:** name the functions, tables, imports, bytes, or other bounded
  evidence actually compared.
- **No change found:** the available evidence was reviewed but coverage is incomplete.
- **Not assessed / cannot determine:** the behavior lives outside the inputs or the analysis
  could not resolve it.

Never turn “not present in the changed-function list” into “unchanged” without checking that
matching coverage and the relevant data surface support the claim.

## 6. Write the changelog

Write `CHANGELOG-<old>-to-<new>.md` with this structure, adapting headings to the target:

```markdown
# <Product> — Technical Binary Changelog: <old> → <new>

> Provenance, analysis method, input hashes, scope, and reproducibility statement.

## Summary
Comparison metrics table, concise release characterization, and numbered findings.

## 1. <Behavior-level finding>
What changed, old versus new evidence, affected flow/data, consequence, uncertainty.

## N. Non-functional and unresolved differences
Compact table reconciling compiler/layout churn and unresolved rows.

## Complete function accounting
Matched/changed/identical/unmatched totals and disposition of every changed row.

## Verified negatives and blind spots
Explicitly checked non-changes, unassessed surfaces, and external-content limitations.

## Reproduction
Commands, tool versions, artifact paths, thresholds, and any manual corroboration.
```

Lead each finding with behavior, not byte counts or addresses. Include exact constants,
offsets, masks, prototypes, pseudocode or assembly fragments, and old/new addresses as
supporting evidence. Explain consequences for callers, operators, users, file or network
compatibility, and downstream tools when the evidence permits it.

Clearly label inference and uncertainty. Prefer “the new guard prevents the fall-through”
over “the developer fixed a crash”; prefer “consistent with a compatibility shim” over an
unsupported claim of intent. If a claim cannot be resolved, preserve the evidence and say so.

## 7. Final audit

Before delivery, verify:

- input identities and comparison direction are unambiguous;
- summary totals agree with `summary.json` and the ledger;
- every changed and unmatched row has a disposition;
- no finding relies only on an address, size, score, or decompiler rendering;
- cascades are collapsed into logical changes;
- external data is not declared unchanged from a code-only comparison;
- facts, inferences, hypotheses, and blind spots are distinguishable;
- verified negatives name their evidence boundary;
- commands and artifact paths are sufficient to reproduce the analysis.

For a release series, diff adjacent versions and write one changelog per pair. Use longer-range
comparisons only as cross-checks; they compound toolchain churn and obscure when a change first
appeared.

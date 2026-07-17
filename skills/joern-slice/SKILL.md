---
name: joern-slice
description: "Build a bounded code property graph and focused data-flow or usage slice with pinned Joern. Use when reverse engineering or security analysis needs interprocedural source context beyond syntax trees. Static and offline; never executes target code."
---

# Joern Code Slicer

Use Joern after syntax-level inspection has identified a function, API, or behavior
worth deeper analysis. It builds a code property graph (CPG), asks Joern for a bounded
slice, and emits both the raw graph and a stable Rekit evidence document. This is a
deeper layer than Tree-sitter, not a replacement for broad multi-language scanning.

## Install

```bash
rekit install joern-slice
rekit doctor joern-slice
```

The explicit install step pulls the official image by immutable multi-platform digest.
Analysis never pulls and always runs with Docker networking disabled.

## Usage

```bash
rekit run joern-slice ./source ./out --language pythonsrc
rekit run joern-slice ./source ./out --language jssrc --mode data-flow \
  --sink-filter '.*(?:eval|exec).*'
rekit run joern-slice ./source ./out --language c --mode usages
```

`behavior-flow` is the default. Its declarative profile selects source and sink
patterns without accepting executable Joern or Scala supplied by the caller. Pass a
versioned profile with `--profile`; its schema is in `assets/profile.schema.json`.
`data-flow` exposes Joern's bounded graph directly, while `usages` records method and
type usages. Use `--reuse-cpg` when iterating on profiles against an already generated
CPG from the same target and frontend. Reuse requires its sibling `evidence.json` and
verifies the target manifest, frontend, and immutable image before accepting the CPG.

Every run publishes `cpg.bin`, `raw-slice.json`, and `evidence.json` atomically. The
evidence records the target manifest digest, frontend, profile digest, image identity,
coverage, graph, paths, findings, resource limits, and phase timing. Joern frontends
vary: some graphs contain an explicit edge to the sink, while others end at the value
selected by the sink query. Rekit labels the latter `slice-selected-by-sink`; it does
not fabricate a reaching-definition edge.

## Scope and safety

One run analyzes one frontend and one CPG. Mixed-language repositories require one run
per relevant language; the results do not imply cross-language data flow. The default
input bounds are 10,000 regular files and 512 MiB. Symlinks are excluded and reported.
The target is copied into a temporary read-only mount. Target code is parsed but never
executed.

The container uses a read-only root filesystem, no network, no capabilities, no
privilege escalation, and CPU, memory, process, temporary-storage, and wall-clock
limits. `/tmp` is private but executable because Joern's trusted zstd JNI library is
loaded from there. Only the temporary analysis output is writable.

Treat an empty, unresolved, or excluded result as bounded evidence, not proof that a
behavior is absent. Use the reported coverage and unresolved fields when composing a
reverse-engineering conclusion.

---
name: protection-survey
description: "Statically survey source trees for anti-analysis and protection patterns across C/C++, Objective-C, assembly, Rust, Go, Python, JavaScript/TypeScript, Java/Kotlin, C#, and Swift. Finds anti-debug/VM checks, runtime API resolution, executable-memory changes, early execution, custom sections, inline assembly, opaque/flattened control flow, stack strings, obfuscating build flags, injection primitives, and self-integrity checks. Emits evidence with confidence; read-only and never executes source."
---

# Source Protection Survey

Run a fast, read-only first pass over source code before deeper manual review. The
scanner reports protection *mechanisms*, not intent: each finding is a location,
matched indicator, confidence, and judgment-free `PROT.*` atom.

## Usage

```bash
rekit run protection-survey ./source --format json
rekit run protection-survey ./main.rs --format text
rekit run protection-survey ./source --max-files 20000 --max-file-bytes 4194304
```

## Workflow

1. Scan the project root or a single source/build file.
2. Rank categories by count and confidence.
3. Review the reported lines in context; do not infer maliciousness from one API.
4. Correlate multiple families—for example anti-debug checks plus executable-memory
   transitions plus runtime resolution—before drawing conclusions.

The scanner understands common source extensions for C-family languages, assembly,
Rust, Go, Python, JS/TS, JVM languages, C#, and Swift. It also examines build files
such as `Cargo.toml`, `build.rs`, `Makefile`, and `CMakeLists.txt`. Generated/vendor
trees are skipped by default.

## Output and limits

JSON includes `{ok, root, filesScanned, skipped, findingCount, categoryCounts,
families, assessment, findings}`. Each finding contains `atom`, `confidence`, `file`,
`line`, `col`, `indicator`, `snippet`, and `method: "protection-survey"`.

Regex and co-occurrence heuristics are intentionally explainable. They can miss
macro-generated or semantically disguised protections and can flag legitimate
systems code. Treat the output as a review queue, not a verdict.

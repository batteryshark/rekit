---
name: js-sourcemap-extract
description: "Recover the original, un-minified sources from a JavaScript source map's sourcesContent — turning a bundled/minified .js back into a readable file tree. Accepts a .map (JSON) or a .js that references one via //# sourceMappingURL (inline data: map or sibling .map). Pure stdlib, read-only; path-traversal guarded (strips webpack:// and ../)."
---

# JS Source-Map Extractor

Recover the **original** source from a JavaScript **source map** — the fastest way to
turn a minified/bundled `.js` back into readable files, when a map is available.

## When to use

You have a minified or webpacked bundle (or a leaked prod build) and there's a source
map — a `.map` file, or a `//# sourceMappingURL=` in the `.js` (inline `data:` map or
a sibling `.map`). A map's `sourcesContent` usually holds the *complete original
source* of every input file, so this beats deobfuscation: no guessing, you get the
author's actual code. If there's no map, fall back to `js-deobfuscate`.

## What it does

- Loads the map from a `.map` (JSON) or from a `.js`'s `sourceMappingURL` (inline
  base64 `data:` map, or a sibling `.map` file — never fetched over the network).
- Writes each `sourcesContent` entry to `outdir/<source-path>`, cleaning the path
  (strips `webpack://`, schemes, and `../` so everything stays under the output dir).
- Reports how many sources were recovered vs. had no embedded content.

Read-only, pure stdlib. Then scan the recovered tree with `js-covert-scan` /
`js-deobfuscate`.

## Usage

```bash
rekit run js-sourcemap-extract ./app.min.js.map ./out
rekit run js-sourcemap-extract ./bundle.js ./out    # follows its sourceMappingURL
```

No map found → `{"hasSourceMap": false, "note": "…"}`.

## Prerequisites

- **python3 ≥ 3.8** — pure stdlib, nothing to vendor.

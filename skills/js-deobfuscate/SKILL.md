---
name: js-deobfuscate
description: "Deobfuscate and unpack obfuscated JavaScript (webcrack): reverses string arrays, folds constants, deflattens control flow, unminifies, and splits webpack/browserify bundles. Encoded string arrays are decoded by running the decoder inside an isolated-vm sandbox — not the whole program."
---

# JavaScript Deobfuscator

Statically deobfuscate and unpack obfuscated JavaScript using
[webcrack](https://github.com/j4k0xb/webcrack).

## When to use

Reach for this when JavaScript reads as machine-generated noise and you can't tell
what it does: `_0x`-prefixed identifiers, big string arrays with a decoder function,
`eval(function(p,a,c,k,e,d){...})` packer output, control-flow flattening, or a
single-line minified/webpacked bundle. Deobfuscation often reveals the behaviour the
packing was hiding — a network beacon, a `child_process` spawn, a decode-and-eval.

In an MCD/analysis pipeline: trigger this when the scanner flags obfuscation
(`XFRM.*` atoms) on a JS artifact, then **re-scan the deobfuscated output**.

## What it does

- reverses string-array obfuscation (obfuscator.io style)
- folds constants and simplifies expressions
- deflattens control flow
- unminifies / restores readable structure
- unpacks webpack/browserify bundles into separate module files

Mostly **static** Babel AST transforms. The one exception: to recover *encoded*
string arrays (base64/RC4 obfuscation), webcrack must run the obfuscated **decoder
function** — it does so inside an **isolated-vm sandbox** (no filesystem, no network,
memory/time capped), a narrow slice, never the whole program. That sandboxed
execution is why webcrack carries a native addon. Still run the node process itself
sandboxed: no network, writes only to the output dir, with a timeout.

## Usage

```bash
# via the dispatcher (checks that node is present first)
rekit run js-deobfuscate ./obfuscated.js ./out

# or directly
node skills/js-deobfuscate/runtime/run.mjs ./obfuscated.js ./out
```

Writes `out/deobfuscated.js` (the single-file result) and, for detected bundles,
`out/unpacked/` (one file per recovered module). Prints a JSON result line:

```json
{"ok": true, "outputFile": "out/deobfuscated.js", "unpackedDir": "out/unpacked",
 "moduleCount": 12, "bytesIn": 48213, "bytesOut": 91044, "changed": true}
```

## Prerequisites

- **node ≥ 18** — the only runtime requirement. webcrack (and its native
  `isolated-vm` addon) is vendored under `runtime/node_modules`, so there is no
  `npm install` or network at analysis time. `isolated-vm` ships prebuilt binaries
  for darwin-arm64/x64, linux-x64/arm64, and win32-x64; an LTS node is safest for
  ABI match (otherwise isolated-vm falls back to building from source, which needs a
  C++ toolchain).

If node is absent, the caller should either install it or record the artifact as
*not deobfuscated / not fully analysed* — do not guess at obfuscated behaviour.

## Rebuilding the payload

`runtime/node_modules` is populated from a pinned webcrack by `scripts/build.sh`
(npm, at build time only). Re-run it to refresh and re-pin the version; commit the
vendored `runtime/` so the skill stays offline.

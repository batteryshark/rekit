// Runner for the js-deobfuscate skill. Lives next to the vendored ./node_modules,
// so `import { webcrack } from 'webcrack'` resolves to the pinned, offline copy.
//
// Contract: `node run.mjs <input.js> <outdir>`
//   - writes <outdir>/deobfuscated.js         (single-file deobfuscated result)
//   - writes <outdir>/unpacked/**             (one file per module, if a bundle)
//   - prints ONE json object to stdout        (the machine result)
//
// SAFETY: mostly static AST transforms. To recover ENCODED string arrays webcrack
// executes the obfuscated *decoder function* inside an isolated-vm sandbox (no fs,
// no network, capped) — a narrow slice, not the whole program. Still run this node
// process sandboxed (no network, writes only to <outdir>, with a timeout).

import { webcrack } from 'webcrack';
import { readFileSync, mkdirSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

function emit(obj) { process.stdout.write(JSON.stringify(obj) + '\n'); }
function fail(msg, code = 1) { emit({ ok: false, error: msg }); process.exit(code); }

const inputPath = process.argv[2];
const outDir = process.argv[3];
if (!inputPath || !outDir) fail('usage: run.mjs <input.js> <outdir>', 2);

let code;
try {
  code = readFileSync(inputPath, 'utf8');
} catch (e) {
  fail(`cannot read input: ${e.message}`, 2);
}

try {
  mkdirSync(outDir, { recursive: true });
  const result = await webcrack(code);

  const outputFile = resolve(join(outDir, 'deobfuscated.js'));
  writeFileSync(outputFile, result.code, 'utf8');

  let unpackedDir = null;
  let moduleCount = 0;
  const modules = result.bundle?.modules;
  if (modules && (modules.size ?? modules.length ?? 0) > 0) {
    unpackedDir = resolve(join(outDir, 'unpacked'));
    await result.save(unpackedDir);
    moduleCount = modules.size ?? modules.length ?? 0;
  }

  emit({
    ok: true,
    outputFile,
    unpackedDir,
    moduleCount,
    bytesIn: Buffer.byteLength(code, 'utf8'),
    bytesOut: Buffer.byteLength(result.code, 'utf8'),
    changed: result.code !== code,
  });
} catch (e) {
  fail(`webcrack failed: ${e?.stack || e?.message || String(e)}`);
}

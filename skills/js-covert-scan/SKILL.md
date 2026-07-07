# JavaScript Covert-Tactics Scanner

Detect the tactics code uses to **hide what it does** in JavaScript/TypeScript, and
emit atoms a caller can reason over. Static, read-only, pure-stdlib.

## When to use

You suspect a file is doing something it doesn't advertise — behaving differently
for some users, smuggling signal through text, or hiding strings/logic from a casual
read or a `strings` dump. This scanner surfaces the *tactics*; it does not decide
intent. Run it on a file or a whole package.

## What it detects — three families of atoms

**STEGO** — hidden in text you can't see or can't tell apart:
- `STEGO.INVISIBLE` — zero-width / format / control characters (U+200B, U+FEFF,
  soft hyphen, word joiner, variation selectors, tag chars…).
- `STEGO.BIDI` — bidirectional control characters (the "Trojan Source" reordering
  attack: source that reads differently than it compiles).
- `STEGO.HOMOGLYPH` — confusable characters standing in for ASCII: fancy apostrophes
  / quotes (e.g. `U+2019 ’`, `U+02BC ʼ`, `U+02B9 ʹ`), non-breaking / ideographic
  spaces, look-alike dashes, and Cyrillic/Greek/fullwidth letters posing as Latin.

**OBF** — machine-hidden strings/logic:
- `OBF.XOR` — XOR of character codes (a common way to keep strings out of a plain
  `strings` dump).
- `OBF.CHARCODE` — strings assembled from `String.fromCharCode(…)` number lists.
- `OBF.ESCAPE` — long `\xNN` / `\uNNNN` escaped string blobs.
- `OBF.DYNEVAL` — `eval(…)` / `new Function(…)` dynamic execution.

**EVADE** — environment-keyed conditional behavior (act differently for specific
victims / dodge analysis):
- `EVADE.TIMEZONE` — `Intl.DateTimeFormat().resolvedOptions().timeZone`, timezone
  name literals.
- `EVADE.LOCALE` — `navigator.language`, resolved locale checks.
- `EVADE.GEO` — geolocation / IP-geo checks.
- `EVADE.PROXY` — proxy / `*_PROXY` env checks.

**The real signal is combination.** Any one atom can be innocent. Steganographic
punctuation *next to* a timezone check *next to* an XOR decoder is the shape of
covert, targeted, conditional behavior — so the scan reports a co-occurrence
`assessment` across families, not just isolated hits.

## Usage

```bash
rekit run js-covert-scan ./suspEcious.js
rekit run js-covert-scan ./some-package --format json
```

Text mode prints ranked atoms with location, codepoint (for STEGO), and the line.
JSON mode returns `{ok, filesScanned, findingCount, summary, families, assessment,
findings:[{atom, family, confidence, file, line, col, codepoint?, snippet, note}]}` —
ready to fold into an MCD reading (the atoms map cleanly onto XFRM/EVADE lenses).

## Prerequisites

- **python3 ≥ 3.8** — pure stdlib (`unicodedata` + `re`), no vendored runtime.

## Notes / limits

Regex + Unicode heuristics, not a full parser: strong on the textual tactics
(steganography especially), best-effort on logic-level obfuscation. Homoglyph
*letters* and confusable punctuation can occur in legitimate natural-language
strings, so they carry lower confidence — weigh them with the co-occurrence
assessment. A future version can add AST-level precision for the OBF/EVADE atoms.

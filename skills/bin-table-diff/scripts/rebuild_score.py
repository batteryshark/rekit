#!/usr/bin/env python3
"""Score a rebuild: how much of a target binary do freshly compiled objects reproduce?

The measurement that matters for a reconstruction project is not "does it build"
but "how much of the shipped binary does this source actually account for" —
weighted by bytes, because a count of functions is flattered by a long tail of
tiny accessors.

Two things make a naive byte comparison useless, and both are handled here:

* **Relocations.** A `.o` holds zeros (or addends) where the linker will later
  patch in addresses; the shipped binary holds the resolved values. Every
  function that calls anything or touches a global would mismatch. Relocation
  sites are read from `.rel.text` and masked out of *both* sides before
  comparing, which is the standard decompilation-project technique.
* **Name shape.** Object symbols are Itanium-mangled (`_ZN7CSelect5BeginEv`)
  while a disassembler's database holds `CSelect::Begin`. Simple mangled names
  are decoded so the two can be matched.

    rebuild_score.py --objects DIR --target BIN --names names.json --sizes sizes.json

Functions whose name is not in the target database fall back to a window-overlap
score, which measures how much of the compiled code appears anywhere in the
target — weaker evidence, reported separately and never mixed into the exact
match figure.
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import re
import struct
import sys

MANGLED = re.compile(r"^_ZN?(\d+)(.+)$")


def demangle_simple(name: str) -> str | None:
    """`_ZN7CSelect5BeginEv` -> `CSelect::Begin`. Only the simple nested form."""
    if not name.startswith("_ZN"):
        return None
    rest, parts = name[3:], []
    while rest and rest[0].isdigit():
        match = re.match(r"^(\d+)", rest)
        length = int(match.group(1))
        rest = rest[match.end():]
        if len(rest) < length:
            return None
        parts.append(rest[:length])
        rest = rest[length:]
    return "::".join(parts) if len(parts) >= 2 else None


class Elf:
    def __init__(self, path: str):
        self.data = open(path, "rb").read()
        d = self.data
        if d[:4] != b"\x7fELF":
            raise ValueError(f"not ELF: {path}")
        e_shoff, = struct.unpack_from("<I", d, 0x20)
        entsize, num, strndx = struct.unpack_from("<HHH", d, 0x2E)
        self._sh = [struct.unpack_from("<IIIIIIIIII", d, e_shoff + i * entsize)
                    for i in range(num)]
        stroff = self._sh[strndx][4]
        self.sections = {}
        for sh in self._sh:
            s = d[stroff + sh[0]:]
            self.sections[s[:s.index(b"\0")].decode()] = sh

    def section(self, name: str) -> bytes:
        sh = self.sections.get(name)
        return self.data[sh[4]:sh[4] + sh[5]] if sh else b""

    def functions(self) -> list:
        """(name, offset_in_text, size) for STT_FUNC symbols in .text."""
        sym, strt = self.sections.get(".symtab"), self.sections.get(".strtab")
        text_index = None
        for i, sh in enumerate(self._sh):
            if sh is self.sections.get(".text"):
                text_index = i
        if not sym or not strt:
            return []
        out = []
        for i in range(sym[5] // sym[9]):
            off = sym[4] + i * sym[9]
            nm, value, size, info, _o, shndx = struct.unpack_from("<IIIBBH", self.data, off)
            if info & 0xF != 2 or not size:
                continue
            if text_index is not None and shndx != text_index:
                continue
            s = self.data[strt[4] + nm:]
            out.append((s[:s.index(b"\0")].decode(), value, size))
        return out

    def text_relocations(self) -> set:
        """Byte offsets within .text that the linker will patch."""
        rel = self.sections.get(".rel.text")
        if not rel:
            return set()
        masked = set()
        for i in range(rel[5] // 8):
            offset, _info = struct.unpack_from("<II", self.data, rel[4] + i * 8)
            masked.update(range(offset, offset + 4))
        return masked


def masked(buf: bytes, base: int, holes: set) -> bytes:
    out = bytearray(buf)
    for i in range(len(out)):
        if base + i in holes:
            out[i] = 0
    return bytes(out)


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="rebuild-score")
    p.add_argument("--objects", required=True)
    p.add_argument("--target", required=True)
    p.add_argument("--names", required=True)
    p.add_argument("--sizes", required=True)
    p.add_argument("--funcmeta",
                   help="per-address {raw_name,...} map; lets mangled object "
                        "symbols match uniquely instead of via display names, "
                        "which are shared by C1/C2 and D0/D1 pairs")
    p.add_argument("--window", type=int, default=24)
    p.add_argument("--min-evidence", type=int, default=16,
                   help="an exact match resting on fewer than this many "
                        "UNMASKED bytes is flagged weak: masking relocated "
                        "operands can equate genuinely different functions")
    p.add_argument("--json", action="store_true")
    a = p.parse_args(argv[1:])

    target = open(a.target, "rb").read()
    # VA -> file offset, so a function named in the inventory can be pulled out of
    # the shipped binary and masked at the same relative offsets as the object.
    tgt = Elf(a.target)
    segs = []
    e_phoff, = struct.unpack_from("<I", target, 0x1C)
    phentsize, phnum = struct.unpack_from("<HH", target, 0x2A)
    for i in range(phnum):
        base = e_phoff + i * phentsize
        ptype, poff, pvaddr, _pa, pfilesz = struct.unpack_from("<IIIII", target, base)
        if ptype == 1:
            segs.append((pvaddr, poff, pfilesz))
    def to_off(va):
        for v, o, sz in segs:
            if v <= va < v + sz:
                return o + (va - v)
        return None
    # Inverting address->name collapses duplicates, and duplicates are guaranteed:
    # the Itanium ABI emits C1/C2 constructor and D0/D1 destructor pairs that
    # demangle to the SAME display string at different addresses. Keep every
    # candidate and prefer the mangled spelling, which is unique and is what the
    # object symbols actually carry -- no demangling needed on that path.
    raw_names = {}
    if a.funcmeta:
        for addr, meta in json.load(open(a.funcmeta)).items():
            raw = meta.get("raw_name")
            if raw:
                raw_names.setdefault(raw, int(addr, 16))
    display = {}
    for addr, name in json.load(open(a.names)).items():
        display.setdefault(name, []).append(int(addr, 16))
    ambiguous = {n: v for n, v in display.items() if len(v) > 1}
    names = {n: v[0] for n, v in display.items()}
    sizes = {int(k, 16): v for k, v in json.load(open(a.sizes)).items()}
    total_target_bytes = sum(sizes.values())

    exact, partial, unmatched = [], [], []
    for obj in sorted(glob.glob(os.path.join(a.objects, "*.o"))):
        try:
            elf = Elf(obj)
        except ValueError:
            continue
        text = elf.section(".text")
        holes = elf.text_relocations()
        for name, off, size in elf.functions():
            if off + size > len(text):
                continue
            code = masked(text[off:off + size], off, holes)
            # Mangled first: unique, and it is the object symbol verbatim.
            addr = raw_names.get(name)
            key = name
            if addr is None:
                key = demangle_simple(name) or name
                addr = names.get(key)
            record = {"object": os.path.basename(obj), "symbol": name,
                      "name": key, "size": size}
            if addr is not None:
                tsize = sizes.get(addr, 0)
                record["targetAddr"] = f"{addr:08x}"
                record["targetSize"] = tsize
                toff = to_off(addr)
                hit = False
                if toff is not None and tsize:
                    tbytes = target[toff:toff + size]
                    if len(tbytes) == size:
                        # Mask the SAME relative offsets on both sides: the object
                        # holds zeros/addends where the binary holds resolved
                        # addresses, so only the non-relocated bytes are comparable.
                        rel = {i - off for i in holes if off <= i < off + size}
                        tm = masked(tbytes, 0, rel)
                        cm = masked(code, 0, rel)
                        hit = tm == cm
                        # Masking is what makes this comparison possible, but it
                        # also destroys evidence: two DIFFERENT functions can be
                        # identical outside their relocated operands. Real case
                        # in this corpus -- deg2rad at 0x8071480 and a sibling at
                        # 0x8072ef0 differ in exactly ONE byte, the displacement
                        # of the constant they load, and that byte is masked.
                        # They compute different things. So report how much of
                        # the match actually rested on unmasked bytes.
                        record["maskedBytes"] = len(rel)
                        record["evidenceBytes"] = size - len(rel)
                        if hit and (size - len(rel)) < a.min_evidence:
                            record["weak"] = True
                        if not hit:
                            same = sum(1 for x, y in zip(tm, cm) if x == y)
                            record["byteAgreement"] = round(same / size, 3)
                (exact if hit else partial).append(record)
            else:
                wins = tries = 0
                for i in range(0, max(0, len(code) - a.window), 8):
                    w = code[i:i + a.window]
                    if w.count(0) > a.window // 2:
                        continue
                    tries += 1
                    if w in target:
                        wins += 1
                record["overlap"] = round(wins / tries, 3) if tries else None
                unmatched.append(record)

    exact_bytes = sum(r["size"] for r in exact)
    named_bytes = exact_bytes + sum(r["size"] for r in partial)
    summary = {
        "targetFunctions": len(sizes),
        "targetBytes": total_target_bytes,
        "compiledFunctions": len(exact) + len(partial) + len(unmatched),
        "nameMatched": len(exact) + len(partial),
        "exactMatches": len(exact),
        "exactBytes": exact_bytes,
        "pctTargetBytes": round(100 * exact_bytes / total_target_bytes, 2)
                          if total_target_bytes else 0,
        "pctOfNamedBytes": round(100 * exact_bytes / named_bytes, 1) if named_bytes else 0,
    }
    if a.json:
        print(json.dumps({"summary": summary, "exact": exact[:200]}, indent=2))
        return 0
    print(f"target inventory      {summary['targetFunctions']} functions, "
          f"{summary['targetBytes']} bytes")
    if ambiguous:
        shared = sum(len(v) for v in ambiguous.values())
        print(f"  NOTE {len(ambiguous)} display names cover {shared} addresses "
              f"(C1/C2, D0/D1 pairs)"
              + ("; matched by mangled symbol" if raw_names
                 else " -- pass --funcmeta to disambiguate"))
    print(f"compiled functions    {summary['compiledFunctions']}")
    print(f"  name-matched        {summary['nameMatched']}")
    print(f"  EXACT (masked)      {summary['exactMatches']}  "
          f"({summary['exactBytes']} bytes)")
    print(f"  = {summary['pctTargetBytes']}% of target bytes, "
          f"{summary['pctOfNamedBytes']}% of name-matched bytes")
    weak = [r for r in exact if r.get("weak")]
    if weak:
        print(f"  WEAK: {len(weak)} exact match(es) rest on <{a.min_evidence} "
              f"unmasked bytes -- verify behaviourally, not by bytes")
        for r in weak[:5]:
            print(f"    {r['evidenceBytes']:>3}B evidence / {r['size']:>3}B  {r['name'][:44]}")
    strong = [r for r in unmatched if (r.get("overlap") or 0) >= 0.5]
    print(f"  unnamed w/ >=50% window overlap: {len(strong)}")
    for r in sorted(exact, key=lambda r: -r["size"])[:12]:
        print(f"    EXACT {r['size']:>6}B  {r['name'][:44]}   [{r['object']}]")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

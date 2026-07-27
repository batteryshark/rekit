#!/usr/bin/env python3
"""Check inferred binary names against the vocabulary of real source trees.

A name recovered by analogy is a hypothesis. If the same `Class::Method` appears
in a source tree from the same codebase, that hypothesis has independent support;
if the class exists but the method never does, the name is suspect; if the class
appears nowhere, it was probably imported from a different era of the codebase.

Absence is weaker evidence than presence: a 2004 binary may contain classes that
were deleted before the 2013 source snapshot, and a non-polymorphic helper may
never appear in a header at all. Treat "unsupported" as "unverified", not "wrong".

    source_vocab.py --src DIR [--src DIR ...] --names names.json

Source files are read as latin-1: these trees carry EUC-KR comments, which make
grep classify them as binary and silently skip them.
"""

from __future__ import annotations

import argparse
import collections
import json
import os
import re
import sys

# `Class::Method(` in a definition or call, and `~Class` destructors.
QUALIFIED = re.compile(r"\b([A-Z]\w{2,40})::(~?\w{1,60})\s*\(")
CLASS_DECL = re.compile(r"\bclass\s+([A-Z]\w{2,40})\b")
SOURCE_EXT = (".cpp", ".c", ".h", ".hpp", ".inl", ".cc", ".cxx")


def scan_tree(root: str) -> tuple[dict, set]:
    methods: dict = collections.defaultdict(set)
    classes: set = set()
    for base, _dirs, files in os.walk(root):
        for name in files:
            if not name.lower().endswith(SOURCE_EXT):
                continue
            path = os.path.join(base, name)
            try:
                with open(path, "rb") as handle:
                    text = handle.read().decode("latin-1")
            except OSError:
                continue
            for match in QUALIFIED.finditer(text):
                methods[match.group(1)].add(match.group(2))
            for match in CLASS_DECL.finditer(text):
                classes.add(match.group(1))
    return methods, classes


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="source-vocab")
    parser.add_argument("--src", action="append", required=True)
    parser.add_argument("--names", required=True)
    parser.add_argument("--rtti-classes",
                        help="binary to read RTTI class names from; a class the "
                             "binary itself declares needs no source support")
    parser.add_argument("--out")
    args = parser.parse_args(argv[1:])

    trees = {}
    for root in args.src:
        methods, classes = scan_tree(root)
        trees[os.path.basename(root.rstrip("/"))] = (methods, classes)
        print(f"{os.path.basename(root.rstrip('/')):<26} "
              f"classes {len(classes):>4}  qualified methods "
              f"{sum(len(v) for v in methods.values()):>5}")

    rtti = set()
    if args.rtti_classes:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from rtti_vtables import Binary, find_typeinfos, find_vtables
        binary = Binary(args.rtti_classes)
        rtti = {t["class"] for t in find_vtables(binary, find_typeinfos(binary))}
        print(f"{'binary RTTI':<26} classes {len(rtti):>4}")

    names = json.load(open(args.names))
    verdicts = collections.Counter()
    detail = []
    for addr, name in sorted(names.items()):
        if "::" not in name or name.startswith(("_Z", ".")):
            continue
        cls, _, method = name.partition("::")
        method = method.split("(")[0]
        supporting = [t for t, (m, _c) in trees.items() if method in m.get(cls, ())]
        class_only = [t for t, (m, c) in trees.items()
                      if cls in c or cls in m]
        if cls in rtti:
            # The binary declares this class in its own RTTI; the name's class is
            # not in question whatever the source trees happen to contain.
            verdict = "class from binary RTTI"
        elif supporting:
            verdict = "method+class in source"
        elif class_only:
            verdict = "class known, method not found"
        else:
            verdict = "class unknown in any source"
        verdicts[verdict] += 1
        detail.append({"address": addr, "name": name, "verdict": verdict,
                       "supporting": supporting, "classSeenIn": class_only})

    print(f"\nchecked {len(detail)} scoped names")
    for verdict, count in verdicts.most_common():
        print(f"  {verdict:<32} {count:>4}")
    if args.out:
        json.dump(detail, open(args.out, "w"), indent=2)
        print(f"\nwrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

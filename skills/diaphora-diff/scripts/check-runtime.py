#!/usr/bin/env python3
"""Prerequisite check for diaphora-diff: is the pinned Diaphora runtime vendored?

Prints the pinned version on success so `rekit doctor` can show it. IDA is NOT
checked here — it is needed only by the `export` operation, and `diff`/`report`
remain fully usable without it.
"""

from __future__ import annotations

import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DIAPHORA = os.path.join(SCRIPT_DIR, "diaphora")
SITE = os.path.join(SCRIPT_DIR, "site")


def main() -> int:
    entry = os.path.join(DIAPHORA, "diaphora.py")
    if not os.path.isfile(entry):
        print("Diaphora not vendored (missing scripts/diaphora/diaphora.py)",
              file=sys.stderr)
        return 1
    if not os.path.isdir(SITE):
        print("Diaphora dependencies not vendored (missing scripts/site)",
              file=sys.stderr)
        return 1
    pin = os.path.join(DIAPHORA, ".rekit-pin")
    version = "unknown"
    if os.path.isfile(pin):
        with open(pin, encoding="utf-8") as handle:
            version = handle.read().split()[0]
    print(f"diaphora {version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

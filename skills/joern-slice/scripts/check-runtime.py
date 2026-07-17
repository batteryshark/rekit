#!/usr/bin/env python3
from __future__ import annotations

from runtime import RuntimeUnavailable, verify_runtime


def main() -> int:
    try:
        ref, identity = verify_runtime()
    except RuntimeUnavailable as exc:
        print(f"joern-slice runtime unavailable: {exc}")
        return 1
    print(f"joern-slice runtime ready: {identity} ({ref})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

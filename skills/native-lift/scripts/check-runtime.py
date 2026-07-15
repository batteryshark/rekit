#!/usr/bin/env python3
from __future__ import annotations

from runtime import RuntimeUnavailable, verify_runtime


def main() -> int:
    try:
        ref, version = verify_runtime()
    except RuntimeUnavailable as exc:
        print(f"native-lift runtime unavailable: {exc}")
        return 1
    print(f"native-lift runtime ready: {version} ({ref})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

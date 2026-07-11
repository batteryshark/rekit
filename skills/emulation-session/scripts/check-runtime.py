#!/usr/bin/env python3
"""Verify the vendored emulation runtime can import under this interpreter."""

from __future__ import annotations

import sys
from pathlib import Path

SITE = Path(__file__).resolve().parent / "site"
if not SITE.is_dir():
    raise SystemExit("scripts/site is missing; run `bin/rekit install emulation-session`")
sys.path.insert(0, str(SITE))

try:
    import capstone
    import gevent
    import keystone
    import qiling
    import unicorn
    import qiling.arch.x86
    import qiling.os.linux.linux
except Exception as exc:
    raise SystemExit(f"emulation runtime import failed: {type(exc).__name__}: {exc}") from None

print(
    "runtime ready: "
    f"unicorn={unicorn.__version__} capstone={capstone.__version__} "
    f"keystone={keystone.__version__} gevent={gevent.__version__} "
    f"qiling={getattr(qiling, '__version__', 'unknown')}"
)

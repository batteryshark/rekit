#!/usr/bin/env bash
# Vendor Qiling into runtime/site. Heavier than unicorn (pulls capstone/keystone/pefile/
# gevent/…) but pure-python glue over native wheels, so --target vendoring holds.
# Runtime prereq: python3 + a BYO OS rootfs at --rootfs. Build-time only (needs uv +
# network). Re-run to refresh.
set -euo pipefail
SKILL_DIR="$(cd "$(dirname "$0")/.." && pwd)"
RT="$SKILL_DIR/runtime"
rm -rf "$RT/site"
echo "vendoring qiling into runtime/site (this pulls a few native deps)..."
uv pip install --target "$RT/site" -r "$RT/requirements.txt" -q
echo "done: runtime/site ($(du -sh "$RT/site" | cut -f1))"
echo "note: you still need a rootfs — see github.com/qilingframework/rootfs"

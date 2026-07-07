#!/usr/bin/env bash
# Vendor pefile into runtime/site (offline, portable). Pure-Python, no native addon,
# so the `uv pip install --target` tree works on any OS/arch. Runtime prereq: python3.
# Build-time only (needs uv + network). Re-run to refresh.
set -euo pipefail
SKILL_DIR="$(cd "$(dirname "$0")/.." && pwd)"
RT="$SKILL_DIR/runtime"
rm -rf "$RT/site"
echo "vendoring pefile into runtime/site..."
uv pip install --target "$RT/site" -r "$RT/requirements.txt" -q
echo "done: runtime/site ($(du -sh "$RT/site" | cut -f1))"

#!/usr/bin/env bash
# Vendor decompyle3 into scripts/site (offline, self-contained, portable).
#
# decompyle3 (+ xdis, spark-parser, six, click) is pure Python, so a
# `uv pip install --target` tree works on any OS/arch — no native addon (contrast
# js-deobfuscate, which needs a native isolated-vm). Runtime prereq: python3.
#
# Build-time only (needs uv + network). Re-run to refresh. Commit scripts/site if
# you want the skill fully offline on clone (it's small + pure-python).
set -euo pipefail

SKILL_DIR="$(cd "$(dirname "$0")/.." && pwd)"
RT="$SKILL_DIR/scripts"

rm -rf "$RT/site"
echo "vendoring decompyle3 into scripts/site (pure-python)..."
uv pip install --target "$RT/site" -r "$RT/requirements.txt" -q

VER="$(python3 -c "import sys; sys.path.insert(0,'$RT/site'); import decompyle3.version as v; print(getattr(v,'__version__', getattr(v,'version','?')))" 2>/dev/null || echo '?')"
echo "decompyle3 $VER"
echo "done: scripts/site ($(du -sh "$RT/site" | cut -f1))"

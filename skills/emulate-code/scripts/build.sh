#!/usr/bin/env bash
# Vendor unicorn into scripts/site. Native CPU emulator (ships wheels for common
# platforms; the vendored tree is platform-specific like js-deobfuscate's addon).
# Runtime prereq: python3. Build-time only (needs uv + network). Re-run to refresh.
set -euo pipefail
SKILL_DIR="$(cd "$(dirname "$0")/.." && pwd)"
RT="$SKILL_DIR/scripts"
rm -rf "$RT/site"
echo "vendoring unicorn into scripts/site..."
uv pip install --target "$RT/site" -r "$RT/requirements.txt" -q
echo "done: scripts/site ($(du -sh "$RT/site" | cut -f1))"

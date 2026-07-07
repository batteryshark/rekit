#!/usr/bin/env bash
# Vendor unicorn into runtime/site. Native CPU emulator (ships wheels for common
# platforms; the vendored tree is platform-specific like js-deobfuscate's addon).
# Runtime prereq: python3. Build-time only (needs uv + network). Re-run to refresh.
set -euo pipefail
SKILL_DIR="$(cd "$(dirname "$0")/.." && pwd)"
RT="$SKILL_DIR/runtime"
rm -rf "$RT/site"
echo "vendoring unicorn into runtime/site..."
uv pip install --target "$RT/site" -r "$RT/requirements.txt" -q
echo "done: runtime/site ($(du -sh "$RT/site" | cut -f1))"

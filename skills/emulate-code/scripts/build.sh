#!/usr/bin/env bash
# Vendor unicorn into scripts/site. Native CPU emulator (ships wheels for common
# platforms; the vendored tree is platform-specific like js-deobfuscate's addon).
# Runtime prereq: python3. Build-time only (needs uv + network). Re-run to refresh.
set -euo pipefail
SKILL_DIR="$(cd "$(dirname "$0")/.." && pwd)"
RT="$SKILL_DIR/scripts"
rm -rf "$RT/site"
rm -rf "$RT/site-x86_64"
echo "vendoring unicorn into scripts/site..."
uv pip install --target "$RT/site" -r "$RT/requirements.txt" -q
if [[ "$(uname -s)" == "Darwin" && "$(uname -m)" == "arm64" ]]; then
  if arch -x86_64 /usr/bin/python3 -c 'import platform; assert platform.machine() == "x86_64"' 2>/dev/null; then
    echo "vendoring Unicorn Rosetta fallback into scripts/site-x86_64..."
    uv pip install --target "$RT/site-x86_64" \
      --python-platform x86_64-apple-darwin --python-version 3.9 \
      -r "$RT/requirements.txt" -q
  else
    echo "note: Rosetta is unavailable; native Unicorn capability must pass doctor"
  fi
fi
echo "done: scripts/site ($(du -sh "$RT/site" | cut -f1))"

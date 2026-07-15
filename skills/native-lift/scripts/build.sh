#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE_REF="$(PYTHONPATH="$SCRIPT_DIR" python3 -c 'from runtime import image_ref; print(image_ref())')"

docker pull "$IMAGE_REF"
PYTHONPATH="$SCRIPT_DIR" python3 "$SCRIPT_DIR/check-runtime.py"

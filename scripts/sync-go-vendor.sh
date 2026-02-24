#!/usr/bin/env bash
set -euo pipefail

# Refresh Go module vendor dependencies.
# Seccomp assets live in third_party/ and are unaffected by go mod vendor.

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
ROOT_DIR="$( cd "$SCRIPT_DIR/.." && pwd )"

(
  cd "$ROOT_DIR"
  go mod vendor
)

echo "Vendor sync complete."

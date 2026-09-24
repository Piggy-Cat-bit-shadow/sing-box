#!/usr/bin/env bash
# Shared helpers for the Jiejie CI scripts.
set -euo pipefail

# sha256_of prints the SHA-256 of a file, portable across Linux and macOS.
sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}
export -f sha256_of 2>/dev/null || true

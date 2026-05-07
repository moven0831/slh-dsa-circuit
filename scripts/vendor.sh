#!/usr/bin/env bash
# Vendor pinned dependencies that are not on npm.
# circomlib comes from yarn (npm package); only hash-circuits and fips205 are vendored.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VENDOR="$ROOT/vendor"
mkdir -p "$VENDOR"

clone_pinned() {
  local url="$1"
  local sha="$2"
  local dest="$3"
  if [ -d "$dest/.git" ]; then
    echo "[vendor] $dest already cloned; checking SHA..."
    pushd "$dest" >/dev/null
    local current
    current=$(git rev-parse HEAD)
    if [ "$current" = "$sha" ]; then
      echo "[vendor] $dest at $sha (ok)"
      popd >/dev/null
      return 0
    fi
    echo "[vendor] $dest at $current, fetching $sha..."
    git fetch --depth 50 origin "$sha" || git fetch origin
    git checkout "$sha"
    popd >/dev/null
    return 0
  fi
  echo "[vendor] cloning $url to $dest @ $sha"
  git clone --filter=blob:none "$url" "$dest"
  pushd "$dest" >/dev/null
  git checkout "$sha"
  popd >/dev/null
}

# bkomuves/hash-circuits — sha512 + keccak/SHAKE for our SHAKE-256 wrapper
clone_pinned \
  https://github.com/bkomuves/hash-circuits.git \
  4ef64777cc9b78ba987fbace27e0be7348670296 \
  "$VENDOR/hash-circuits"

# integritychain/fips205 — Rust SLH-DSA reference + ACVP KATs
clone_pinned \
  https://github.com/integritychain/fips205.git \
  30bac08580aa61f653e5436d1bbacb5ffac446c4 \
  "$VENDOR/fips205"

echo "[vendor] done"

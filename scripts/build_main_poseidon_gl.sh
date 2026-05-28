#!/usr/bin/env bash
# Compile the monolithic Goldilocks SLH-DSA-128s verifier circuit.
#
# Bypasses circomkit because `circomkit.json` hardcodes `prime: secq256r1`;
# `--prime goldilocks` must be invoked directly (same convention as every
# other circuit under `circuits/poseidon_gl/`).
#
# Output: build/main_poseidon_gl/{main_poseidon_gl.r1cs,.wasm,.sym}
# Constraint count is reported via `snarkjs r1cs info` at the end.
#
# Expected size (per the 0.85× HT-layer bloat factor measured in
# results/hash_based_analysis.md): ~3.4M R1CS, comparable to the secq256r1
# `main_poseidon` baseline of 3,992,159 R1CS. Should compile in <2 min on a
# 24 GB M3 (per CLAUDE.md §"OOM ceiling" — main_poseidon compiles in <1 min,
# Goldilocks variant should not be heavier).

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/circuits/poseidon_gl/main_poseidon_gl.circom"
OUT="$ROOT/build/main_poseidon_gl"
INCLUDE_VENDOR="$ROOT/vendor/hash-circuits/circuits"
INCLUDE_NPM="$ROOT/node_modules"

mkdir -p "$OUT"

if [ ! -d "$INCLUDE_VENDOR" ] || [ ! -d "$INCLUDE_NPM" ]; then
  echo "ERROR: vendor and node_modules must be set up before compiling."
  echo "       Run: corepack enable && yarn install && bash scripts/vendor.sh"
  exit 1
fi

echo "=== circom --prime goldilocks --O2 main_poseidon_gl ==="
echo "    src: $SRC"
echo "    out: $OUT"
echo

START=$(date +%s)

circom "$SRC" \
  --prime goldilocks \
  --r1cs --wasm --sym \
  --O2 \
  -l "$INCLUDE_NPM" \
  -l "$ROOT/circuits" \
  -l "$INCLUDE_VENDOR" \
  -o "$OUT"

END=$(date +%s)
echo
echo "=== compile finished in $((END - START))s ==="
echo

R1CS="$OUT/main_poseidon_gl.r1cs"
if [ -f "$R1CS" ] && command -v npx >/dev/null 2>&1; then
  echo "=== snarkjs r1cs info ==="
  # snarkjs ships with V8's 4 GB default; a ~400 MB r1cs blows past that.
  # 12 GB max-old-space-size handles the full monolithic without OOM.
  NODE_OPTIONS="--max-old-space-size=12288" npx snarkjs r1cs info "$R1CS" || true
fi

echo
echo "Done. Next: feed $R1CS to the slh-dsa-spartan2-gl bench crate."

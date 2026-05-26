#!/usr/bin/env bash
# Compile circuits/poseidon_gl/poseidon_gl_smoke.circom (one PoseidonGlPermute call)
# against the Goldilocks prime, then validate output against all 4 Plonky2 reference
# test vectors. Exits non-zero on R1CS-count drift or any vector mismatch.
#
# Usage: bash scripts/test_poseidon_gl.sh
#
# Expected R1CS: exactly 472 (8 full × 12 lanes × 4 S-box mults + 22 partial × 1 × 4).
# Expected vectors: zeros, range, neg_one, random — all byte-for-byte against
# 0xPolygonZero/plonky2 @ v1.1.0 (see scripts/check_poseidon_gl.py for sources).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="$REPO_ROOT/build/poseidon_gl_smoke"
EXPECTED_R1CS=472

mkdir -p "$BUILD_DIR"

echo "=== Compile circuits/poseidon_gl/poseidon_gl_smoke.circom (prime=goldilocks, --O2) ==="
circom "$REPO_ROOT/circuits/poseidon_gl/poseidon_gl_smoke.circom" \
    --r1cs --wasm --O2 --prime goldilocks \
    -o "$BUILD_DIR" \
    -l "$REPO_ROOT/circuits/poseidon_gl" \
    2>&1 | tee "$BUILD_DIR/compile.log"

ACTUAL_R1CS=$(awk '/non-linear constraints/ {print $NF}' "$BUILD_DIR/compile.log" | tr -d '\r')
if [ "$ACTUAL_R1CS" != "$EXPECTED_R1CS" ]; then
    echo "FAIL: R1CS count = $ACTUAL_R1CS, expected $EXPECTED_R1CS"
    exit 1
fi
echo "PASS: R1CS = $ACTUAL_R1CS (matches expected $EXPECTED_R1CS)"
echo

WASM_DIR="$BUILD_DIR/poseidon_gl_smoke_js"
WASM="$WASM_DIR/poseidon_gl_smoke.wasm"
GEN="$WASM_DIR/generate_witness.js"

ALL_PASS=1
for label in zeros range neg_one random; do
    INPUT_JSON="$BUILD_DIR/input_$label.json"
    WTNS="$BUILD_DIR/wtns_$label.wtns"
    WTNS_JSON="$BUILD_DIR/wtns_$label.json"
    python3 "$REPO_ROOT/scripts/check_poseidon_gl.py" emit "$label" > "$INPUT_JSON"
    node "$GEN" "$WASM" "$INPUT_JSON" "$WTNS" > /dev/null
    npx snarkjs wtns export json "$WTNS" "$WTNS_JSON" > /dev/null
    if ! python3 "$REPO_ROOT/scripts/check_poseidon_gl.py" check "$label" "$WTNS_JSON"; then
        ALL_PASS=0
    fi
done

if [ "$ALL_PASS" = "1" ]; then
    echo "RESULT: all checks passed."
else
    echo "RESULT: one or more vectors mismatched."
    exit 1
fi

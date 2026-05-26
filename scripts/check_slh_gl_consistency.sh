#!/usr/bin/env bash
# Witness-consistency check for circuits/poseidon_gl/bench/bench_slh_f_gl.circom.
#
# Strategy: SlhF on all-zero inputs reduces to PoseidonGl(12) on [0; 12]
# (because PackBytes16To2Fe of [0;16] = (0, 0), and all ADRS sub-fields and the
# tag are 0). PoseidonGl(12) is the one-shot construction state[0..12] = inputs;
# state[12..] = 0; PoseidonGlPermute. So the result is exactly
# PoseidonGlPermute([0; 12]) — for which we have the Plonky2 reference vector
# (0x3c18a9786cb0b359, 0xc4055e3364a246c3, ..., the same 12-tuple already
# verified for PoseidonGlSmoke by scripts/test_poseidon_gl.sh).
#
# Expected SlhF([0;16], 0,0,0,0,0,0,0, [0;16]) → out[0..16] = LE bytes of
# (out_lo = 0x3c18a9786cb0b359, out_hi = 0xc4055e3364a246c3).
#   LE(0x3c18a9786cb0b359) = 59 b3 b0 6c 78 a9 18 3c
#   LE(0xc4055e3364a246c3) = c3 46 a2 64 33 5e 05 c4
#
# This validates: (a) PackBytes16To2Fe maps all-zero → (0,0), (b) PoseidonGl(12)
# uses the one-shot construction (no rate-8 sponge), (c) UnpackFe2To16Bytes
# emits LE bytes per FE. Catches: pack/unpack order errors, sponge vs one-shot
# confusion, byte-endianness bugs.
#
# Day-2 review (commit 79d5b8a) flagged the lack of a witness-consistency check
# beyond R1CS counts. This script + the existing scripts/test_poseidon_gl.sh
# together cover the most likely silent-bug categories.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="$REPO_ROOT/build/slh_gl_consistency"
SRC="$REPO_ROOT/circuits/poseidon_gl/bench/bench_slh_f_gl.circom"

mkdir -p "$BUILD_DIR"

echo "=== Compile bench_slh_f_gl (Goldilocks, --O2) ==="
circom "$SRC" \
    --r1cs --wasm --O2 --prime goldilocks \
    -o "$BUILD_DIR" \
    -l "$REPO_ROOT/circuits/poseidon_gl" \
    -l "$REPO_ROOT/node_modules" \
    > "$BUILD_DIR/compile.log" 2>&1

# All-zero input.
INPUT="$BUILD_DIR/input.json"
python3 -c "
import json
data = {
    'pk_seed':   ['0'] * 16,
    'layer':     '0',
    'tree_high': '0',
    'tree_low':  '0',
    'type_':     '0',
    'keypair':   '0',
    'chain':     '0',
    'hash':      '0',
    'm':         ['0'] * 16,
}
print(json.dumps(data))
" > "$INPUT"

WC="$BUILD_DIR/bench_slh_f_gl_js"
node "$WC/generate_witness.js" "$WC/bench_slh_f_gl.wasm" "$INPUT" "$BUILD_DIR/witness.wtns" > /dev/null
npx snarkjs wtns export json "$BUILD_DIR/witness.wtns" "$BUILD_DIR/witness.json" > /dev/null

# Expected output (LE bytes of PoseidonGlPermute([0;12])[0..2]).
# 0x3c18a9786cb0b359 → 0x59 0xb3 0xb0 0x6c 0x78 0xa9 0x18 0x3c
# 0xc4055e3364a246c3 → 0xc3 0x46 0xa2 0x64 0x33 0x5e 0x05 0xc4
python3 -c "
import json, sys
expected = [
    0x59, 0xb3, 0xb0, 0x6c, 0x78, 0xa9, 0x18, 0x3c,
    0xc3, 0x46, 0xa2, 0x64, 0x33, 0x5e, 0x05, 0xc4,
]
w = json.load(open('$BUILD_DIR/witness.json'))
# Layout: w[0]=1, w[1..17]=out[0..16] (public outputs, 16 bytes).
all_match = True
for i in range(16):
    actual = int(w[1 + i])
    ok = actual == expected[i]
    if not ok:
        all_match = False
    marker = 'OK ' if ok else 'FAIL'
    print(f'  out[{i:2d}] = 0x{actual:02x}  (expected 0x{expected[i]:02x})  {marker}')
print(f'consistency: {\"PASS\" if all_match else \"FAIL\"}')
sys.exit(0 if all_match else 1)
"

echo
echo "RESULT: SlhF_Gl(all_zeros) produces the expected bytes derived from"
echo "        PoseidonGlPermute([0;12]) — packing/unpacking + one-shot construction OK."

#!/usr/bin/env bash
# Per-primitive validation tests: regenerate inputs from the Rust
# oracle, compile test wrapper circuits, and run circomkit witness.
# Witness gen succeeds iff the circuit's output matches Rust-computed
# FIPS 205 reference. Also runs negative tests where expected_out is
# tampered — witness gen should FAIL for those.

set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

TESTS=(
    test_sha2_F  test_sha2_H  test_sha2_Tk  test_sha2_Tlen  test_sha2_HMsg
    test_shake_F test_shake_H test_shake_Tk test_shake_Tlen test_shake_HMsg
)

# Generate fresh inputs.
echo "=== Generating Rust expected outputs ==="
cargo run --release --manifest-path reference/Cargo.toml -- all all 2>&1 | grep -E "expected_out|^Wrote"

# Mirror inputs to circomkit's expected layout.
for c in "${TESTS[@]}"; do
    mkdir -p inputs/$c
    cp -f kat/inputs/$c.json inputs/$c/default.json
done

PASS=0
FAIL=0

echo
echo "=== Positive tests (witness gen should succeed) ==="
for c in "${TESTS[@]}"; do
    if [ ! -f build/$c/$c.r1cs ]; then
        npx circomkit compile $c >/tmp/compile_$c.log 2>&1
    fi
    if npx circomkit witness $c default >/tmp/w_$c.log 2>&1; then
        echo "[$c] ✓ output matches Rust expected"
        PASS=$((PASS + 1))
    else
        echo "[$c] ✗ witness gen failed:"
        tail -3 /tmp/w_$c.log
        FAIL=$((FAIL + 1))
    fi
done

echo
echo "=== Negative tests (tampered expected_out should fail witness gen) ==="
for c in "${TESTS[@]}"; do
    # Make a tampered copy: flip one byte in expected_out.
    python3 -c "
import json
with open('inputs/$c/default.json') as f: d = json.load(f)
# expected_out is a list of decimal strings; flip the LSB of the first byte
v = int(d['expected_out'][0])
d['expected_out'][0] = str(v ^ 1)
with open('inputs/$c/tampered.json', 'w') as f: json.dump(d, f)
"
    if npx circomkit witness $c tampered >/tmp/wn_$c.log 2>&1; then
        echo "[$c] ✗ witness gen ACCEPTED tampered output (soundness bug!)"
        FAIL=$((FAIL + 1))
    else
        echo "[$c] ✓ tampered output rejected"
        PASS=$((PASS + 1))
    fi
done

echo
echo "=== Summary: $PASS passed, $FAIL failed ==="
[ $FAIL -eq 0 ] && exit 0 || exit 1

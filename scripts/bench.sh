#!/usr/bin/env bash
# Compile every named circuit in circuits.json and capture
# `circomkit info` (= snarkjs r1cs info) into results/raw_bench.txt.
#
# Skips circuits whose compile fails (e.g. OOM); records "FAILED" in
# the output line for those.

set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

OUT="$ROOT/results/raw_bench.txt"
mkdir -p "$(dirname "$OUT")"

# List all named circuits from circuits.json (top-level keys).
CIRCUITS="$(python3 -c '
import json, sys
with open("circuits.json") as f:
    d = json.load(f)
for name in d.keys():
    print(name)
')"

: > "$OUT"
echo "# raw_bench.txt — generated $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$OUT"
echo "# Format: <circuit> <status> nConstraints=<N> nWires=<W> nPubIn=<P> nPrvIn=<Q> .r1cs_size=<bytes>" >> "$OUT"

for c in $CIRCUITS; do
    echo "Benching $c ..."
    if [ ! -f "build/$c/$c.r1cs" ]; then
        # Compile if missing.
        if ! npx circomkit compile "$c" >/tmp/bench_compile_$c.log 2>&1; then
            echo "$c FAILED status=compile_error log=/tmp/bench_compile_$c.log" >> "$OUT"
            continue
        fi
    fi
    info_out=$(npx circomkit info "$c" 2>&1)
    nConstraints=$(echo "$info_out" | grep -E '^Number of Constraints' | awk '{print $4}')
    nWires=$(echo "$info_out" | grep -E '^Number of Wires' | awk '{print $4}')
    nPubIn=$(echo "$info_out" | grep -E '^Number of Public Inputs' | awk '{print $5}')
    nPrvIn=$(echo "$info_out" | grep -E '^Number of Private Inputs' | awk '{print $5}')
    r1cs_size=$(stat -f%z "build/$c/$c.r1cs" 2>/dev/null || stat -c%s "build/$c/$c.r1cs")
    echo "$c OK nConstraints=$nConstraints nWires=$nWires nPubIn=$nPubIn nPrvIn=$nPrvIn r1cs_size=$r1cs_size" >> "$OUT"
done

echo "Done. Output: $OUT"
cat "$OUT"

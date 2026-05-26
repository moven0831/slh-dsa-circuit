#!/usr/bin/env bash
# Compile every circuit under circuits/poseidon_gl/bench/ against --prime goldilocks
# and report R1CS counts. Output suitable for inclusion in
# research/folding/poseidon_gl_audit.md.
#
# Usage: bash scripts/bench_poseidon_gl.sh [bench_name ...]
# With no args, benches everything in circuits/poseidon_gl/bench/.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BENCH_DIR="$REPO_ROOT/circuits/poseidon_gl/bench"
BUILD_ROOT="$REPO_ROOT/build/poseidon_gl_bench"

mkdir -p "$BUILD_ROOT"

if [ $# -gt 0 ]; then
    BENCHES=("$@")
else
    BENCHES=()
    for f in "$BENCH_DIR"/*.circom; do
        BENCHES+=("$(basename "$f" .circom)")
    done
fi

printf "%-35s %-12s %-8s %-8s\n" "circuit" "non-linear" "wires" "labels"
printf "%-35s %-12s %-8s %-8s\n" "-------" "----------" "-----" "------"

for b in "${BENCHES[@]}"; do
    SRC="$BENCH_DIR/$b.circom"
    OUT="$BUILD_ROOT/$b"
    mkdir -p "$OUT"
    circom "$SRC" --r1cs --O2 --prime goldilocks \
        -o "$OUT" \
        -l "$REPO_ROOT/circuits/poseidon_gl" \
        -l "$REPO_ROOT/node_modules" \
        > "$OUT/compile.log" 2>&1
    NL=$(awk '/non-linear constraints/ {print $NF; exit}' "$OUT/compile.log" | tr -d '\r')
    WIRES=$(awk '/^wires/ {print $NF; exit}' "$OUT/compile.log" | tr -d '\r')
    LABELS=$(awk '/^labels/ {print $NF; exit}' "$OUT/compile.log" | tr -d '\r')
    printf "%-35s %-12s %-8s %-8s\n" "$b" "$NL" "$WIRES" "$LABELS"
done

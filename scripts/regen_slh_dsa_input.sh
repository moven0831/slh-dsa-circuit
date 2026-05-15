#!/usr/bin/env bash
# Regenerate the Poseidon-SLH-DSA-128s witness fixture for the
# wallet-unit-poc/slh-dsa-spartan2 benchmark in the zkID fork.
#
# Output goes to ../slh-dsa-128s-poseidon-bench/wallet-unit-poc/circom/inputs/slh_dsa/1k/default.json
# (relative to this repo's root).
#
# The signer is non-standard (Poseidon over secq256r1 with BN254-tuned
# constants — for benchmarking only, see circuits/poseidon/README.md).

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FORK_INPUTS="${FORK_INPUTS:-$ROOT/../slh-dsa-128s-poseidon-bench/wallet-unit-poc/circom/inputs/slh_dsa/1k}"

mkdir -p "$FORK_INPUTS"
echo "Writing witness to $FORK_INPUTS/default.json"
node "$ROOT/scripts/poseidon_sign.mjs" "$FORK_INPUTS/default.json"

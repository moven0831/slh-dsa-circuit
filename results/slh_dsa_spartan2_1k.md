# SLH-DSA-128s (Poseidon, 1 KB msg) — Spartan2 benchmark

Captured against [moven0831/slh-dsa-128s-poseidon-bench@feat/slh-dsa-spartan2-bench](https://github.com/moven0831/slh-dsa-128s-poseidon-bench/tree/feat/slh-dsa-spartan2-bench), `wallet-unit-poc/slh-dsa-spartan2/`.

- **Host**: MacBook M3, 24 GB unified memory, macOS Darwin 24.6.0
- **Backend**: Spartan2 (0xVikasRushi `openac-sdk` fork) — `T256HyraxEngine` (Hyrax-PC over secq256r1)
- **Circuit**: `circuits/slh_dsa/main_poseidon.circom`
  - R1CS: **3,992,159 constraints**, 3,861,768 wires, 1,056 public inputs (`pk[32]`, `msg[1024]`), 7,856 private inputs (`r[16]`, `sig_fors[14][13][16]`, `sig_ht[7][44][16]`), 1 public output (`valid`)
  - Field: `secq256r1`
  - R1CS file: 2.28 GB; C++ witness generator: 30 MB; `.dat` constants: 32 MB

## Setup phase (no satisfying witness required)

| Metric              | Value      |
|---------------------|-----------:|
| Setup time          | **23,143 ms** (≈ 23.1 s) |
| Proving key         | 2.37 GB    |
| Verifying key       | 2.37 GB    |
| Peak RSS            | 10.45 GB   |
| Peak memory footprint | 10.46 GB |
| User CPU            | 23.98 s    |
| System CPU          | 4.24 s     |
| Wall time           | 33.70 s    |

Notes:
- VK size matching PK size is an artifact of this Spartan2 fork's `VerifierKey` serializing the full preprocessed R1CS shape (`S`), not the circuit. The on-the-wire verifier proof footprint is much smaller (see Prove section, once captured).
- The 24 GB host had ~12 GB free at the time; setup peaked at 10.45 GB without macOS evicting the process.

## Prove / Verify phase

**Status**: blocked on Poseidon-side witness fixture.

The Poseidon-SLH-DSA-128s scheme is non-standard (circomlib BN254 Poseidon constants reused over secq256r1) and has no existing Rust or JS signer. Producing a valid witness for `prove` requires implementing FORS + WOTS + XMSS + HT signing using Poseidon as the hash family — roughly 400-600 lines of Rust including the BN254-constants-over-secq256r1 Poseidon permutation.

The `slh-dsa-spartan2` crate's `prove` and `verify` commands are wired and ready; they fail at witness generation because `inputs/slh_dsa/1k/default.json` does not yet contain a valid (pk, msg, r, sig_fors, sig_ht) tuple.

## Reproducing

```sh
git clone https://github.com/moven0831/slh-dsa-128s-poseidon-bench.git
cd slh-dsa-128s-poseidon-bench && git checkout feat/slh-dsa-spartan2-bench

cd wallet-unit-poc/circom
corepack enable && yarn install
yarn compile:slh_dsa_1k

cd ../slh-dsa-spartan2
cargo build --release
/usr/bin/time -l ./target/release/slh-dsa-spartan2 setup
```

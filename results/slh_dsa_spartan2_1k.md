# SLH-DSA-128s (Poseidon, 1 KB msg) — Spartan2 / OpenAC benchmark

End-to-end benchmark of the SLH-DSA-128s Poseidon-hash signature verifier on
the OpenAC Spartan2 stack, captured at
[moven0831/slh-dsa-128s-poseidon-bench](https://github.com/moven0831/slh-dsa-128s-poseidon-bench),
crate `wallet-unit-poc/slh-dsa-spartan2/`.

## Setup

- **Host**: MacBook M3, 24 GB unified memory, macOS Darwin 24.6.0
- **Backend**: Spartan2 (0xVikasRushi `openac-sdk` fork) — `T256HyraxEngine`
  (Hyrax-PC over secq256r1 = secp256r1's base field per circom 2.2.3)
- **Circuit**: `wallet-unit-poc/circom/circuits/slh_dsa/main_poseidon.circom`
  - R1CS: **3,992,159 constraints**, 3,861,768 wires, 1,056 public inputs
    (`pk[32]`, `msg[1024]`), 7,856 private inputs (`r[16]`,
    `sig_fors[14][13][16]`, `sig_ht[7][44][16]`), 1 public output (`valid`)
  - Field: `secq256r1`
  - Build artifacts: `.r1cs` 2.28 GB; `.cpp` witness gen 30 MB; `.dat` 32 MB
- **Witness fixture**: produced by `scripts/poseidon_sign.mjs` in
  ~22 min of JS BigInt arithmetic (270 K Poseidon perm for keygen, 114 K
  for FORS, 1.88 M for HT-layer XMSS rebuilds)

## Results

### Timing

| Phase                       |        Time | Peak RSS |
|-----------------------------|------------:|---------:|
| Setup (R1CSSNARK::setup)    |  23,143 ms  | 10.45 GB |
| Witnesscalc (Circom → witness) |   1,387 ms |        - |
| Load proving key (file → mem)  |   4,281 ms |        - |
| Prep prove                  |       20 ms |        - |
| **Prove**                   | **16,184 ms** |  5.41 GB |
| **Verify**                  |  **9,522 ms** |  3.11 GB |

### Sizes

| Artifact      |    Size |
|---------------|--------:|
| Proving key   | 2.37 GB |
| Verifying key | 2.37 GB |
| Proof         |  208.80 KB |
| `.r1cs`       | 2.28 GB |
| C++ witness gen | 30 MB |
| `.dat`        | 32 MB |

Notes:
- Verifying-key size matches PK because this Spartan2 fork's `VerifierKey`
  serializes the full preprocessed R1CS shape (`S`). The on-wire proof
  is the small artifact (208 KB).
- All measurements taken with `/usr/bin/time -l` on M3/24 GB; peak RSS is
  `maximum resident set size`. Wall times include file I/O.

### Pipeline wall times

| Command                       | Wall time |
|-------------------------------|----------:|
| `slh-dsa-spartan2 setup`      |   33.70 s |
| `slh-dsa-spartan2 prove --input …` |   21.27 s |
| `slh-dsa-spartan2 verify`     |   14.21 s |

## Comparison context

Sibling `ecdsa-spartan2` on the **same backend** reports on M5/24 GB (its README):

|                  | ecdsa-spartan2 jwt_1k | **slh-dsa-spartan2 1k** | Ratio |
|------------------|----------------------:|------------------------:|------:|
| Prove (ms)       |                 1,119 |                  16,184 |  ~14× |
| Verify (ms)      |                   740 |                   9,522 |  ~13× |
| Proving key (MB) |                   257 |                   2,422 |  ~9×  |
| Proof (KB)       |                    76 |                     209 |  ~3×  |

The constant-overhead ratio (~10×) closely tracks the R1CS-size ratio
(SLH-DSA-128s ≈ 4 M constraints vs ecdsa-spartan2 jwt_1k ≈ ~500 K). Some
extra factor comes from the host being M3 vs M5 in the reference numbers.

## Reproducing

```sh
# 1. Clone the fork branch
git clone https://github.com/moven0831/slh-dsa-128s-poseidon-bench.git
cd slh-dsa-128s-poseidon-bench && git checkout feat/slh-dsa-spartan2-bench

# 2. Compile Circom (~1 min, <2 GB RSS)
cd wallet-unit-poc/circom
corepack enable && yarn install
yarn compile:slh_dsa_1k

# 3. Build Spartan2 prover (~15 min cold, ~10s incremental)
cd ../slh-dsa-spartan2
cargo build --release

# 4. Generate witness fixture (~22 min in JS BigInt)
cd /Users/moventsai/Projects/mine/slh-dsa-circuit   # this repo
FORK_INPUTS=../slh-dsa-128s-poseidon-bench/wallet-unit-poc/circom/inputs/slh_dsa/1k \
  bash scripts/regen_slh_dsa_input.sh

# 5. End-to-end
cd ../slh-dsa-128s-poseidon-bench/wallet-unit-poc/slh-dsa-spartan2
./target/release/slh-dsa-spartan2 setup
./target/release/slh-dsa-spartan2 prove --input ../circom/inputs/slh_dsa/1k/default.json
./target/release/slh-dsa-spartan2 verify   # → VERIFY OK
```

## Caveats

- **Poseidon-SLH-DSA is non-standard**: circomlib's BN254-tuned Poseidon
  constants reused over secq256r1. R1CS structure unchanged from BN254;
  benchmark numbers are valid but security analysis does NOT transfer.
  See `circuits/poseidon/README.md` upstream for the full caveat.
- The signer script (`scripts/poseidon_sign.mjs`) is a fixture generator,
  not a production cryptographic signer. It deterministically derives
  keypair/signature material from fixed seeds for reproducibility.
- `circomkit.json` for the fork hardcodes `cWitness: true` so the
  `witnesscalc-adapter` consumer in the Rust crate works.

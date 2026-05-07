# slhdsa-128s-circom

R1CS arithmetization benchmark of the **NIST FIPS 205 SLH-DSA-128s**
signature verifier under three swappable hash gadget configurations,
on the `secq256r1` prime field (matching
[`privacy-ethereum/zkID/wallet-unit-poc/circom/circomkit.json`](https://github.com/privacy-ethereum/zkID/blob/main/wallet-unit-poc/circom/circomkit.json)).

| Family   | Standardization                          | Primitives                          |
|----------|------------------------------------------|-------------------------------------|
| SHA-2    | FIPS 205 §11.2 SLH-DSA-SHA2-128s         | SHA-256 (+ MGF1-SHA-256 for H_msg)  |
| SHAKE    | FIPS 205 §11.1 SLH-DSA-SHAKE-128s        | SHAKE-256                           |
| Poseidon | non-standard, ZK-benchmarking only       | circomlib Poseidon over secq256r1   |

## TLDR

- **Per-call cost ratio**: Poseidon ≪ SHA-2 ≪ SHAKE.
  Picking F (the dominant primitive at 3,675 invocations per verifier):
  Poseidon **968** ≈ 1×, SHA-2 **30,290** ≈ 31×, SHAKE **145,568** ≈ 150×.
- **Full-verifier R1CS** (sum of all primitives × invocations): Poseidon
  **3.99 M** (compiles), SHA-2 **~121.7 M**, SHAKE **~577.5 M**.
- **Midstate optimization** (FIPS 205 §11.2.2 zero-padded prefix block
  compressed once, shared across F/H/T_l calls) halves SHA-2: F goes
  60,778 → 30,290, dropping the SHA-2 main from ~242 M → ~122 M
  (–50 %). Output bits identical to the unoptimized version.
- **Cryptographic correctness**: 20/20 per-primitive tests pass —
  Rust oracle (`reference/`) computes FIPS 205 §11.1/§11.2.2
  reference outputs and circuit `out === expected_out` assertions
  hold. Negative tests (flipped expected) all reject as expected.
- **Hardware limit (†)**: `main_sha2` (~122 M) and `main_shake` (~578 M)
  OOM the `circom v2.2.3` compiler. Tested on a 24 GB M3 MacBook —
  circom reached peak RSS 3.94 GB after ~3 minutes before being
  SIGKILL'd by macOS memory pressure (system swap was 13/14 GB used
  during the test, so ~10 GB was free for circom against an estimated
  12+ GB working-set need). On a less loaded 24 GB system or any
  32 GB+ machine, the compile is expected to succeed. `main_poseidon`
  (4 M) compiles in <1 min, peak RSS <2 GB. The Poseidon integrated
  count vs sum-of-parts is +0.9 % — validates the SHA-2/SHAKE
  projections within ~1 %.
- **What's the user-facing implication?** For ZK-friendly SLH-DSA
  applications the **Poseidon family is ~30× smaller than SHA-2** at
  the cost of being non-standard. For FIPS-compliant applications,
  SHA-2 is recommended over SHAKE (4–5× smaller).

| Family   | F | H | T_k | T_len | H_msg | **Verifier total** | Compile status |
|----------|--:|--:|--:|--:|--:|---:|---|
| **SHA-2** (midstate) | 30,290 | 30,662 | 123,182 | 307,106 | 583,273 | **~121.7 M** | OOM (see note†) |
| **SHAKE** | 145,568 | 145,824 | 440,736 | 737,952 | 1,182,912 | **~577.5 M** | OOM (see note†) |
| **Poseidon** (non-standard) | 968 | 1,102 | 5,989 | 14,428 | 24,844 | **3,992,159** ✓ | <1 min, <2 GB |

The deliverable is **R1CS stats** — per-component constraint counts,
witness sizes, totals — plus 20/20 per-primitive correctness tests.
**No trusted setup, no proof generation, no Solidity verifier.**

See [`results/results.md`](results/results.md) for the full
per-family breakdown, [`results/soundness_audit.md`](results/soundness_audit.md)
for the soundness analysis, and `Dependencies.md` for pinned versions.

## Quickstart

```bash
corepack enable
yarn install
bash scripts/vendor.sh         # clones bkomuves/hash-circuits + integritychain/fips205 at pinned SHAs
yarn bench                     # compiles every circuit in circuits.json + dumps r1cs info to results/raw_bench.txt
yarn parse                     # generates results/results_summary.md
bash scripts/run_tests.sh      # 20 per-primitive correctness tests (Rust oracle ↔ circom)
cat results/results.md         # detailed report with all three per-family tables
```

## Status

- **All 16 per-primitive benches compile cleanly** — F, H, T_k, T_len,
  H_msg for each of {SHA-2, SHAKE, Poseidon}, plus SHA-2 seed-IV and
  one-chain WOTS validation. See `results/results.md`.
- **`main_poseidon`** compiles end-to-end: 3,992,159 constraints in
  ~50 seconds, peak RSS <2 GB. Integration delta from sum-of-parts is
  +0.9% (validates the per-component extrapolation methodology).
- **SHA-2 midstate optimization** applied (FIPS 205 §11.2.2's zero-padded
  `pk_seed||zeros[48]` block compressed once, shared via `Sha256SeedIv`):
  F goes 60,778 → 30,290, H 61,150 → 30,662, etc. SHA-2 main projection
  drops from ~241M to ~121M constraints.
- **`main_sha2`** (~121M) and **`main_shake`** (~578M) **OOM** the
  `circom v2.2.3` compiler under memory pressure (RSS hits ~3.9 GB
  before macOS SIGKILLs). Tested on a 24 GB M3 MacBook with ~13 GB
  swap already committed by other processes, leaving ~10 GB free
  against circom's estimated 12+ GB working set. Workarounds:
  (1) close other apps to free memory; (2) run on 32 GB+ hardware
  (no code changes); (3) deeper circuit-level optimizations
  (specialized SHA-256 by length, shared ADRS encoding, smarter
  multiplexers — stacking these may bring SHA-2 to ~108M, still tight).
- **Per-primitive Rust oracle** (`reference/src/main.rs`) computes
  FIPS 205 §11.2.2 / §11.1 reference outputs for SHA-2 and SHAKE
  primitives, emits circom witness JSONs with expected outputs, and
  test wrapper circuits assert `out === expected_out`. **All 20 tests
  pass** (10 positive: circuit output matches Rust; 10 negative:
  flipped expected_out causes witness gen to fail on the assertion).
  See `scripts/run_tests.sh` and `results/results.md` "Cryptographic
  correctness" section.
- **End-to-end main-level witness check** still pending: SHA-2 and
  SHAKE mains OOM, and Poseidon needs a from-scratch shadow impl
  since no library does Poseidon-SLH-DSA over secq256r1.

## Documented spec decisions

These ambiguities are resolved as follows; see the implementation plan
for the full rationale.

1. **H_msg for 128s** uses MGF1-SHA-256 per FIPS 205 §11.2.1
   (Category 1). The brief mentioned SHA-512, which is FIPS 205 §11.2.2
   for Category 3+ parameter sets only.
2. **PRF_msg** is signing-only and not in the verifier circuit.
3. **`vocdoni/keccak256-circom` dropped** — `bkomuves/hash-circuits`
   ships SHAKE-256 natively under MIT.
4. **Poseidon ADRS encoding**: 7 native field elements (one per ADRS
   sub-field) over secq256r1.
5. **Poseidon truncation**: low 128 bits of one Poseidon output for
   n-byte slots; H_msg uses two calls with domain-separation tags to
   produce 30 bytes.
6. **Poseidon domain separation**: prepend a primitive-tag field
   element (F=0, H=1, T_k=2, T_len=3, H_msg=4) to every Poseidon call.
7. **Fixed message length**: M = exactly 1024 B; KATs filtered to
   `len(M) == 1024`.
8. **Optimization**: compile with `--O2` (set via `circomkit.json`
   `optimization: 2`).
9. **Prime**: `secq256r1`. The `protocol: "groth16"` field in
   `circomkit.json` is required by circomkit but unused — no proofs
   are generated.
10. **Poseidon constants on secq256r1**: circomlib's Poseidon round
    constants are tuned for BN254. Used here mod p_secq256r1, the
    construction is non-standard (R1CS structure unchanged, security
    analysis does not transfer). **Benchmarking only.**
11. **Build orchestrator**: `circomkit ^0.3.4` matching zkID.
12. **Yarn version**: yarn berry 4.13.0 (corepack-managed).
13. **SHA-2 midstate optimization**: pre-compute `Sha256Compression(default_IV, pk_seed||zeros[48])` once via `Sha256SeedIv` and pass the resulting 256-bit `iv_state` to every F/H/T_l call. FIPS 205 §11.2.2's mandatory 48-byte zero padding aligns to a SHA-256 block boundary, so this is a pure compiler optimization — output bits are bit-identical to the unoptimized version.

## Layout

```
circuits/
  common/        params + bytes + ADRS struct + digest parsing + base_2b
  common/{wots,fors,xmss,ht,slhdsa_verify}.circom
                 pk_seed-based templates (used by SHAKE and Poseidon mains)
  sha2/          midstate-optimized SHA-2 family
    sha256_midstate.circom   Sha256SeedIv + Sha256BodyBytes
    sha256_wrap.circom       Sha256Bytes (for HMsg only — no midstate)
    adrs_encode_sha2.circom  AdrsFields → 22-byte compressed (FIPS 205 §11.2.2)
    hashes.circom            SlhF/SlhH/SlhTk/SlhTlen/SlhHMsg
    {wots,fors,xmss,ht,slhdsa_verify}.circom   iv_state-based common templates
  shake/         shake256_wrap + adrs_encode_shake + hashes
  poseidon/      poseidon_wrap + hashes (uses common/wots etc.)
  main_<family>.circom       top-level mains
  bench/                     per-primitive standalone benches
  test/                      Rust-oracle assertion wrappers (test_<family>_<prim>)
reference/                   Rust oracle: FIPS 205 §11.1/§11.2.2 hashers
                             + circom witness JSON emitter
scripts/                     vendor.sh, bench.sh, parse_r1cs_stats.py, run_tests.sh
results/                     final tables + raw_bench.txt + soundness_audit.md
vendor/                      git-cloned at pinned SHAs
```

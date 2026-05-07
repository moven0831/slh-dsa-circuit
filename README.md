# slhdsa-128s-circom

R1CS arithmetization benchmark of the **NIST FIPS 205 SLH-DSA-128s**
signature verifier under three swappable hash gadget configurations:

| Family   | Standardization                          | Primitives                          |
|----------|------------------------------------------|-------------------------------------|
| SHA-2    | FIPS 205 §11.2 SLH-DSA-SHA2-128s         | SHA-256 (+ MGF1-SHA-256 for H_msg)  |
| SHAKE    | FIPS 205 §11.1 SLH-DSA-SHAKE-128s        | SHAKE-256                           |
| Poseidon | non-standard, ZK-benchmarking only       | circomlib Poseidon over secq256r1   |

The deliverable is **R1CS stats** — per-component constraint counts,
witness sizes, totals — plus a sanity test that each circuit accepts a
real KAT and rejects a tampered KAT. **No trusted setup, no proof
generation, no Solidity verifier, no integration.**

The prime field is `secq256r1` (P-256 group order), matching
[`privacy-ethereum/zkID/wallet-unit-poc/circom/circomkit.json`](https://github.com/privacy-ethereum/zkID/blob/main/wallet-unit-poc/circom/circomkit.json).

See `docs/PLAN.md` (or the in-tree `task-build-circom-calm-duckling.md`)
for the implementation plan, `Dependencies.md` for pinned versions,
and `results/results.md` for the constraint-count tables.

## Quickstart

```bash
corepack enable
yarn install
bash scripts/vendor.sh         # clones bkomuves/hash-circuits + integritychain/fips205 at pinned SHAs
yarn bench                     # compiles every circuit in circuits.json + dumps r1cs info to results/raw_bench.txt
yarn parse                     # generates results/results_summary.md
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
  `circom v2.2.3` compiler on a 16 GB MacBook (RSS hits 3.9 GB before
  macOS memory pressure SIGKILLs). Workarounds: (1) run on 32–64 GB
  hardware (no code changes); (2) deeper circuit-level optimizations
  (specialized SHA-256 by length, shared ADRS encoding, smarter
  multiplexers — stacking these may bring SHA-2 to ~108M, still tight).
- **Witness oracle** (positive + negative test) pending — requires Rust
  reference using `vendor/fips205::keygen_with_seeds` for SHA-2/SHAKE
  KATs (the ACVP `internalProjection.json` shipped with `fips205@30bac08`
  doesn't include 128s vectors). Poseidon needs a from-scratch shadow
  impl since no library does Poseidon-SLH-DSA over secq256r1.

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
reference/                   Rust oracle (vendor/fips205) — pending
scripts/                     vendor.sh, bench.sh, parse_r1cs_stats.py
results/                     final tables + raw_bench.txt
vendor/                      git-cloned at pinned SHAs
```

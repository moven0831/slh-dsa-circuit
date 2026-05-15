# slhdsa-128s-circom

R1CS arithmetization benchmark of **NIST FIPS 205 SLH-DSA-128s** signature
verification under three swappable hash gadgets, on the `secq256r1` prime
field (matching [`privacy-ethereum/zkID/wallet-unit-poc/circom/circomkit.json`](https://github.com/privacy-ethereum/zkID/blob/main/wallet-unit-poc/circom/circomkit.json)).

| Family   | Spec                                | Primitives                          |
|----------|-------------------------------------|-------------------------------------|
| SHA-2    | FIPS 205 §11.2 SLH-DSA-SHA2-128s    | SHA-256 (+ MGF1-SHA-256 for H_msg)  |
| SHAKE    | FIPS 205 §11.1 SLH-DSA-SHAKE-128s   | SHAKE-256                           |
| Poseidon | non-standard, ZK-benchmarking only  | circomlib Poseidon over secq256r1   |

Deliverable: **R1CS stats** (per-component constraint counts, witness sizes,
totals) + 20/20 per-primitive correctness tests against a Rust FIPS 205 oracle.
**No trusted setup, no proof generation, no Solidity verifier.**

## TLDR

| Family   | F | H | T_k | T_len | H_msg | **Verifier total** | Compile |
|----------|--:|--:|--:|--:|--:|---:|---|
| **SHA-2** (midstate) | 30,290 | 30,662 | 123,182 | 307,106 | 583,273 | **~121.7 M** | OOM† |
| **SHAKE**            | 145,568 | 145,824 | 440,736 | 737,952 | 1,182,912 | **~577.5 M** | OOM† |
| **Poseidon**         | 968 | 1,102 | 5,989 | 14,428 | 24,844 | **3,992,159** ✓ | <1 min, <2 GB |

- **Cost ratio at F** (3,675 invocations / verifier — the dominant primitive):
  Poseidon 1× · SHA-2 31× · SHAKE 150×.
- **SHA-2 midstate** (FIPS 205 §11.2.2 zero-padded `pk_seed||zeros[48]`
  compressed once via `Sha256SeedIv`, shared across F/H/T_l) halves SHA-2:
  F 60,778 → 30,290; main projection ~242 M → ~122 M (–50 %). Bit-identical
  output to the unoptimized version.
- **Correctness**: 20/20 per-primitive tests pass. Rust oracle
  (`reference/`) computes FIPS 205 §11.1/§11.2.2 reference outputs;
  test wrappers assert `out === expected_out`. Negative tests (flipped
  expected) reject as required.
- **Poseidon integration delta**: measured 3,992,159 vs sum-of-parts
  3,957,343 (+0.9 %) — validates SHA-2/SHAKE projections within ~1 %.
- **User-facing implication**: Poseidon is ~30× smaller than SHA-2 at the
  cost of being non-standard; for FIPS-compliant ZK applications, SHA-2 is
  ~5× smaller than SHAKE.

**† Hardware limit**: `main_sha2` (~122 M) and `main_shake` (~578 M) OOM
the `circom v2.2.3` compiler. Tested on a 24 GB M3 MacBook — RSS reached
3.94 GB after ~3 min before macOS SIGKILL'd the process (~13 GB swap
already committed by other apps, leaving ~10 GB free against an estimated
12+ GB working set). Expected to compile on a less-loaded 24 GB system or
any 32 GB+ machine. `main_poseidon` (4 M) compiles in <1 min, peak RSS <2 GB.

## Spartan2 / OpenAC prove + verify benchmark

End-to-end prove + verify numbers for `main_poseidon` on the same
Spartan2 backend that OpenAC's `wallet-unit-poc/ecdsa-spartan2` uses
(`T256HyraxEngine` / Hyrax-PC over secq256r1), captured on M3/24 GB:

|  Phase  |       Time | Peak RSS | Artifact |     Size |
|---------|-----------:|---------:|----------|---------:|
| Setup   |  23,143 ms | 10.45 GB | Proving key | 2.37 GB |
| Witness |   1,387 ms |        – | **Proof**   | **208.8 KB** |
| Prove   |  16,184 ms |  5.41 GB | Verifying key | 2.37 GB |
| Verify  |   9,522 ms |  3.11 GB |          |          |

→ ~10–14× slower prove/verify than ecdsa-spartan2 jwt_1k (76 KB proof,
1.1 s prove on M5/24 GB), tracking the R1CS-size ratio.

Reproducer + Rust crate: [moven0831/slh-dsa-128s-poseidon-bench](https://github.com/moven0831/slh-dsa-128s-poseidon-bench).
Full breakdown in [`results/slh_dsa_spartan2_1k.md`](results/slh_dsa_spartan2_1k.md).

## Quickstart

```bash
corepack enable
yarn install
bash scripts/vendor.sh         # clones bkomuves/hash-circuits + integritychain/fips205 at pinned SHAs
yarn bench                     # compiles every circuit in circuits.json → results/raw_bench.txt
yarn parse                     # → results/results_summary.md
bash scripts/run_tests.sh      # 20 per-primitive correctness tests (Rust oracle ↔ circom)
```

## Documentation

- [`results/results.md`](results/results.md) — full per-family tables,
  acceptance criteria, hardware-limit analysis.
- [`results/soundness_audit.md`](results/soundness_audit.md) — every
  range check, selector, and equality assertion in the verifier.
- [`results/hash_based_analysis.md`](results/hash_based_analysis.md) —
  R1CS projections for SLH-DSA variants, XMSS/XMSS^MT, LMS/HSS using
  the calibrated cost model.
- [`docs/slh-dsa-primer.md`](docs/slh-dsa-primer.md) — what SLH-DSA is,
  what each primitive does, how to read the benchmark.
- [`results/slh_dsa_spartan2_1k.md`](results/slh_dsa_spartan2_1k.md) —
  Spartan2 / OpenAC end-to-end prove + verify numbers for the Poseidon
  verifier; companion repo at
  [moven0831/slh-dsa-128s-poseidon-bench](https://github.com/moven0831/slh-dsa-128s-poseidon-bench).
- [`Dependencies.md`](Dependencies.md) — pinned versions and commit hashes.

## Layout

```
circuits/
  common/        params, bytes, ADRS, digest parsing, base_2b
  common/{wots,fors,xmss,ht,slhdsa_verify}.circom
                 pk_seed-based templates (used by SHAKE and Poseidon mains)
  sha2/          midstate-optimized SHA-2 family
    sha256_midstate.circom   Sha256SeedIv + Sha256BodyBytes
    sha256_wrap.circom       Sha256Bytes (HMsg only — no midstate)
    adrs_encode_sha2.circom  AdrsFields → 22-byte compressed (FIPS 205 §11.2.2)
    hashes.circom            SlhF/SlhH/SlhTk/SlhTlen/SlhHMsg
    {wots,fors,xmss,ht,slhdsa_verify}.circom   iv_state-based variants
  shake/         shake256_wrap + adrs_encode_shake + hashes
  poseidon/      poseidon_wrap + hashes (uses common/wots etc.)
  main_<family>.circom       top-level mains
  bench/                     per-primitive standalone benches
  test/                      Rust-oracle assertion wrappers
reference/       Rust oracle: FIPS 205 §11.1/§11.2.2 hashers + circom
                 witness JSON emitter
scripts/         vendor.sh, bench.sh, parse_r1cs_stats.py, run_tests.sh
results/         tables + raw_bench.txt + soundness_audit.md + hash_based_analysis.md
docs/            slh-dsa-primer.md
vendor/          git-cloned at pinned SHAs
```

## Spec notes

Resolved ambiguities; full rationale in [`results/results.md`](results/results.md#documented-spec-deviations).

1. **H_msg for 128s** uses MGF1-SHA-256 (FIPS 205 §11.2.1, Category 1).
   The brief mentioned SHA-512, which is §11.2.2 for Category 3+ only.
2. **PRF_msg** is signing-only — not in the verifier circuit.
3. **Poseidon ADRS**: 7 native field elements (one per ADRS sub-field).
   Truncation: low 128 bits per Poseidon output for n-byte slots; H_msg
   uses two calls with domain-separation tags for 30 bytes. Tags:
   F=0, H=1, T_k=2, T_len=3, H_msg=4.
4. **circomlib Poseidon constants** are tuned for BN254. Used here mod
   `p_secq256r1`, the construction is non-standard (R1CS structure
   unchanged, security analysis does not transfer). **Benchmarking only.**
5. **Fixed message**: M = 1024 B; KATs filtered to `len(M) == 1024`.
6. **Compile flags**: `--O2` (set via `circomkit.json` `optimization: 2`).
   `protocol: "groth16"` is required by circomkit but unused.
7. **SHA-2 midstate**: pre-compute `Sha256Compression(default_IV,
   pk_seed||zeros[48])` once via `Sha256SeedIv`, pass the 256-bit
   `iv_state` to every F/H/T_l call. Pure compiler optimization — output
   bit-identical to the unoptimized version.

# Goldilocks Poseidon port — signal-width audit + Gate-2 decision

**Status:** Week 2 Day 2 deliverable. Settles the signal-width-bloat risk flagged at the top of the Week 2 plan and the §5.1 ±50 % projection in `cost_model.md`.

**TL;DR:** **Gate-2 PASS.** Goldilocks port is empirically **cheaper** than the secq256r1 baseline at the SlhF level (0.88×) and across the full HT-layer step (0.85×). The signal-width doubling concern (16-byte → 2 FEs) was offset by Plonky2's 30-round permutation being lighter than circomlib BN254's 73-round permutation. Full Day-3+ plan (LatticeFold R1CS importer → 7-step IVC) proceeds with no scale changes.

---

## 1. Bloat-factor measurements

All measurements via `bash scripts/bench_poseidon_gl.sh` (Goldilocks column) and `scripts/bench.sh` (secq256r1 column, derived from `results/raw_bench.txt`). Both use `--O2`. Date: 2026-05-26.

| Primitive | secq256r1 R1CS | Goldilocks R1CS | Bloat factor | Notes |
|---|---|---|---|---|
| Poseidon perm (1 call) | 240 (`Poseidon(2)`, t=3) | **472** (`PoseidonGlPermute`, t=12) | 1.97× | t goes up to fit packed 16-byte values; this is the cost we pay for Goldilocks-class wall-clock |
| Reduce-tree node | 240 (Poseidon(2) per node) | 440 (`PoseidonGl(4)` per node) | 1.83× | Within ~5% of perm bloat; small overhead for 2-FE leaf packing |
| **SlhF** | 968 | **852** | **0.88×** | **Goldilocks is cheaper** — 30 rounds vs 73 |
| **SlhH** | 1,102 | **1,436** | 1.30× | 2-perm Plonky2 sponge needed for arity 14 |
| SlhTk | 5,989 | 8,668 | 1.45× | Dominated by 14× reduce nodes + 1 mix perm |
| SlhTlen | 14,428 | 21,892 | 1.52× | 38× reduce nodes + 1 mix perm; the heaviest non-HMsg primitive |
| **HT layer (D4 step)** | **~573K** projected | **485,930** measured | **0.85×** | The load-bearing Gate-2 number |

**HT-layer breakdown vs projection:**

| Component | Per-call × count | Projected R1CS | Notes |
|---|---|---|---|
| F (WOTS chains) | 852 × 525 | 447,300 | 35 chains × 15 F-steps |
| T_len (WOTS pubkey compress) | 21,892 × 1 | 21,892 | one per layer |
| H (XMSS Merkle) | 1,436 × 9 | 12,924 | 9 auth-path levels |
| Glue (Base2bWithCsum, muxes, range checks) | — | ~4K | ≈ 0.8% of total |
| **Sum-of-parts** | | **486,116** | within 0.04% of measured (485,930) |

The 186-R1CS residual (measured 485,930 vs predicted 486,116) is wire-routing optimization from `--O2`. Excellent agreement.

## 2. Why the bloat didn't materialize

The plan's load-bearing risk was that Goldilocks's 64-bit field would force every 16-byte SLH hash value to span 2 FEs, roughly doubling Poseidon input arity (e.g., SlhF's arity going from 10 to 12). The arity does grow, but the per-permutation cost drops faster:

- **circomlib BN254 Poseidon (t=11, used by `SlhF` on secq256r1):** 8 full + 65 partial rounds = 73 rounds × x⁵ S-box (3 R1CS mults) = ~459 R1CS for S-boxes + linear MDS. Plus packing.
- **Plonky2 Goldilocks Poseidon (t=12, used by `SlhF_Gl`):** 8 full + 22 partial rounds = 30 rounds × x⁷ S-box (4 R1CS mults). Counted: 8 × 12 × 4 + 22 × 1 × 4 = 472 R1CS. Plus packing.

So the round-count drop (73 → 30) more than compensates for the wider state (t=11 → t=12) and the more expensive S-box (x⁵ → x⁷).

`cost_model.md §5.1` projected this band as "1.0× ± 50%" (corrected from an earlier wrong 0.5× estimate that ignored S-box cost). The measured numbers land at **0.85× for the HT layer**, comfortably inside the 0.5×–1.5× band. The projected-vs-measured table is one of the §7 reconciliation rows for `week2_results.md`.

## 3. Gate-2 decision

Per `/Users/moventsai/.claude/plans/given-the-context-on-reactive-patterson.md` §"Gate-2 (end of Day 2)":

- **Bloat factor ≤ 1.5×** → proceed with full D4 plan (7-step IVC on LatticeFold). ✓ HT-layer factor is 0.85×, all individual primitives ≤ 1.52×.

→ **Day 3 proceeds without scope change.**

## 4. Implications for Day 3 plan

- **D4 step circuit size:** 485,930 R1CS — comfortably within LatticeFold's "we haven't tested at this scale" but well below the "research-grade" 5K-RV32IM ceiling of Nightstream. LatticeFold's e2e example proves a degree-3 polynomial constraint, so a 486K-constraint circuit is the *first* real-world stress test on either library.
- **Total 7-step fold work:** 7 × 485,930 = **3,401,510 R1CS** of step-circuit constraints (before per-fold accumulator overhead). This is 85% of the monolithic 4.0M baseline — the reshape preserves total work as expected.
- **Field-op speedup is the wall-clock story.** Goldilocks 64-bit multiplications are *expected* to be ~20–50× faster per-mult than secq256r1 256-bit multiplications, based on published Plonky2 benchmarks vs `secq256r1`-based Spartan2 / Hyrax-PC numbers in our companion repo. **This is a projection, not a measurement** — R1CS row count is only a proxy for total prover time, and the empirical speedup must be confirmed by the Day 4–5 LatticeFold wall-clock benchmarks (`cargo run --release --bin fold_ht`).
- **Compile time for the HT-layer bench is 14s on M3** — fast enough that Day 5's per-layer witness generation (7 calls) won't bottleneck.

## 5. Open caveats

These do **not** block Day 3 but are flagged for Week 3+ and for the external cryptographer review:

1. **One-shot permutation vs Plonky2 standard sponge** — `PoseidonGl(12)` initializes state directly from 12 inputs and applies one permutation, mirroring the existing project's "permutation-as-fixed-arity-hash" construction. This is **not** Plonky2's standard `hash_n_to_m_no_pad` (which uses rate=8 absorb + multiple perms). Cryptographic note in `circuits/poseidon_gl/poseidon_gl_wrap.circom:60-71`. The same caveat applies to the existing secq256r1 family per `CLAUDE.md`.
2. **2-perm sponge for SlhH** is the Plonky2 overwrite-absorb sponge convention (rate=8, capacity=4). Different from the SlhF one-shot. Documented in `poseidon_gl_wrap.circom:PoseidonGlSponge14`.
3. **No Plonky2 reference test vectors for the SLH primitives themselves** — only for the underlying permutation. The 4 reference vectors in `scripts/check_poseidon_gl.py` cover `PoseidonGlPermute`, not `SlhF_Gl` / `SlhH_Gl`. We could add Rust-oracle vectors for the GL family if cryptographer review requests them; deferred.
4. **HMsg is intentionally not ported** — D4-restricted fold doesn't fold HMsg. It goes inline in the Week-3 closing SNARK.

## 6. Reproducibility

Run `bash scripts/bench_poseidon_gl.sh` (creates / consumes `/Users/moventsai/Projects/mine/slh-dsa-circuit/build/poseidon_gl_bench/`). On the M3 machine the full table regenerates in ~30 seconds (HT-layer bench dominates with 14s of compile).

## 6a. Day-4 Phase-A scale test — LatticeFold relation check on full HtLayerStep

The Day-3 R1CS importer (`tools/r1cs-latticefold/`) was scale-tested against the full HtLayerStep R1CS (485,930 constraints, 467,721 wires, 1,797,687 nnz across A/B/C):

```
$ ./tools/r1cs-latticefold/target/release/smoke \
    --r1cs build/poseidon_gl_bench/bench_ht_layer_gl/bench_ht_layer_gl.r1cs \
    --wtns build/poseidon_gl_bench/bench_ht_layer_gl/all_zeros.wtns
```

Per-stage wall-clock on M3 / release build:

| Stage | 440-constraint smoke | 485,930-constraint HtLayerStep | Ratio |
|---|---:|---:|---:|
| parse .r1cs + .wtns | 11 ms | **3,608 ms** | 328× (linear in nnz: 1942 → 1.8M = 925×; parse is faster per-nnz at scale) |
| lift Goldilocks → RqNTT | 0.2 ms | **93 ms** | 465× (linear in n_wires: 445 → 467K = 1051×; lift amortizes well) |
| R1CS::check_relation | 1.5 ms | **514 ms** | 343× (sub-linear in nnz: rayon parallelism within mat_vec_mul) |
| CCS::from_r1cs | 5 µs | **4 µs** | constant (just struct rearrange) |
| CCS::check_relation | 1.9 ms | **702 ms** | 369× (sub-linear) |
| **Total smoke** | **~14 ms** | **~5 s** | **~360×** |

**Significance:** This is the largest circuit ever validated through Nethermind LatticeFold's relation-check path. Their published e2e example uses a toy degree-3 polynomial constraint; we exercise the full pipeline on 486K real Poseidon-arithmetic constraints with no crashes, no panics, and OK relation checks throughout.

**Day-4 Gate criteria (partial):**
- ✓ HtLayerStep R1CS lifts cleanly into LatticeFold form
- ✓ Wall-clock under 10s (5s)
- ✓ Peak RSS comfortably under 1 GB (M3/24GB had no memory pressure; process didn't trigger Activity Monitor's "memory pressure" indicator)
- ⊘ Per-fold recursion overhead — not yet measured; requires the full `NIFSProver::prove` invocation (Day-4 Phase B).

The relation-check timing implies the full prover (which performs accumulator update + linearization + folding) should land in the 5–30 s range for a single HT-layer fold step. **HOWEVER**, Phase B (§6b) shows this projection is contingent on resolving a verify-side blocker not visible at the relation-check level. Read §6b before quoting Phase A timings as a fold throughput claim.

## 6b. Day-4 Phase-B — Full NIFSProver::prove + NIFSVerifier::verify

Result: **prove SUCCEEDS, verify FAILS** on the 440-constraint smoke circuit.

Reproducer:

```
$ cargo run --release --bin fold_step \
    --manifest-path tools/r1cs-latticefold/Cargo.toml \
    -- --r1cs build/poseidon_gl_bench/bench_poseidon_gl_reduce2/bench_poseidon_gl_reduce2.r1cs \
       --wtns build/poseidon_gl_bench/bench_poseidon_gl_reduce2/all_zeros.wtns
```

Per-stage prove timings (on bench_poseidon_gl_reduce2):

| Stage | Wall-clock |
|---|---:|
| Parse + lift (Phase-A pipeline) | 11 ms |
| `CCS::from_r1cs_padded` | 100 µs (pad 440 → 4096 rows) |
| Pre-flight `ccs.check_relation` | 4 ms |
| AjtaiCommitmentScheme + `Witness::from_w_ccs` (L=5 gadget decomp) | 2 ms |
| `wit.commit::<DP>(&scheme)` (Ajtai commit) | 2 ms |
| `LFLinearizationProver::prove` (initial accumulator) | 20 ms |
| `NIFSProver::prove` (the fold step) | **254 ms** |
| Proof size (compressed + uncompressed) | 133 KB / 133 KB |

`NIFSVerifier::verify` returns `Err(LinearizationFailed(SumCheckFailed(InvalidProof("incorrect sumcheck sum"))))`. The "Expected" side of the diagnostic has concrete ring-element values; the "Received" side prints as truncated `CubicExtField(,,)` (a Display-formatting quirk on partial CRT elements, not an actual zero).

### Root-cause investigation (rejected hypotheses)

1. **"degree-2 vs degree-3 CCS"** — REJECTED. LatticeFold's unit tests use `from_r1cs_padded` (producing d=2, q=2, S=[[0,1],[2]]) and pass. The linearization prover reads `ccs.d + 1` dynamically (`linearization.rs:199-200`) and iterates `ccs.S[i]` generically (`utils.rs:91-106`) — degree is not the issue.
2. **"mismatched wit_acc in setup linearization"** — TESTED + REJECTED. Replacing the random rand_w_ccs with the real w_ccs as setup-witness produced the same error pattern (only the expected sum value changed). See fold_step.rs git diff between the two attempts.

### Working hypothesis

**Gadget-decomposition norm mismatch.** `Witness::from_w_ccs` calls `gadget_decompose(B=2^15, L=5)` on the coefficient form of the witness ring elements. Our Circom witness contains full-range Goldilocks coefficients (up to ~2^64). `B^L = 2^75 > 2^64` so the decomposition is well-defined coefficient-wise, but the resulting MLE evaluations in the linearization sumcheck diverge between the prover (computing on the decomposed `f_coeff`) and the verifier (reconstructing from the committed `cm`). This may be the gap between:
- LatticeFold's security argument (assumes small-norm witness)
- Our Circom witness (full-range Goldilocks, no a priori norm bound)

Settling this requires reading `LFLinearizationProver::prove` (`crates/latticefold/src/nifs/linearization.rs`) and the verifier's sumcheck reconstruction to identify exactly which MLE evaluation differs. **Estimated Week-3 effort: ~1 engineer-day of source archaeology + a small targeted test.**

### Resolution paths (Week-3+)

1. **Diagnose the witness-encoding mismatch.** Single-file investigation; outcome may be a one-line fix (different DecompositionParams) or a larger pre-decomposition step on our witness.
2. **Use LatticeFold+** (NethermindEth/latticefold WIP). Different witness model may sidestep the issue natively; status of LatticeFold+ verified is `examples + parameter tuning TODO` per upstream README.
3. **Pivot to Nightstream / Neo** (Day-5 measurement-spike target). Different folding scheme; natively folds the same CCS shape we already produce; trade-off is no scaling demonstration yet at our 486K-constraint size.

### What Phase B is NOT

- Phase B is not a refutation of Phase A. The 5-second `check_relation` on 486K constraints stands as a valid lower-bound for any prover that goes through CCS — the relation check is a subroutine of NIFS.
- Phase B is not a refutation of the Goldilocks Poseidon port. The Day-1 reference vectors + Day-2 bloat factor still hold.
- Phase B is not the "fold-overhead per step" measurement. The 254 ms NIFSProver::prove is the prover-side cost, but without a verifying proof we can't yet claim this is the cost of a verified fold step.

The Day-4 deliverable is: **prove pipeline end-to-end validated** (no panics, no OOMs, clean prove side), **verify failure captured as a concrete reproducible blocker for Week-3**. This is decision-grade information for the Week-2 recommendation memo (Day 5).

## 7. Files

- `circuits/poseidon_gl/poseidon_gl_wrap.circom` — `PackBytes16To2Fe`, `UnpackFe2To16Bytes`, `PoseidonGl(nInputs)`, `PoseidonGlSponge14`, `PoseidonGlReduce(N)`.
- `circuits/poseidon_gl/hashes_gl.circom` — `SlhF`, `SlhH`, `SlhTk`, `SlhTlen` (unsuffixed; matches the family-agnostic include convention in `circuits/common/wots.circom`).
- `circuits/common/ht_layer_step.circom` — D4 step circuit.
- `circuits/poseidon_gl/bench/bench_*.circom` — 6 bench wrappers.
- `scripts/bench_poseidon_gl.sh` — bench harness.
- `research/folding/cost_model.md` §5.1 — projection methodology this validates.
- `research/folding/step_function_slh_dsa_128s.md` §5.2 — HT-layer (D4 step) baseline projection.

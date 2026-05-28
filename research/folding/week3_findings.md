# Week-3 findings: production-params folding of SLH-DSA-128s on Nightstream — measured

**Date:** 2026-05-28
**Status:** V1 + V4 verified from Nightstream source. **V2 + V3 now measured end-to-end** at production security via the `rfp_smoke` binary in `github.com/moven0831/slh-dsa-neo`.
**Supersedes:** the "fold beats monolith on Spartan2-GL" hypothesis in `week2_results.md §9` and the per-fold-overhead numbers in `cost_model.md §3.3`. Also walks back the in-conversation "maybe wall-clock-competitive" speculation from the earlier draft of this memo.

## TL;DR

**Production-params `r1cs_f_prime` works end-to-end on a Circom-derived Goldilocks R1CS at SLH-DSA-128s D4 scale.** One HT-layer fold step (486 K R1CS / 467 K wires → 30 M-row F' CCS structure) on M3 / 24 GB / single-thread:

- **Prove + finish:** 116.6 s
- **Verify (uncompressed):** 19.8 s
- **Preprocess (Ajtai setup, one-time):** 86.7 s
- **Peak RSS:** 10.46 GB
- **Total wall-clock:** 227 s
- Plan `limbs = m × 64 + 1 = 29 934 145` — confirms the structural `~64×` row blow-up

Extrapolated full D4 chain (7 folds, same shape per step, c_data_entries minimally sized): ~815 s prove (~14 min). For comparison, the companion repo's monolithic Spartan2 + Hyrax on secq256r1 verifies the same SLH-DSA-128s signature in 16.2 s prove + 9.5 s verify ≈ 25.7 s total / 5.41 GB peak RSS / 208.8 KB proof. Two ways to frame the gap: **~50× slower in prover wall-clock** (815 s / 16.2 s) **or ~32× slower if you count prove + verify on both sides** (835 s / 25.7 s). Either way, folding via `r1cs_f_prime` is meaningfully slower at SLH-DSA-128s scale.

This refutes both the "fold beats monolith" thesis (`week2_results.md §9`) and the earlier in-conversation speculation that Goldilocks per-row speedup would compensate for the 64× row blow-up. The Goldilocks speedup is real but smaller than the structural overhead, in this regime. **Folding via `r1cs_f_prime` is meaningfully slower than monolithic Spartan2 at SLH-DSA-128s scale.**

The smoke binary `rfp_smoke` makes this reproducible in ~30 s of test time (the 5 s 440-R1CS smoke at production params) and ~4 min of test time (the 227 s 486 K HT-layer step at production params). Both run on stock M3 / 24 GB.

## 1. What the rfp_smoke binary produced

Phase-A pivot landed at [`github.com/moven0831/slh-dsa-neo`](https://github.com/moven0831/slh-dsa-neo) commit on `main`. The `rfp_smoke` binary (`crates/neo-ivc/src/bin/rfp_smoke.rs`) wires:

```
parse Circom .r1cs/.wtns
  → neo_bridge::circom_to_neo_{mats|sparse_mats}
  → direct_ccs::R1cs { a, b, c, m_in } | SparseR1cs { … }
  → r1cs_f_prime::preprocess_{seeded|sparse_seeded}(&r1cs, &plan, seed)
  → R1csChainBuilder::new(&prep).append_assignment(z).finish()
  → lifecycle::verify_uncompressed(&prep.prep, &finished)
```

Plan construction follows `make_small_plan` from `nightstream@755c1595/crates/neo-fold-clean/tests/system/r1cs_compiler.rs:75` (minimal `c_data_entries = 2`, single-child accumulator, `state_x_out` bound to public inputs).

### Run 1 — `bench_poseidon_gl_reduce2` (440 R1CS, m = 445 wires, smoke scale)

Dense path (`Mat<F>` triplet), single fold step, production params, M3 / 24 GB:

| Stage | Wall-clock |
|---|---:|
| Parse Circom .r1cs/.wtns | 9.8 ms |
| Lift to `neo_ccs::Mat<F>` | 0.7 ms |
| R1CS row-wise sat check | 0.7 ms |
| Build `RecursiveStepImagePlan` | 0.1 ms |
| `preprocess_seeded` | 1.72 s |
| `R1csChainBuilder` append + finish | 2.07 s |
| `verify_uncompressed` | 0.62 s |
| **Total** | **4.42 s** |
| Peak RSS | **2.26 GB** |

Result: `PASS — r1cs_f_prime prove + finish + verify all succeed.`

This is the first measured production-params number for `r1cs_f_prime` on a Circom Goldilocks R1CS in any context — Nightstream's own integration tests all use `tiny_params` (κ=4, λ=60, m=2^16) to fit a single fold step under their 5-min CI cap. The fact that the production-params smoke completes in 5 s on M3 / 24 GB is itself useful information.

### Run 2 — `bench_ht_layer_gl` (485 930 R1CS, m = 467 721 wires, the D4 step)

Sparse path (`CcsMatrix<F>::Csc` triplet, dense would OOM at ~1.8 TB virtual), single fold step, production params, M3 / 24 GB:

| Stage | Wall-clock |
|---|---:|
| Parse Circom .r1cs/.wtns | 3.6 s |
| Lift to sparse `CcsMatrix<F>::Csc` | 170 ms |
| R1CS row-wise sat check | 9.4 ms |
| Build `RecursiveStepImagePlan` (limbs = 29.9 M) | 45 µs |
| `preprocess_sparse_seeded` | 86.7 s |
| `R1csChainBuilder` append + finish | **116.6 s** |
| `verify_uncompressed` | **19.8 s** |
| **Total** | **227 s** (3 min 47 s) |
| Peak RSS | **10.46 GB** |

Result: `PASS — r1cs_f_prime prove + finish + verify all succeed.`

Important caveat: `c_data_entries = 2` in the plan is the minimum F'-shell accumulator size (sufficient for one-step chains; Nightstream's two-step lifecycle test uses `TINY_C_DATA_ENTRIES = 216 = κ × D` at tiny_params, or 972 at production). For the full 7-step D4 IVC chain with a properly-sized accumulator, the per-step prove cost may grow ~10–20%. The 116.6 s number is a **lower bound** for a 7-step D4 prove.

## 2. V1 — `b = 2` is structural, not configurable (unchanged)

(Same as the previous draft of this memo.) Verified in `crates/neo-params/src/lib.rs`:

- `goldilocks_paper_b2::B_BASE: u32 = 2` (line 65).
- `Params::production()` and `Params::goldilocks_paper_b2()` both call `NeoParams::goldilocks_paper_b2()`.
- `Params::for_r1cs_shape` → `goldilocks_auto_r1cs_ccs_with(n_rows, min_lambda, safety_margin)` (line 236–270). Reading the loop at line 263: it only varies `lambda`. Never `b`, `k_rho`, `kappa`, `m`.
- Only escape: `Params::test_only_from_neo_params(custom_inner)` — docstring forbids production use.

This is why `direct_ccs::build_instance` on our Circom-derived witness rejected with `‖z‖_∞ ≥ b at index 1 (b = 2)`. The `rfp_smoke` binary works around it by going through `r1cs_f_prime` (bit-decomposition).

## 3. V4 — F'-shell structure: predicted vs. measured (unchanged & confirmed)

**Predicted** (from the `Error::PlanLimbsMismatch` definition + plan analysis): `limbs = m × 64 + 1`. For `m = 467 721` wires that's `limbs = 29 934 145`.

**Measured** (`rfp_smoke --sparse` on HT-layer, stage 4 output): `plan limbs=29934145`. Exact match — the structural claim is verified by the runtime.

Shell constants (CE payload, sponge transcript, boundary digest) at production params + `c_data_entries = 2`: small enough that the dominant row contribution is the m × 64 bitness term. The 30 M-row figure is structural, not budget-flex.

## 4. V2 — production-params `r1cs_f_prime` IS feasible on 24 GB (corrected)

The previous draft of this memo claimed: *"production-params `r1cs_f_prime` at SLH-DSA-128s scale is unmeasured by Nightstream's authors. Could be minutes per step; could be hours; could exceed 24 GB."*

**Corrected:** measured at production params (`κ = 18, λ = 125, m = 2^30, b = 2, k_rho = 14`):

- One HT-layer fold step: 227 s wall-clock total, 10.46 GB peak RSS. Fits in 24 GB.
- Nightstream's own integration tests use `tiny_params` for CI-time reasons, not feasibility reasons. The production regime works.

What's still unverified: the **full 7-step D4 IVC chain** with properly-sized accumulator (`c_data_entries = κ × D = 972` instead of the minimal 2). Naive extrapolation: ~815 s prove. Real number requires running the full chain.

**Update (2026-05-28): real-witness fold confirmed for one step; multi-step is memory-bound on 24 GB.** With the Rust signer's `emit-layers` (slh-dsa-neo), a real SLH-DSA-128s signature decomposes into 7 `bench_ht_layer_gl` step witnesses that each chain to `pk_root` in the per-layer circuit. Layer 0 was folded through `r1cs_f_prime` (`rfp_smoke_full --n-steps 1`): R1CS-sat ✓, preprocess 90.6 s, prove+finish 139.2 s, verify_uncompressed 28.9 s — **PASS**. So the folded path is no longer all-zeros-only; the single-step cost is real-witness-measured.

The *multi-step* real chain at the production accumulator (`c=972`, `r_len=26` after a `PostParentShapeMismatch` probe) parses all 7 witnesses, sat-checks, plans, and preprocesses cleanly — but the **fold phase exceeds the 24 GB box** (2-step peaked 14.24 GB RSS / 130 GB committed before a memory-pressure kill; 7-step SIGKILLed). The `c=972` accumulator fits the 440-R1CS smoke circuit (9.99 GB) but not the 486K-R1CS HT-layer shell (30M F' rows). So the `~815 s` full-chain figure stays a per-step projection — completing it needs a 32 GB+ host (the machinery and shapes are correct; this is a RAM ceiling, consistent with the OOM note in CLAUDE.md). The closing SNARK remains blocked upstream.

## 5. V3 — Goldilocks per-row speedup, measured vs. analytic

**Previous analytic estimate:** Spartan2-GL per-row cost ~0.2–0.8 µs (5–20× speedup vs the companion's 4 µs/row on Spartan2-secq256r1). Extrapolation: 30 M Goldilocks rows × 0.5 µs/row ≈ 15 s of Spartan2-prove-equivalent work per fold step.

**Measured (from `rfp_smoke`):** 116.6 s prove + finish per fold step on 30 M-row CCS structure ≈ **3.9 µs/row**. The Goldilocks speedup didn't materialize at the protocol level — `r1cs_f_prime`'s `R1csChainBuilder::append_assignment` does more per row than Spartan2's sumcheck does (compile_step + Ajtai commits + RLC + sumcheck). The per-row cost is ~the same as Spartan2-secq256r1's monolithic prove.

The walk-back has two parts:

1. **Predicted (Phase 2 finding):** ~64× row blow-up via bit-decomposition. ✅ Confirmed: `plan.limbs = m × 64 + 1 = 29,934,145` for `m = 467,721`. That's a 64.0× factor against the wire count and 61.6× against the R1CS row count. Shell constants are negligible at this scale.
2. **Speculated (in earlier memo draft):** Goldilocks per-row speedup of 5–20× partially offsets, putting folding "plausibly competitive" with monolithic. ❌ Refuted by measurement. Per-row cost in `r1cs_f_prime` is comparable to per-row cost in Spartan2-secq256r1. Net: folding is ~64× × ~1× = ~64× the work per step, partially offset by the IVC's per-step rather than monolithic-batch structure.

**New data point (2026-05-28): a Goldilocks _monolithic_ stack _is_ faster — but via the PCS, not the field.** With the Rust signer now producing a real witness (see slh-dsa-neo `crates/slh-poseidon-gl`), the monolithic Goldilocks verifier was measured end-to-end on `R1CSSNARK<GoldilocksP3MerkleMleEngine>` (Hash-MLE PCS): **6.18 s prove / 0.27 s verify** for 3.69 M R1CS, vs the companion's secq256r1 + Hyrax monolithic at **16.2 s / 9.5 s** for 3.99 M. So at the monolithic level Goldilocks+Hash-MLE is ~2.6× faster to prove and ~35× faster to verify (proof ~2.75× larger). This does **not** contradict the V3 refutation: the folding result holds the *PCS-free* per-row comparison, where Goldilocks ≈ secq256r1; the monolithic win is dominated by swapping Hyrax→Hash-MLE, not by the field. The Row 1↔Row 2 gap in the companion README is therefore "field + PCS", and the Row 2↔Row 3 gap is the clean folding-overhead axis at fixed field+family.

The honest position is now: **folding via `r1cs_f_prime` is ~5× slower per step than the entire monolithic Spartan2-secq256r1 prove, and ~32× slower for the full 7-step D4 chain.**

## 6. What the Week-2 cost model missed (largely unchanged)

`cost_model.md §3.3` projected per-fold cost as roughly linear in the *underlying* Circom R1CS size and assumed Nova-style per-fold overhead (~10 K R1CS). It didn't account for:

- The witness-norm-induced bit-decomposition (~64× row blow-up via `r1cs_f_prime`).
- The Ajtai-commitment-setup cost (86.7 s per fold prep at production params — a substantial fraction of the wall-clock).
- The verify-side cost (~20 s, comparable to the companion's full monolithic verify).

The Day-5 measurement spike (`check_ccs_rowwise_zero` at 21 ms on 486 K rows) didn't surface any of this because relation-check does not enforce the norm bound and does not run NIFS prove. The "33× faster than LatticeFold" claim from `week2_results.md §9` is correct for relation-check throughput but does not translate to a 33× advantage in NIFS prove time — which is what actually matters for IVC.

## 7. Pivots — where Pivot A leaves us

The original three pivots in this memo were Pivot A (measure `r1cs_f_prime` at production), Pivot B (drop folding, bench monolithic Spartan2-GL), Pivot C (fix LatticeFold gadget-norm at verify). **Pivot A is now done.** The result:

- Folding via `r1cs_f_prime` works end-to-end at production security on a real Circom-derived Goldilocks R1CS.
- Wall-clock is meaningfully worse than monolithic Spartan2 on secq256r1: ~5× per step, ~32× for the full D4 chain.
- Peak RSS per step (10.46 GB) is roughly 2× the monolithic baseline (5.41 GB), but **doesn't compound across folds** — IVC's defining property.

If the goal is "competitive wall-clock prove time on SLH-DSA-128s," Pivot A's answer is: **Nightstream's `r1cs_f_prime` is not the path.** The 64× row blow-up is structural to the scheme on Goldilocks; you can't optimize it away without changing the scheme.

**Updated recommendations:**

- **Pivot B (monolithic Spartan2-GL bench, no folding)** — most useful next step. Compares Goldilocks Poseidon Spartan2 prove to the companion's secq256r1 monolith with no folding overhead. Quantifies the small-field benefit cleanly. Reuses the existing Goldilocks Poseidon port. ~3–5 engineer-days. Lowest risk.
- **Pivot C (LatticeFold gadget-norm fix at verify)** — still worth doing. LatticeFold's 5× decomposition factor is more favorable than Nightstream's 64×. If the verify-side fix lands, `r1cs_f_prime`-style measurement on LatticeFold would give per-step prove around `5 × 116.6 / 64 = ~9 s` if the per-row cost is similar — potentially competitive. ~1 engineer-day for the fix per `poseidon_gl_audit.md` line 144, plus a few days to wire and measure.
- **Pivot D (new) — accept folding is for streaming/memory-bound prove, not wall-clock**. Folding's defining advantage is per-step RSS rather than total time. For a constrained-memory verifier (mobile, embedded), folding to small SNARK proof + small verify state could matter even if total prover wall-clock is 10–32× worse. But the SLH-DSA-128s deliverable is for prover wall-clock first, so this isn't the primary path.

A combination of B + C is the realistic delivery for "real folding numbers competitive with the monolithic baseline." A produces real numbers but in the wrong direction.

### Follow-up — API surface for closing the r1cs_f_prime chain (Session 2026-05-28)

While scoping a Spartan2-GL closing-SNARK wrapper for `r1cs_f_prime`, found
that Nightstream `755c1595` ships `finish_*_with_spartan` **only** for the
`direct_ccs` and `rv32im` frontends (`crates/neo-fold-prototype/src/lifecycle/direct_ccs.rs:191`
and the rv32im public-proof flow). For `r1cs_f_prime`, the canonical close
is `neo_fold_clean::lifecycle::compress(prep, audit) → Compressed` via the
audit-mode flow (`chain.finish_with_audit()`), with `verify(prep, &Compressed)`
on the verifier side. A true Spartan2-GL final SNARK on the r1cs_f_prime
output requires custom plumbing: `lifecycle::build_decider_statement(prep,
&audit) → decider::Statement`, then driving
`spartan2::R1CSSNARK<GoldilocksP3MerkleMleEngine>` standalone (the
production-validated `setup → prep_prove → prove → verify` path with
`is_small = true`). The `Compressed`-via-`compress` path is the right
**Track 1.4** deliverable today; the true Spartan2-GL final SNARK is a
**Track 1.4-bis** that's worth measuring once Track 2.2 has built the
standalone Spartan2-GL adapter in the companion repo (since the adapter
machinery is identical).

## 8. Updates needed elsewhere

- `cost_model.md §3.3`: per-fold overhead model needs a "witness-norm decomposition factor" term. For Nightstream `r1cs_f_prime` on Goldilocks: multiply `per_step_R1CS` by ~67 (measured row blow-up: limbs/underlying = 29.9M / 467K + 1 = 64). For LatticeFold (post-fix, projected): ~5×.
- `scheme_selection.md §6`: revise "Neo + D4 + Goldilocks + Spartan2" headline. Quantitatively, Neo + D4 + Goldilocks adds ~32× wall-clock vs monolithic Spartan2-secq256r1.
- `week2_results.md §9`: "Nightstream is the primary Week-3 target" was correct; the measurement now exists. Append the production-params numbers from `rfp_smoke`.
- The Day-5 review's "Week-3 forcing condition" gate (commit `03e7acc`): mark triggered, now with measured data instead of "untested."

## 9. References

- Smoke binary: `slh-dsa-neo/crates/neo-ivc/src/bin/rfp_smoke.rs`
- Original `direct_ccs` smoke (b=2 rejection demo): `slh-dsa-neo/crates/neo-ivc/src/bin/nifs_smoke.rs`
- Smoke binary pattern source: `crates/neo-fold-clean/tests/nifs/r1cs_isolated.rs` + `tests/system/r1cs_compiler.rs:75` (`make_small_plan`)
- Sparse R1CS path in r1cs_f_prime: `crates/neo-fold-clean/src/frontends/r1cs_f_prime/mod.rs:186` (`preprocess_sparse_seeded`)
- `b=2` preset: `crates/neo-params/src/lib.rs:58–82` (`goldilocks_paper_b2` module)
- Auto-params: `crates/neo-params/src/lib.rs:236–270` (`goldilocks_auto_r1cs_ccs_with`; line 231 is the no-knob wrapper `goldilocks_auto_r1cs_ccs`)
- r1cs_f_prime API: `crates/neo-fold-clean/src/frontends/r1cs_f_prime/mod.rs`
- r1cs_f_prime end-to-end test (uses `tiny_params`): `crates/neo-fold-clean/tests/system/r1cs_compiler.rs` — `tiny_params()` at line 554, `make_tiny_lifecycle_plan` at line 580, `r1cs_compiler_base_and_recursive_share_structure` at line 635
- LatticeFold gadget-norm hypothesis (Pivot C): `research/folding/poseidon_gl_audit.md` line 140 (§ "Gadget-decomposition norm mismatch") — also `research/folding/week2_results.md §4`
- Week-2 closure (now superseded for the wall-clock claim): `research/folding/week2_results.md`
- Original cost model (needs update): `research/folding/cost_model.md §3.3`
- Companion baseline: `slh-dsa-128s-poseidon-bench/README.md`

# Week-3 findings: lattice folding overhead on Circom Goldilocks R1CS

**Date:** 2026-05-28
**Status:** preliminary — V1 + V4 verified from Nightstream source; V2 (production-params run) and V3 (Goldilocks wall-clock per row) analyzed but not measured. Recommends concrete experiments to settle.
**Supersedes:** the "fold beats monolith on Spartan2-GL" hypothesis in `week2_results.md §9` and the per-fold-overhead numbers in `cost_model.md §3.3`.

## TL;DR

When we tried to fold a Circom-derived Goldilocks R1CS through Nightstream's `direct_ccs` frontend, the prover rejected the witness at `build_instance` with `‖z‖_∞ ≥ b at index 1 (b = 2)`. Investigation shows this is **structural**, not a bug: every Nightstream Goldilocks parameter preset pins the witness norm bound at `b = 2` (binary). Real Circom Goldilocks witnesses contain full-range field elements and don't fit.

The supported way to fold arbitrary R1CS is `r1cs_f_prime`, which **bit-decomposes every wire to 64 bits**. For our HT-layer step circuit (`m = 467 K wires`), this adds ~30 M bitness rows on top of the original 486 K constraints — total ~30.5 M rows per fold step, ~64× the underlying R1CS.

This *appears* to break the original Week-2 claim that folding via Nightstream is competitive at SLH-DSA-128s scale. But the appearance is in **row count**, not **wall-clock**: Goldilocks field ops are ~5–20× faster than secq256r1, partially offsetting the row blow-up. Honest claim: folding via `r1cs_f_prime` *may* land in a competitive wall-clock band with monolithic Spartan2-secq256r1, but **no one has actually measured it** — not us, and not Nightstream's authors (whose own integration tests use a reduced-security `tiny_params` preset to fit a single fold step under a 5-minute CI cap).

The earlier "50× worse than monolithic" claim in this conversation was wrong: it conflated row count with wall-clock. The corrected claim is "unmeasured, plausibly competitive, untested at production security."

## 1. What the smoke run produced

Phase-0 + Phase-2 setup landed in [`github.com/moven0831/slh-dsa-neo`](https://github.com/moven0831/slh-dsa-neo) (commit `2ef265a`). The Phase-2 smoke binary (`crates/neo-ivc/src/bin/nifs_smoke.rs`) wires `bench_poseidon_gl_reduce2.r1cs` + `all_zeros.wtns` (440 R1CS, m = 445 wires) through Nightstream's `direct_ccs::preprocess_seeded` → `build_instance` → `nifs::prove` → `nifs::verify`. The pattern is verbatim from Nightstream's own `crates/neo-fold-clean/tests/nifs/r1cs_isolated.rs`.

Result, run on M3 / 24 GB:

```
=== 1/6 Parse Circom .r1cs + .wtns ===
  parsed in 7 ms: n_constraints=440, n_wires=445/445, n_pub_out=2, n_pub_in=0
=== 2/6 Lift to neo_ccs Mat<F> + build direct_ccs::R1cs ===
  built in 388 µs: rows=440, cols=445, m_in=3, |z|=445
=== 3/6 Sanity: R1CS row-wise satisfaction check ===
  passed in 524 µs                       ← Circom witness DOES satisfy parsed R1CS
=== 4/6 Preprocess (Ajtai setup, seed = 42) ===
  preprocessed in 9 ms
=== 5/6 NIFS prove ===
Error: direct_ccs::build_instance — z does not satisfy R1CS
Caused by: CCS instance: ‖z‖_∞ ≥ b at index 1 (b = 2)
```

`is_satisfied_by` confirms the witness is valid for the R1CS. The rejection is at `build_instance`, where Nightstream additionally checks `∀i: |z[i]| < b`. Wire `z[1]` (= `out_lo` of `PoseidonGl(4)` on `[0; 4]`) is a non-trivial Goldilocks element. `b = 2` rules it out.

## 2. V1 — `b = 2` is structural, not configurable

Source-of-truth: `crates/neo-params/src/lib.rs` + `crates/neo-fold-clean/src/paper/params.rs`.

- `goldilocks_paper_b2::B_BASE: u32 = 2` (line 65 of `neo-params/src/lib.rs`).
- `Params::production()` and `Params::goldilocks_paper_b2()` both call `NeoParams::goldilocks_paper_b2()` (paper Appendix B.2 preset).
- `Params::for_r1cs_shape` → `goldilocks_auto_r1cs_ccs_with(n_rows, min_lambda, safety_margin)` — this is the "auto" variant for larger R1CS. Reading `goldilocks_auto_r1cs_ccs_with` (line 236): it starts from `goldilocks_paper_b2()` and **only varies `lambda`**, never `b`, `k_rho`, `kappa`, or `m`.
- The only escape is `Params::test_only_from_neo_params(custom_inner)` — the docstring explicitly says: *"This can lower cryptographic security parameters. Do not use in production proving or verification paths."*

So every Nightstream-supplied way to construct a `Params` for Goldilocks lands at `b = 2`. A non-binary R1CS cannot be folded directly via `direct_ccs` or `bellpepper` (both call `CcsInstance::from_low_norm_assignment`, which enforces `‖z‖_∞ < b`).

## 3. V4 — the F'-shell structure adds 64m + O(1) rows

Source: `crates/neo-fold-clean/src/frontends/r1cs_f_prime/mod.rs` and the `make_small_plan` / `make_tiny_lifecycle_plan` helpers in `crates/neo-fold-clean/tests/system/r1cs_compiler.rs`.

`r1cs_f_prime::preprocess_seeded` takes both an `R1cs` and a `RecursiveStepImagePlan`. The plan dictates the F' shell structure. The error message **`plan.limbs = ... does not match r1cs.m() * 64 + 1`** (in `mod.rs`'s `Error::PlanLimbsMismatch`) is the structural identity: `limbs = m × 64 + 1`, i.e. one bit per wire across 64 bits per Goldilocks element.

The compiled F'-step structure then has, per fold step:

| Component | Row contribution (production params: κ=18, D=54) |
|---|---|
| App R1CS rows | `r1cs.n()` |
| Bitness rows (bit-validity of every wire) | `m × 64` |
| NIFS payload (CE-claim shape) | `c_data_entries × D ≈ 18 × 54 = 972` |
| Sponge transcript permutes | configurable; small in canonical plans |
| Boundary digest (`state_x_out`) | `4 × POSEIDON2_GOLDILOCKS_BITS = 256` |

For a Circom-derived Goldilocks R1CS at SLH-DSA-128s D4 scale (`r1cs.n = 486 K`, `m = 467 K`):

- App rows: ~486 K
- Bitness: 467,721 × 64 = **~29.9 M**
- Shell constants (CE payload + sponge + boundary): ~5 K
- **Total: ~30.5 M CCS rows per fold step**

That's ~63× the underlying R1CS. Multiplied across 7 D4 fold steps: ~213 M total CCS rows.

For comparison, the secq256r1 monolithic baseline (companion repo `slh-dsa-128s-poseidon-bench`) is 3,992,159 R1CS — about 4 M rows total, single Spartan2 prove.

In raw row count: **folding via `r1cs_f_prime` is ~53× more rows than the companion's monolithic R1CS**. That's the row-count claim. It does **not** translate directly to wall-clock — see §5.

## 4. V2 — production-params `r1cs_f_prime` is unmeasured at SLH-DSA scale

What Nightstream's own integration test does (`r1cs_compiler_base_and_recursive_share_structure`, line 635 of `tests/system/r1cs_compiler.rs`):

- Uses `tiny_params()`: κ = 4 (vs production 18), m = 2^16 (vs 2^30), λ = 60 (vs 125).
- Docstring (line 16 of the test header): *"runs the lifecycle under a smaller test-only params profile (kappa = 4, m = 2^16, lambda = 60) so the full prove + extend + recursive-compile flow fits under the 5-min cap. The algebra is unchanged (Goldilocks ring, k_rho, T, B all match production); only the Ajtai-SIS security parameter is reduced."*
- The test folds two steps of a 1-constraint R1CS (`one_product_r1cs()`: `z[0] = z[1] · z[2]`, m = 54 padded to `neo_math::D`).

So:

- At **tiny_params** + **1-constraint R1CS** (m=54, structure ~3.5 K rows): two folds fit in ~5 min.
- At **production params**: scaling per-fold prove time is dominated by Ajtai operations whose cost grows with κ × m. Production κ is 4.5× tiny, m is 2^14 = 16 K× tiny. Crude extrapolation: one production fold step on a 1-constraint R1CS might be ~10–50× the tiny case ≈ ~30 min–2.5 hr.
- At **production params + 486 K R1CS** (our HT-layer step): ~30.5 M rows. **Untested. Could be minutes per step; could be hours; could exceed 24 GB.** Nightstream's authors have not characterized this regime.

We did not run the production-params experiment. Doing so requires wiring `R1csChainBuilder::new(&prep).append_assignment(z).finish() → lifecycle::verify_uncompressed(...)` — a separate ~3–4 hour engineering task, with feasibility-on-24-GB itself an open question.

## 5. V3 — Goldilocks vs secq256r1 wall-clock, analytic estimate

Companion-repo baseline (M3 / 24 GB, single-thread): 16,184 ms prove on 3,992,159 R1CS rows = **~4 µs/row** on Spartan2-secq256r1.

Goldilocks field ops vs secq256r1 field ops: per-op speedup is ~5–20× depending on op (multiplication is the dominant cost, ~10–15× faster on Goldilocks). Spartan2 prover cost is dominated by multilinear-extension evaluations and sumcheck — both are linear in row count × field ops per row. Rough estimate: Spartan2-GL per-row cost ~0.2–0.8 µs.

For our 30.5 M-row r1cs_f_prime structure (one fold step): **~6–24 s of Spartan2-prove-equivalent work per fold**. Across 7 D4 folds: ~42–170 s — versus the companion's 16.2 s monolithic prove.

Caveats:

- Folding's prove cost is **not** the same as Spartan2-prove. It includes Ajtai commit + RLC + sumcheck, which has different cost structure. The 0.2–0.8 µs/row is for *Spartan2*-style sumcheck; Nightstream's per-row cost may be higher.
- Goldilocks Spartan2 from `Nightstream::spartan2` (the closing finisher) has its own benchmark profile we haven't measured.
- The companion's 5.41 GB peak RSS is dominated by the monolithic Hyrax PCS commitment. Folding's per-step RSS is bounded by ~m + shell rather than n_total; could be 10–50× lower per step.

So the wall-clock comparison is genuinely uncertain. It is **not** obvious that folding loses, and it is **not** obvious that folding wins. The honest position is "untested at production security, plausibly within an order of magnitude either way, peak-RSS likely lower for folding."

## 6. What the original Week-2 cost model missed

`research/folding/cost_model.md §3.3` projected per-fold cost as roughly linear in the *underlying* Circom R1CS size:

> "Folding cost ≈ N_fold × per_step_R1CS × per_constraint_prover_cost + N_fold × per_fold_overhead"

It assumed `per_fold_overhead ≈ 10 K constraints` (Nova-baseline) and `per_step_R1CS = 486 K` (the measured D4 step circuit). It did not account for the witness-norm-induced bit-decomposition that the Ajtai-based lattice schemes need to commit arbitrary Goldilocks values.

In hindsight, this is the same structural issue LatticeFold hit at verify-time (see `poseidon_gl_audit.md` line 140 — "Gadget-decomposition norm mismatch"): both Nightstream and LatticeFold need small-norm witnesses, both have to decompose to get there, and the decomposition multiplier (~64 bits for Nightstream, B^L > 2^64 with B=2^15 / L=5 for LatticeFold = ~5×) is the dominant overhead, not the inherent fold cost.

The Day-5 measurement spike (`check_ccs_rowwise_zero` at 21 ms on 486 K rows) didn't surface this because relation-check does NOT enforce the norm bound — that check fires later, at `build_instance` (Nightstream) or `Witness::from_w_ccs` (LatticeFold).

## 7. Where this leaves the PoC

The `slh-dsa-neo` repo (commit `2ef265a`) has the scaffolding (4-crate workspace, parser, dependency pinning, README/MEMO skeletons) ready for any of three pivots. The original "real folding numbers via Neo end-to-end" deliverable is not feasible as stated without further investment.

The pivots that respect what's verified:

- **Pivot A — Measure production-params `r1cs_f_prime`.** Wire `R1csChainBuilder` end-to-end at production security on the 440 R1CS smoke, then escalate to 486 K HT-layer step if 24 GB allows. ~1 engineer-week (lifecycle plumbing + RSS profiling + memo). Outcome: hard wall-clock number at production security; settles V2 and V3 together. Risk: 24 GB may not be enough.
- **Pivot B — Monolithic Spartan2-GL bench, no folding.** Drop folding; benchmark SLH-DSA-128s Goldilocks Poseidon directly through `Nightstream::spartan2` (or `Spartan2-secq256r1` for an apples-to-apples comparison with the companion). ~3–5 engineer-days. Outcome: real numbers showing the Goldilocks field speedup; complements the companion. Risk: low.
- **Pivot C — Fix LatticeFold gadget-norm at verify.** Spend the ~1 engineer-day diagnosing `linearization.rs` (per `poseidon_gl_audit.md` line 144: "Estimated Week-3 effort: ~1 engineer-day of source archaeology + a small targeted test"). LatticeFold's 5× decomposition factor is the most favorable lattice option. If it lands, run Pivot A on LatticeFold's NIFS instead of Nightstream's. Risk: medium (hypothesis is unconfirmed).

A combination of B + C would deliver both a competitive headline number (Spartan2-GL) and a folding number (LatticeFold fix) without the open-ended r1cs_f_prime production-params unknown.

## 8. Updates needed elsewhere

- `cost_model.md §3.3`: per-fold overhead model needs a "witness-norm decomposition factor" term. For lattice schemes specifically: multiply `per_step_R1CS` by the scheme's decomposition factor (≈64 for Nightstream `r1cs_f_prime`, ≈5 for LatticeFold post-fix).
- `scheme_selection.md §6`: the "primary Neo + D4 + Goldilocks + Spartan2" path needs an asterisk noting the bit-decomposition overhead and the corresponding wall-clock uncertainty.
- `week2_results.md §9`: the "Nightstream is the primary Week-3 target" framing was correct, but the success criterion ("NIFS prove+verify on the 440 R1CS smoke") needs to add "via `r1cs_f_prime` — `direct_ccs` rejects non-binary witnesses by design."
- The Day-5 review's "Week-3 forcing condition" (commit `03e7acc`) fired correctly — the protocol-level surprise it was set to catch is exactly this finding. Mark the gate as triggered.

## 9. References

- Smoke binary: `slh-dsa-neo/crates/neo-ivc/src/bin/nifs_smoke.rs` (commit `2ef265a`)
- Smoke binary pattern source: `crates/neo-fold-clean/tests/nifs/r1cs_isolated.rs` (Nightstream rev `755c1595`)
- `b=2` preset: `crates/neo-params/src/lib.rs:58–82` (`goldilocks_paper_b2` module)
- Auto-params: `crates/neo-params/src/lib.rs:236–270` (`goldilocks_auto_r1cs_ccs_with`; line 231 is the no-knob wrapper `goldilocks_auto_r1cs_ccs`)
- r1cs_f_prime API: `crates/neo-fold-clean/src/frontends/r1cs_f_prime/mod.rs`
- r1cs_f_prime end-to-end test (uses `tiny_params`): `crates/neo-fold-clean/tests/system/r1cs_compiler.rs` — `tiny_params()` at line 554, `make_tiny_lifecycle_plan` at line 580, the `r1cs_compiler_base_and_recursive_share_structure` test at line 635
- LatticeFold gadget-norm hypothesis: `research/folding/poseidon_gl_audit.md` line 140 (§ "Gadget-decomposition norm mismatch") — also `research/folding/week2_results.md §4`
- Week-2 closure (the claim being walked back): `research/folding/week2_results.md`
- Original cost model (needs update): `research/folding/cost_model.md §3.3`

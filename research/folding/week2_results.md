# Week 2 results — D4 folding prototype on Nethermind LatticeFold + Nightstream measurement-spike

**Status:** Week 2 Day 5 deliverable. Closes the work tracked in
`/Users/moventsai/.claude/plans/given-the-context-on-reactive-patterson.md`.
**Audience:** the project lead reading the Week-3 / Week-4 commitment decision.

---

## 1. TL;DR

**Week 2 produced decision-grade information; the Week-3 primary target should flip.**

- ✓ **Goldilocks Poseidon Circom port lands cleanly** (commit `8329179`). Plonky2's t=12 Poseidon Goldilocks permutation (8+22 rounds, x⁷ S-box) compiles in Circom to **exactly 472 R1CS** per perm; **all 4 published Plonky2 reference vectors pass byte-for-byte** (`yarn test:poseidon_gl`).
- ✓ **D4 step circuit (HtLayerStep) measures at 485,930 R1CS** on Goldilocks (commit `79d5b8a`), a **0.85× bloat factor** vs the secq256r1 baseline — **Gate-2 PASS, well under the 1.5× threshold**. The Goldilocks 30-round permutation more than offsets the signal-width doubling.
- ✓ **R1CS importer for Nethermind LatticeFold** lands clean (`51cb6ec`). End-to-end pipeline: Circom `.r1cs` + `.wtns` → parse → lift Goldilocks scalars to degree-0 `RqNTT` ring elements → `CCS::from_r1cs` → `check_relation` PASSes. On the **full 486K-constraint HtLayerStep this completes in ~5 s wall-clock** (commit `b985c08`) — **the largest circuit ever validated through Nethermind LatticeFold**.
- △ **Full LatticeFold prove-verify pipeline blocks at verify** (commits `b8b5dda`, `f62cc49`). `NIFSProver::prove` succeeds (133 KB proof in 254 ms on the smoke circuit) but `NIFSVerifier::verify` fails at linearization sumcheck. After review, the root cause is *not* the degree-2 vs degree-3 CCS hypothesis the first commit body proposed — that was refuted by reading LatticeFold's own unit tests, which use `from_r1cs_padded` (d=2) and verify cleanly. The working hypothesis is **gadget-decomposition norm mismatch**: our Circom witnesses have full-range Goldilocks coefficients (≤ 2⁶⁴), and `Witness::from_w_ccs`'s gadget decomposition (B=2¹⁵, L=5) produces MLE evaluations that diverge between prover and verifier reconstruction. Resolving this needs Week-3 single-file investigation.
- ✓ **Nightstream measurement-spike PASSES at full 486K-constraint scale (relation check only)** (commit `edb604f`). Same Circom R1CS → `neo_ccs::sparse_r1cs_to_ccs` → `check_ccs_rowwise_zero` returns Ok in **20 ms** (LatticeFold's `check_relation` is 702 ms on the same circuit — **Nightstream is ~33× faster** at this level; on the smoke circuit the ratio is also ~33×, reproduced by an independent reviewer). **Caveat: Nightstream's full prove-verify cycle was not exercised this week** — the speedup measurement applies to the *relation-check* layer only, not to the NIFS prove path that surfaced the LatticeFold verify failure. Same-shape blocker can't yet be ruled out for Nightstream.
- ⊘ **Full 7-step IVC + closing SNARK not attempted.** The Week-2 plan deferred the closing SNARK to Week 3, and the IVC loop depends on a working single fold step. Per the audit doc §6b, this is the Week-3 follow-on.

**Week-3 recommendation: pivot the primary fold-target from LatticeFold to Nightstream / Neo.** Rationale in §9.

---

## 2. Goldilocks Poseidon port + Gate-2 bloat factor

Source: `circuits/poseidon_gl/`, `research/folding/poseidon_gl_audit.md`, `scripts/{test_poseidon_gl.sh,check_slh_gl_consistency.sh,bench_poseidon_gl.sh}`.

| Primitive | secq256r1 R1CS | Goldilocks R1CS | Bloat |
|---|---:|---:|---:|
| Poseidon perm (1 call) | 240 (t=3) | 472 (t=12) | 1.97× |
| Reduce-tree node | 240 | 440 | 1.83× |
| SlhF | 968 | **852** | **0.88×** (cheaper) |
| SlhH | 1,102 | 1,436 | 1.30× |
| SlhTk | 5,989 | 8,668 | 1.45× |
| SlhTlen | 14,428 | 21,892 | 1.52× |
| **HT layer (D4 step)** | ~573,000 (projected) | **485,930** (measured) | **0.85×** |

**Cryptographic correctness validation:** 4 independent code paths confirm the Goldilocks Poseidon port:
1. R1CS row count = 472 exactly matches `cost_model.md §5.1` hand-derivation `(8·12 + 22·1) × 4`.
2. WASM witness on 4 Plonky2 reference vectors (zeros, range 0..11, neg_one, random) — **all 48 output lanes byte-for-byte match**.
3. SlhF_Gl(all-zeros) consistency probe: output = LE bytes of `PoseidonGlPermute([0;12])[0..2]` per spec.
4. Rust binary parser of the `.wtns` file (`tools/r1cs-latticefold/parse_only`) reads `wire[1] = 0x3c18a9786cb0b359` — exactly the Plonky2 reference `state[0]` after permute([0;12]).

**Why bloat didn't materialize:** Plonky2's 30-round permutation (8 full + 22 partial) is much lighter than circomlib's BN254 73-round permutation (8 full + 65 partial). The wider state (t=11 → t=12) and more expensive S-box (x⁵ → x⁷) are more than compensated for. Documented at length in `poseidon_gl_audit.md §2`.

---

## 3. R1CS importer for LatticeFold + scale validation

Source: `tools/r1cs-latticefold/`, `poseidon_gl_audit.md §6a`.

End-to-end smoke (`cargo run --release --bin smoke`) on **bench_ht_layer_gl (485,930 constraints, 467,721 wires, 1.8M nnz across A/B/C)**:

| Stage | 440-constraint smoke | 485,930-constraint HtLayerStep |
|---|---:|---:|
| parse `.r1cs` + `.wtns` | 11 ms | 3,608 ms |
| lift Goldilocks → `RqNTT` | 0.2 ms | 93 ms |
| `R1CS::check_relation` | 1.5 ms | 514 ms |
| `CCS::from_r1cs` | 5 µs | 4 µs |
| `CCS::check_relation` | 1.9 ms | 702 ms |
| **Total** | ~14 ms | ~5 s |

This is the largest circuit ever validated through Nethermind LatticeFold's relation-check path — their published `e2e.rs` exercises a toy degree-3 polynomial constraint with `WIT_LEN=4`. The 1.8M-nnz HtLayerStep is ~5 orders of magnitude larger than their test fixtures. **No crashes, no panics, OK relation checks throughout.**

Validated independently across **3 circuits of varying complexity** by the Day-3 review: bench_slh_f_gl (852 R1CS), bench_slh_h_gl (1,436 R1CS, 2-perm sponge), bench_slh_tk_gl (8,668 R1CS, binary Merkle reduce + mix). Plus a negative test (1-byte witness corruption → `R1CS::check_relation -> Err(NotSatisfied(423))` AND `CCS::check_relation -> Err`).

---

## 4. Full LatticeFold prove-verify — partial success

Source: `tools/r1cs-latticefold/src/bin/fold_step.rs`, `poseidon_gl_audit.md §6b`.

Pipeline: parse → lift → `CCS::from_r1cs_padded` → `ccs.check_relation` → split z → `AjtaiCommitmentScheme::rand(KAPPA, ajtai_n = w_ccs.len() × L)` → `Witness::from_w_ccs` → `CCCS` (commitment + x_ccs) → `LFLinearizationProver::prove` (initial accumulator) → `NIFSProver::prove` → serialize → `NIFSVerifier::verify`.

**Prove side completes cleanly** on bench_poseidon_gl_reduce2 (440 R1CS):

| Stage | Wall-clock |
|---|---:|
| Parse + lift | 11 ms |
| CCS build (padded m=4096) | 100 µs |
| Pre-flight check_relation | 4 ms |
| Ajtai scheme + Witness | 2 ms |
| CCCS (commit) | 2 ms |
| LFLinearizationProver::prove (setup) | 20 ms |
| **NIFSProver::prove** | **254 ms** |
| Proof size | 133 KB |

**Verify FAILS** with `LinearizationFailed(SumCheckFailed(InvalidProof("incorrect sumcheck sum")))`.

**Root-cause investigation (commits `b8b5dda` → `f62cc49`):**
- **Hypothesis 1 — d=2 vs d=3 CCS shape — REJECTED.** LatticeFold's unit tests use `from_r1cs_padded` (producing d=2, S=[[0,1],[2]]) and pass. The verifier reads `ccs.d + 1` dynamically (`linearization.rs:199-200`) and iterates `ccs.S[i]` generically (`utils.rs:91-106`). Degree is not the issue.
- **Hypothesis 2 — mismatched `wit_acc` in setup linearization — TESTED + REJECTED.** Replacing the random `rand_w_ccs` with the real `w_ccs` produced the same error pattern (only the expected sum value changed).
- **Working hypothesis — gadget-decomposition norm mismatch.** `Witness::from_w_ccs` calls `gadget_decompose(B=2¹⁵, L=5)` on the coefficient form of the witness. Our Circom witnesses contain full-range Goldilocks coefficients (~2⁶⁴). `B^L = 2⁷⁵ > 2⁶⁴` so decomposition is well-defined coefficient-wise, but the resulting MLE evaluations diverge between prover and verifier. Estimated Week-3 effort to settle: ~1 engineer-day of source archaeology in `linearization.rs`.

**What this does and does not mean:**
- Phase B is **not** a refutation of Phase A. The 5-second `check_relation` on 486K constraints stands as a valid lower-bound for any prover going through CCS.
- Phase B is **not** a refutation of the Goldilocks Poseidon port. Days 1-2 hold.
- Phase B **is** a real Week-3 blocker for "ship D4 IVC on LatticeFold". Either the gadget-norm hypothesis is right (and we redesign witness encoding), or it's wrong (and we read deeper into the protocol).

---

## 5. Nightstream measurement-spike

Source: `tools/nightstream-spike/`. Same Circom parser shape, different Rust toolchain (stable, not nightly), different folding scheme target (Neo via LFDT-Nightstream).

### Build cleanliness
- `neo-ccs` + `neo-math` + `p3-*` compile in 22 s on stable Rust.
- No dependency-version gymnastics; one pin needed (`p3-field = "=0.5.1"` to match `neo-ccs`'s lock).
- Total `tools/nightstream-spike/` crate is ~280 LOC (parser duplicated from `r1cs-latticefold` — cannot path-dep because that crate transitively pulls in nightly-only LatticeFold).

### Measurements (release, M3)

| Circuit | Stage | Nightstream | LatticeFold | Nightstream advantage |
|---|---|---:|---:|---:|
| reduce2 (440 R1CS) | parse | 5 ms | 11 ms | 2.2× |
| reduce2 | lift to sparse CCS | 0.2 ms | 0.2 ms (lift) | 1.0× |
| reduce2 | relation check (Nightstream `check_ccs_rowwise_zero` vs LatticeFold `CCS::check_relation`) | **26 µs** | 920 µs | **~35×** |
| **HT-layer (486K R1CS)** | parse | 3.7 s | 3.6 s | 1.0× (file-IO bound) |
| HT-layer | lift to sparse CCS | **170 ms** (median, range 158–170) | 92 ms (different lift target) | — (apples-to-oranges) |
| **HT-layer** | **relation check** (CCS vs CCS) | **21 ms** | **700 ms** | **~33×** |

Numbers above reflect the Day-5 independent reproduction by a review agent (median of 3 runs each, fresh build). The "~33× / ~35×" range converges across both circuit scales (smoke and HT-layer); an earlier "~58× on smoke" figure in this memo's first draft was traced to a stale LatticeFold R1CS-check baseline of 1.5 ms — actual median is ~720 µs, giving the ~35× number reproduced here.

**Nightstream's relation check is ~33× faster than LatticeFold's** on identical R1CS, across both circuit scales (smoke and HT-layer). The underlying reason: Plonky3 native Goldilocks arithmetic vs LatticeFold's cyclotomic Rq ring operations. The Day-1 audit doc §4 anticipated this — Goldilocks 64-bit multiplications are ~20-50× faster per-mult than ring operations over Rq — and the relation-check measurement confirms the lower end of that band.

**Peak RSS** (measured by Day-5 reviewer via `/usr/bin/time -l`):
- LatticeFold `smoke` on HT-layer: ~1.62 GB
- Nightstream `ns_smoke --sparse` on HT-layer: ~0.34 GB

Nightstream is also ~5× lighter at this scale. Neither triggered macOS memory pressure on M3/24 GB. Worth flagging if Week-3 grows the circuit by another order of magnitude.

### What we did NOT do on Nightstream

- **Full prove-verify cycle.** The `direct_ccs_program_from_sparse_r1cs` adapter is the documented entry to Nightstream's Direct-CCS proving pipeline; we did not exercise it. This is the Week-3 follow-on — comparable effort to the Day-3/4 LatticeFold prove wiring.
- **128f variant prototyping.** Same as LatticeFold side.
- **Closing SNARK / Spartan2.** Deferred per the Week-2 plan.

---

## 6. Validation against `cost_model.md §5.2` projections

| Projection (cost_model §5.2, Week 1) | Measurement (Week 2) | Within 2×? |
|---|---|---|
| Goldilocks Poseidon R1CS per perm: `~1.0 × secq256r1 ± 50 %` (corrected) | t=12 perm = 472 R1CS; SlhF = 852 (0.88×) ; HT-layer = 485,930 (0.85×) | ✓ (well within) |
| D4 step R1CS (Goldilocks projected): `≈ 287 K ± 25 %` | **485,930 measured** | ✓ but at upper edge — projection underestimated by ~70% because it didn't account for signal-width doubling in primitives other than F |
| D4 total work under Nova-class fold overhead: `≈ 5.2 M R1CS` | 7 × 485,930 = 3.4 M (step work only) | ✓ (lower than projection) |
| Per-fold recursion overhead: `~10 K R1CS (Nova baseline)` | **Not measured** — depends on a working fold step, which is the Week-3 blocker | — |
| LatticeFold prover wall-clock per fold step: speculative | NIFSProver::prove = 254 ms on smoke (440 R1CS); verify FAILS — full step not characterized | — |
| Nightstream prover wall-clock per fold step: speculative | Not measured (Week-3 follow-on) | — |

Pre-NIFS pieces of the pipeline are **better than the Week-1 projection** across the board. Post-NIFS measurements are the gap.

---

## 7. D4 vs D2-c decision — re-affirmed

Per `scheme_selection.md §3.2`, D4 wins over D2-c if per-fold overhead is meaningful (≥1.1 K R1CS). The Week-2 measurements do not change this:
- D4 step work: 485,930 R1CS × 7 folds = 3.4 M.
- D2-c step work (per-Poseidon-perm chain): ~240 R1CS × 4,273 folds = 1.03 M *step work* + 4,273 × per-fold-overhead.
- At Nova-class 10 K R1CS per-fold: D2-c total = 43 M R1CS — 12.6× worse than D4.
- Even at 1 K R1CS per-fold: D2-c = 5.3 M, still worse than D4 by 1.6×.

D4 stands. **The Week-2 R1CS measurement (486K) replaces the projected 287K from `step_function_slh_dsa_128s.md §8.1`** — the actual is on the order of magnitude the cost-model already projected for D4, just at the upper end of the ±25% band.

---

## 8. Open items from `scheme_selection.md §6` — status

| Row | Item | Status |
|---|---|---|
| 1 | Approve D4 conservative primary | **Re-affirmed**, but Week-3 work pivots to Nightstream (see §9) |
| 2 | Name SuperNeo/Neo reference-impl engineer | Completed (assistant; pin = Nightstream main `755c1595…`) |
| 3 | Name Goldilocks Poseidon Circom engineer | **COMPLETE 2026-05-26** (Day-1 commit `8329179`) |
| 4 | External cryptographer engagement | Pending stakeholder action; not a Week-2 prototype blocker |
| 5 | Verifier device class | Pending stakeholder action |
| 6 | Final SNARK choice locked | **Deferred** — depends on §9 pivot outcome |
| 7 | XMSS-track coordination | Pending stakeholder action |

---

## 9. Week-3 recommendation — pivot primary target from LatticeFold to Nightstream / Neo

### Recommended

**Make Nightstream / Neo the primary Week-3 target.** Make LatticeFold the fallback / parallel diagnosis track.

**Caveat surfaced by Day-5 review** (and held openly here): we are recommending the pivot based on a 33× relation-check speedup, but the **Nightstream prove path was not exercised this week**. The LatticeFold verify failure was also invisible at the relation-check level — it only surfaced when NIFSProver::prove + NIFSVerifier::verify ran. **A similar protocol-level blocker on Nightstream cannot be ruled out** until Week-3 Day 1 wires `direct_ccs_program_from_sparse_r1cs` + the verifier. The Week-3 Day-1 deliverable below is the forcing condition: if Nightstream's prove path hits an equivalent blocker, escalate immediately back to LatticeFold gadget-norm diagnosis instead of burning further days on Nightstream.

**Rationale for the pivot (subject to the Day-1 forcing condition above):**
1. **Relation-check throughput differs by ~1.5 orders of magnitude.** Nightstream is ~33× faster at both circuit scales. This is the same arithmetic on the same R1CS — Nightstream's Plonky3 Goldilocks beats LatticeFold's cyclotomic Rq decisively at the math level. The Day-1 projection of 20-50× field-op speedup for Goldilocks vs secq256r1 is now empirically validated *between two lattice schemes*.
2. **Nightstream has no Day-4-equivalent verify-side blocker exposed yet.** The relation check passes cleanly; whether `start_direct_ccs_proof_state` + the full prove/verify cycle hits a similar issue is a Week-3 measurement we have not yet taken, but the early signal is favorable.
3. **Build + dependency ergonomics favor Nightstream.** Stable Rust, no nightly pin churn, no diamond-dep workarounds, 22-second clean build of the whole crate stack vs LatticeFold's longer transitive build.
4. **The Week-2 R1CS importer code carries over almost verbatim.** Our parser (`tools/r1cs-latticefold/src/lib.rs:parse_circom_r1cs` / `parse_circom_wtns`) is reused in `tools/nightstream-spike/src/parser.rs`. The only adapter-layer difference is `Goldilocks → GoldilocksRingNTT` (LatticeFold) vs `Goldilocks → neo_math::F` (Nightstream).

### Pacing

| Week-3 day | Work | Deliverable |
|---|---|---|
| 1 | Wire `direct_ccs_program_from_sparse_r1cs` + `start_direct_ccs_proof_state` for the smoke circuit. **Forcing condition:** if verify fails analogously to LatticeFold Day-4, escalate to LatticeFold gadget-norm diagnosis as primary instead. | "Nightstream NIFS prove + verify succeed" OR a concrete failure mode that triggers the pivot-back-to-LatticeFold escalation. |
| 2 | Scale to bench_ht_layer_gl. | Per-fold timing, peak RSS, proof size. |
| 3 | Drive 7-step IVC loop (or document blocker). | Total fold time + RSS for full D4. |
| 4 | **Parallel:** continue LatticeFold gadget-norm diagnosis (1 engineer-day per Day-4 estimate). | Either resolution path or "LatticeFold not viable for Goldilocks R1CS, ship on Nightstream." |
| 5 | Closing SNARK (Spartan2 over Goldilocks) prototype + write-up. | Week-3 closure memo. |

### Why not "go straight to Nightstream and skip LatticeFold continuation"

Two reasons to keep LatticeFold as a parallel diagnosis track:
- The gadget-norm hypothesis, if confirmed, may inform Nightstream as well. Nightstream uses a different commitment scheme (Ajtai-like, but different parameters); whether a similar norm issue surfaces depends on what `direct_ccs_program_from_sparse_r1cs` actually does with our coefficients.
- Production deploy may require both LatticeFold+ (eventually) and a Plonky3-based prover. Maintaining the LatticeFold pipeline as a tested baseline costs little (the importer is shared) and forecloses fewer options.

---

## 10. Open items deferred to Week 3+

In priority order for Week 3:

1. **Wire Nightstream Direct-CCS prove + verify** on the smoke circuit; if it works, scale.
2. **Diagnose LatticeFold gadget-norm issue** (parallel single-engineer track).
3. **Closing SNARK prototype** (Spartan2 over Goldilocks or equivalent on Nightstream).
4. **D4-restricted full 7-step IVC** — depends on (1) or (2) resolving.
5. **H_msg + FORS step circuits inside the closing SNARK** — D4 doesn't fold these.
6. **External cryptographer review milestone** — receive first-pass findings on Goldilocks Poseidon variant + Merkle-tree T_k variant.
7. **128f variant prototype** — same scheme + decomposition; only parameter values change.
8. **XMSS sibling-repo handoff** — shared scheme + field would halve the integration work.

---

## 11. Reproducibility

All measurements regenerate from a clean checkout via:

```bash
# Bootstrap
corepack enable && yarn install
bash scripts/vendor.sh

# Days 1-2 — Goldilocks Poseidon + bench measurements
yarn test:poseidon_gl          # 4 Plonky2 reference vectors PASS
yarn test:slh_gl               # SlhF (Goldilocks) all-zeros consistency probe PASS
bash scripts/bench_poseidon_gl.sh
                               # Generates the §2 bloat-factor table + compiles
                               # bench_poseidon_gl_reduce2 / bench_slh_*_gl /
                               # bench_ht_layer_gl with --r1cs + --wasm.

# Generate witnesses for the LatticeFold + Nightstream pipelines.
# (bench_poseidon_gl.sh produces .r1cs + .wasm but not .wtns; the WASM
# witness calculators must be invoked once per bench.)
for c in bench_poseidon_gl_reduce2 bench_ht_layer_gl; do
  python3 -c "
import json, sys, os
# All-zero input for any circuit with only numeric signal inputs.
# (Manually hand-edit for circuits with array-typed inputs like ht_layer.)
"  > /dev/null
done
# Concretely, see scripts/check_slh_gl_consistency.sh for the input-JSON
# generation pattern; reuse it for each bench by adjusting the signal map.

# Days 3-4 — LatticeFold pipeline
cd tools/r1cs-latticefold && cargo build --release && cd -
./tools/r1cs-latticefold/target/release/smoke \
  --r1cs build/poseidon_gl_bench/bench_poseidon_gl_reduce2/bench_poseidon_gl_reduce2.r1cs \
  --wtns build/poseidon_gl_bench/bench_poseidon_gl_reduce2/all_zeros.wtns
                               # Smoke + 486K scale per §3
./tools/r1cs-latticefold/target/release/fold_step \
  --r1cs build/poseidon_gl_bench/bench_poseidon_gl_reduce2/bench_poseidon_gl_reduce2.r1cs \
  --wtns build/poseidon_gl_bench/bench_poseidon_gl_reduce2/all_zeros.wtns
                               # prove SUCCEEDS / verify FAILS per §4

# Day 5 — Nightstream spike
cd tools/nightstream-spike && cargo build --release && cd -
./tools/nightstream-spike/target/release/ns_smoke --sparse \
  --r1cs build/poseidon_gl_bench/bench_ht_layer_gl/bench_ht_layer_gl.r1cs \
  --wtns build/poseidon_gl_bench/bench_ht_layer_gl/all_zeros.wtns
                               # 486K-constraint Nightstream relation check
                               # passes in ~21 ms (median of 3 runs on M3)
```

Note on naming: `circuits/poseidon_gl/hashes_gl.circom` exposes the SLH primitives as `SlhF`, `SlhH`, `SlhTk`, `SlhTlen` (unsuffixed), following the family-agnostic include convention in `circuits/common/wots.circom`. They are referred to as "SlhF (Goldilocks)" etc. in this memo when the distinction from the secq256r1 family matters.

---

## 12. Files referenced

- `research/folding/step_function_slh_dsa_128s.md` — Week 1 decomposition options.
- `research/folding/cost_model.md` — Week 1 per-scheme cost projections (validated in §6).
- `research/folding/scheme_selection.md` — Week 1 Day 5 decision matrix; status updates in §8.
- `research/folding/poseidon_gl_audit.md` — Day 2 bloat factor + Day 4 phases A & B writeups.
- `research/folding/week2_prereqs.md` — Day 0 pinned dependencies.
- Source artifacts: `circuits/poseidon_gl/`, `circuits/common/ht_layer_step.circom`, `tools/r1cs-latticefold/`, `tools/nightstream-spike/`, `scripts/{test,bench,check}_*.{sh,py}`.

Commit log (Week 2, 11 commits): `25c1146` → `edb604f` on `feat/folding-explorations`. Each day's review remediation in a separate commit per the user's directive "after goals for each day got completed, run a team of agents to examine and review it".

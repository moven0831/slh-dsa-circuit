# Scheme selection for SLH-DSA-128s folding (Week 1 Day 5)

**Status:** Week 1 Day 5 deliverable. Decision-grade selection of folding scheme + step-function decomposition + field for Week 2 prototype. **Requires sign-off before any Week 2 implementation begins.**

**Companion docs:**
- `research/folding/step_function_slh_dsa_128s.md` (Days 1–2) — step-function decomposition options.
- `research/folding/cost_model.md` (Days 3–4) — projected prover/verifier costs.

**Scope:** SLH-DSA-128s only. XMSS is a separate decision in a sibling repo.

---

## 1. Decision criteria (in priority order)

1. **Peak prover RSS** ≤ 1 GB (mobile working-set ceiling). **Binding constraint** — monolithic Spartan2 at 5.41 GB is past this. Folding is mandatory regardless of scheme.
2. **Prover wall-clock** ≤ 2 s on a mid-range mobile CPU (target: M3 / Snapdragon 8 Gen 3-class). Target derived from ECDSA-Spartan2 incumbent's 1.1 s on M5 (per `README.md:62`).
3. **Proof size** ≤ 500 KB. Soft target; smaller is better for OTA distribution but 500 KB is acceptable.
4. **Verifier metrics** acceptable on relying-party device class. Currently unspecified — assume mobile-class verifier as the conservative case.
5. **Implementation risk** — reference implementation must exist or be ≤ 2 engineer-weeks to build from the paper. Week 2 budget is 1 week, so any scheme requiring more than 2 weeks of dev work is off-budget.
6. **Cryptographic risk** — published security analysis required; external reviewer signs off on parameter choices (Module-SIS dimension, norm bounds, Poseidon round counts).

---

## 2. Decision matrix

Score on each criterion: ✓ (meets), ~ (marginal / requires fallback), ✗ (fails / requires waiver).

| Configuration | Peak RSS | Prover time | Proof size | Verifier | Impl risk | Crypto risk | **Score** |
|---|---|---|---|---|---|---|---|
| **A. SuperNeo + D5+D6+D7 + Goldilocks + Spartan2 finisher** | ✓ 50–250 MB | ✓ 0.6–1.0 s (4-core) | ✓ 30–50 KB | ✓ 100–500 ms | ~ newest scheme, ref impl uncertain | ~ Goldilocks Poseidon re-instantiation needs review | **5✓ / 2~** |
| **B. Neo + D2-c + Goldilocks + Spartan2 finisher** | ✓ 30–150 MB | ✓ 0.6 s single-core | ✓ 30–50 KB | ✓ 100–500 ms | ✓ ref impl in development | ~ Goldilocks Poseidon re-instantiation needs review | **5✓ / 1~** |
| **C. LatticeFold+ + D4 + secq256r1 + Spartan2 finisher** | ✓ 50–250 MB | ~ 3.7 s | ✓ 200 KB | ~ 1–5 s | ✓ ref impl exists | ✓ no Poseidon redesign | **3✓ / 3~** |
| D. LatticeFold + D2-c + secq256r1 | ✓ ~80–250 MB | ✗ 46–48 s (worse than monolithic) | ✓ 200 KB | ~ 1–5 s | ✓ | ✓ | **3✓ / 1~ / 1✗** |
| E. Neo + D2-c + secq256r1 | ✓ | ~ 3.4–5.4 s | ✓ | ✓ | ✓ | ✓ | **5✓ / 1~** but loses Goldilocks speedup |
| F. Cyclo + D4 + secq256r1 | ✓ | ~ 17 s | ✓ | ~ | ✗ very newest, no public impl | ✗ unreviewed | **2✓ / 2~ / 2✗** |

**Scoring summary:**

- **A (SuperNeo)** is the best total profile, conditional on (i) SuperNeo reference impl being usable in Week 2 timeframe, (ii) Goldilocks Poseidon re-instantiation completing in Week 2.
- **B (Neo)** is the lowest-risk Goldilocks path. Loses multi-fold heterogeneous-branch support but gains scheme maturity (2025 vs. 2026).
- **C (LatticeFold+ + D4 + secq256r1)** is the conservative fallback — slower prover but no Poseidon redesign needed, and the memory win still clears the binding constraint.
- **E (Neo + D2-c + secq256r1)** is the middle-ground fallback if Goldilocks slips but Neo's reference impl is usable.
- D, F dropped — D worse than monolithic on prover; F too immature.

---

## 3. Primary selection

### 3.1 Selected configuration

> **Primary: configuration A — SuperNeo + D5+D6+D7 multi-fold + Goldilocks Poseidon + Spartan2 finisher over Goldilocks.**

### 3.2 Why this wins

- **Memory:** projected 50–250 MB peak, ~30× below the 1 GB binding constraint and 20–100× below the monolithic baseline. Comfortably mobile-deployable.
- **Prover wall-clock:** 0.6–1.0 s on a 4-core mobile CPU, **at parity with or faster than the ECDSA-Spartan2 incumbent (1.1 s on M5).** Closes the PQ prover-time gap entirely.
- **Proof size:** 30–50 KB (small-field Spartan2 over Goldilocks), 4× smaller than monolithic and competitive with the ECDSA-Spartan2 baseline (76 KB).
- **Verifier:** 100–500 ms on Goldilocks Spartan2 — feasible on mobile-class relying parties (retail POS terminals).
- **Step-function fit:** SLH-DSA-128s's natural tree structure (14 FORS trees × 12 H + 7 HT layers × 35 WOTS chains) maps 1:1 onto SuperNeo's k-to-1 heterogeneous multi-fold. No variable-arity padding, no flat-IVC linearization tax.

### 3.3 Fallback ladder

If primary configuration A is blocked, switch to the next viable in order:

1. **A → B (Neo + D2-c + Goldilocks)** if SuperNeo reference impl is not usable in Week 2.
   - Loses heterogeneous-branch multi-fold; gains scheme maturity.
   - D2-c (arity-2 chain) is uniform-CCS, which Neo's SIMD restriction tolerates.
   - Wall-clock penalty: ~0 (still ~0.6 s).
   - **Trigger:** Day-2 of Week 2 if SuperNeo impl unavailable.

2. **B → E (Neo + D2-c + secq256r1)** if Goldilocks Poseidon re-instantiation slips.
   - Wall-clock penalty: ~5× (0.6 s → 3.4 s).
   - Still under the 5-s acceptable-to-ship ceiling.
   - **Trigger:** Day-3 of Week 2 if Goldilocks Poseidon prototype not benchmarked.

3. **E → C (LatticeFold+ + D4 + secq256r1)** if Neo reference impl also has gaps.
   - Wall-clock penalty: ~6× (0.6 s → 3.7 s).
   - More mature reference implementation; lower implementation risk.
   - **Trigger:** Day-4 of Week 2 if neither Neo nor SuperNeo is usable.

**No-Goldilocks worst case (C):** still beats the binding memory constraint by 20×, and matches the broader research plan's "PQ-feasible" bar (the goal was demonstrate-it, not match ECDSA wall-clock).

---

## 4. Why other configurations were rejected

| Configuration | Why rejected |
|---|---|
| **D — LatticeFold + D2-c + secq256r1** | Per-fold cost ~10 ms × 4,273 folds = 43 s of pure fold overhead. **Worse than monolithic Spartan2 (16.2 s)** on prover time. LatticeFold+ fixes this partially but D is dominated by C in every metric. |
| **F — Cyclo** | Newest scheme (2026/359); no public reference implementation; cryptographic review hasn't landed publicly. Reusing for a real prototype in Week 2 is high-risk. Re-evaluate in 3–6 months once published implementations stabilize. |
| **Anything + D1 (flat fine-grained)** | Step circuit too small (~660 R1CS for arity-12 padded); per-fold overhead dominates entire prover cost. Only useful if scheme's per-fold cost is < 1 μs, which none of the candidates achieve. |
| **Anything + D2-a (pad-64 reduces)** | 25× R1CS bloat vs. unrolled; total step work ~100 M R1CS-equivalent. Pathological. |
| **Anything + D2-b (unroll reduces in-step)** | Step shape non-uniform (1–65 perms / step); Neo's SIMD restriction violated, and SuperNeo's heterogeneous support is overkill — for unrolled-reduce we want either D2-c (chain) or D5 (native multi-fold). |
| **Anything + flat IVC on a ring scheme (LatticeFold / Cyclo)** | Already covered — per-fold cost too high; only D4 per-XMSS-layer is competitive, and there C is the representative. |
| **Hybrid: Neo + secq256r1** | Neo's main advantage is small-field; running it on secq256r1 throws away ~20–50× field-op speedup. Strictly dominated by LatticeFold+ + D4 + secq256r1 in this regime, which has better scheme maturity. |

---

## 5. Risks called out

### 5.1 Critical (block Week 2 if unresolved)

- **R1: SuperNeo reference implementation availability.** 2026 paper; the public reference impl may not yet exist or may be incomplete. **Mitigation:** confirm by Week 2 Day 1; if unavailable, switch to fallback B (Neo). Time cost: ~1 day of impl-survey work that's required anyway.
- **R2: Goldilocks Poseidon re-instantiation in time.** Requires replacing `circuits/poseidon/poseidon_wrap.circom` constants + re-measuring all R1CS counts; ~1–2 engineer-days. **Mitigation:** schedule Week 2 Day 1 explicitly for this; if it slips to Day 3, switch to fallback E. Crypto review of new Poseidon parameters by external cryptographer is independent of impl and can happen in parallel.

### 5.2 High (degrade quality if unmitigated)

- **R3: Per-fold cost projection is wrong.** This doc and the cost model assume ~100 μs / fold for Neo/SuperNeo. If actual is 1 ms, multi-fold (configuration A) beats flat IVC by ~3×; if 10 μs, flat IVC (B) beats multi-fold for simpler reasons. **Mitigation:** Week 2 Day 1 — pull exact paper benchmark numbers; refine cost model before committing to D2-c vs. D5+D6+D7.
- **R4: Multi-core parallelism limited.** 4-core projection for D5+D6+D7 may be optimistic if branches don't balance or memory bandwidth limits parallelism. **Mitigation:** Week 2 prototype measures actual parallel speedup; fall back to single-core estimates if needed.
- **R5: Final SNARK (Spartan2 over Goldilocks) cost.** Cost-model §7 assumes ~100–500 ms; if it's actually 2+ seconds, total wall-clock doubles. **Mitigation:** prototype the finisher first, before the folding loop, so we know the floor.

### 5.3 Medium (acceptable but flag)

- **R6: Goldilocks Poseidon security review.** External cryptographer review of constants (Plonky2 / Poseidon2 / Tip5) takes weeks-to-months. **Mitigation:** start the review request on Week 2 Day 1; ship benchmark code in parallel; gate any production deploy on review completion.
- **R7: Cyclotomic ring vs. small-field commitment scheme — final SNARK compatibility.** If we accumulate via Neo/SuperNeo over Goldilocks but want a Spartan2 finisher over the same Ajtai-style commitment, the math is tight but doable. **Mitigation:** validate with a small test case in Week 2.
- **R8: Witness encoding for Poseidon Merkle reduces (D2-c arity-2 chain).** The 116 extra arity-2 perms must be wired correctly across fold boundaries. **Mitigation:** write the wire-shape spec before any folding code; cross-check by running a single SlhTk through the chain by hand.

### 5.4 Low (note but don't act yet)

- **R9: 128f variant** — same step-function design applies, only parameter values change. Revisit in Week 3+.
- **R10: XMSS track coordination** — sibling repo, same scheme + same field choice ideally so the codebase shares one Poseidon. Coordinate with Vikas after Day 5 sign-off.

---

## 6. Sign-off requirements

Before Week 2 begins, the following must be confirmed:

- [ ] **Stakeholder approval** on configuration A as primary, with fallback ladder B → E → C.
- [ ] **Week 2 owner** for the SuperNeo reference-impl survey (Day 1 of Week 2).
- [ ] **Week 2 owner** for Goldilocks Poseidon re-instantiation in `circuits/poseidon/poseidon_wrap.circom` (Days 1–2 of Week 2).
- [ ] **External cryptographer engaged** for Poseidon parameter review (parallel track; not a Week 2 blocker for prototype, only for production).
- [ ] **Verifier device class confirmed** for the CSP relying party — needed to set the verifier-cost bar (currently assumed mobile-class).
- [ ] **Final SNARK choice locked** to Spartan2 over Goldilocks; fallback to Spartan2 over Pallas/Vesta if Goldilocks finisher impl is unavailable.

---

## 7. Next steps (Week 2 plan, high-level)

**Day 1:**
- SuperNeo reference-impl survey (~3 hrs). If unavailable, switch to Neo.
- Goldilocks Poseidon parameter import (Plonky2 constants). Begin Circom port of `poseidon_wrap.circom`.
- Pull exact per-fold benchmark numbers from Neo paper §benchmarks; refine cost model §5.

**Day 2:**
- Complete Goldilocks Poseidon port; re-measure SlhF/H/Tk/Tlen/HMsg R1CS counts. Update step-function design doc §5 with measured (not projected) Goldilocks column.
- Pilot folding: 1 H_msg step + 1 FORS leaf step + 2 reduce steps wired end-to-end. Confirm step circuit compiles in the chosen scheme's CCS form.

**Day 3:**
- Scale pilot to full FORS verification (197 Poseidon perms). Measure per-fold time, accumulator size, peak RSS.
- Validate cost-model §5 projections to within 2×.

**Day 4–5:**
- Scale to full SLH-DSA-128s verify (4,273 perms). End-to-end prover wall-clock, RSS, proof-size measurements.
- Spartan2 finisher over Goldilocks: prototype + benchmark.

**Day 6–7:**
- Write-up: prototype repo, measured numbers vs. projections, recommendation memo for production commitment.
- Compare to ECDSA-Spartan2 baseline on identical hardware.

---

## 8. Open questions to revisit at Day 5 sign-off

1. **Is the 1 GB peak RSS ceiling correct for the CSP target device?** If the deployment is laptop-class instead of phone-class, the binding constraint relaxes and the conservative fallback C becomes more attractive.
2. **What's the relying-party device class?** Affects verifier-cost weight in the matrix.
3. **Is there appetite for SuperNeo's higher impl risk in exchange for the multi-fold heterogeneous-branch advantage?** If the team is risk-averse for a v1 ship, go directly to B (Neo + D2-c).
4. **What's the timeline pressure on Goldilocks Poseidon security review?** If it must complete before any deploy, schedule it now.
5. **Is XMSS (Vikas's track) targeting the same scheme + field?** Coordination point — using the same scheme across XMSS and SLH-DSA-128s halves the integration work.

---

## 9. Files referenced

- `research/folding/step_function_slh_dsa_128s.md` — step decomposition options
- `research/folding/cost_model.md` — projected costs per (scheme × decomposition × field)
- `results/results_summary.md`, `README.md` — monolithic baseline (measured)
- LatticeFold ePrint 2024/257, Neo ePrint 2025/294, SuperNeo ePrint 2026/242, Cyclo ePrint 2026/359 (cited, not loaded)

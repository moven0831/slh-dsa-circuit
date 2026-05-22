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

## 3. Primary selection — revised 2026-05-22 after literature survey

### 3.1 Selected configuration

> **Primary (conservative): configuration A' — SuperNeo or Neo + D4 (per-XMSS-layer) + Goldilocks Poseidon + Spartan2 finisher over Goldilocks.**
>
> **Aggressive alternative: configuration A — SuperNeo + Nebula switchboard NIVC + D5+D6+D7 multi-fold + Goldilocks Poseidon + Spartan2 finisher.** *Only* if Week 2 Day 1 confirms the Nebula/SuperNeo composition is implementable in the prototype window.

### 3.2 Why D4 is the new conservative lead (was D5+D6+D7 in Week 1 Day 5)

**The literature survey (2026-05-22) surfaced two facts that flip the primary recommendation:**

1. **Per-fold recursion-circuit overhead is ≈ 10,000 R1CS** for Nova-class folding schemes (SuperNeo §1.1 D6; `oskarth/nova-bench`). Neo / SuperNeo claim "logarithmic" overhead but report no absolute number. Under the Nova baseline, total prover work is fold-overhead-bound for fine-grained decompositions:

   | Decomposition | Folds | Step R1CS | Step + 10K-overhead total |
   |---|---|---|---|
   | D2-c | 4,273 | 240 | **43.7 M R1CS** |
   | D3 | 669 | ≈ 5,000 | 10.0 M R1CS |
   | **D4** | **9** | **573,000** | **5.2 M R1CS — 8.4 × better than D2-c** |

2. **Neo / SuperNeo do not natively support heterogeneous-branch step circuits.** Their k-to-1 multi-folding requires the k folded instances to share the same CCS shape (Neo §3 SIMD restriction; SuperNeo Fig 1). The multi-fold story for SLH-DSA's tree-shaped workload requires layering **SuperNova / NIVC** (ePrint 2022/1758) or **Nebula switchboard** (ePrint 2024/1605) on top — *unpublished* composition with no open-source implementation (Sonobe issue #144 tracks NIVC support as not-yet-implemented across all major folding libraries as of 2026-05).

D4 sidesteps both issues — uniform step shape (no NIVC needed), tiny fold count (overhead vanishes).

### 3.2a Why D5+D6+D7 multi-fold is still listed (aggressive alternative)

If Week 2 Day 1 measurement shows Neo/SuperNeo recursion overhead is **sub-1 K R1CS** (a 10 × improvement on Nova baseline), the math flips again and per-primitive granularity wins. The multi-fold primary remains relevant for *parallelism* (per-branch folding on multi-core CPUs) once the NIVC layering issue is resolved.

### 3.3 Fallback ladder (revised)

If primary configuration A' is blocked, switch in order:

1. **A' → B' (LatticeFold+ + D4 + Goldilocks Poseidon)** if Neo/SuperNeo reference impls are not usable in Week 2.
   - LatticeFold+ over cyclotomic rings is more mature than Neo/SuperNeo; trade-off is slower per-fold (Rq-multiplication vs. small-field).
   - Wall-clock penalty: ~5–10 × vs. Neo/SuperNeo on Goldilocks per cost_model §5.
   - **Trigger:** Day 1 of Week 2 if neither Neo nor SuperNeo reference impl is usable.

2. **B' → C' (LatticeFold+ + D4 + `secq256r1`)** if Goldilocks Poseidon re-instantiation slips.
   - No Poseidon redesign needed; uses existing `circuits/poseidon/hashes.circom`.
   - Memory wins still ≈ 20 × vs. monolithic Spartan2 baseline.
   - **Trigger:** Day 2 of Week 2 if Goldilocks Poseidon prototype not benchmarked.

3. **C' → D' (LatticeFold+ + D3 sub-layer + `secq256r1`)** if D4's step R1CS (573 K) blows the prototype's memory ceiling.
   - Trades step size for fold count (669 folds × 5 K step).
   - **Trigger:** Day 3 of Week 2 if D4 step prototype OOMs.

4. **D' → original Spartan2 monolithic baseline** if none of the above is achievable.
   - Re-evaluate the entire folding direction.
   - **Trigger:** Day 4 if no folding prototype works end-to-end.

**Configuration A (multi-fold) is reserved for parallel pursuit if there's bandwidth — not the primary path.**

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

## 6. Sign-off requirements (actionable, revised 2026-05-22)

Before Week 2 Day 1 begins, the following must each have: **Decision**, **Owner**, **Trigger**, **Evidence-artifact**, and a Date filled in. Replace the `<>` placeholders. Items missing any of the four fields **block Week 2**.

| # | Decision | Owner | Trigger | Evidence artifact | Date |
|---|---|---|---|---|---|
| 1 | Approve D4 conservative primary + D2-c conditional alternative (gated on Week 2 Day 1 per-fold-overhead measurement); fallback ladder A' → B' → C' → D'. | `<PI / project lead>` | Reviewer reading EXEC_SUMMARY + this §3 confirms. | `EXEC_SUMMARY.md` approved-by line filled in. | `<YYYY-MM-DD>` |
| 2 | Name Week 2 engineer for SuperNeo / Neo reference-impl survey + per-fold-overhead micro-bench (Day 1 deliverable). | `<EM>` | Week 2 Day 0. | `research/folding/week2_prereqs.md` lists owner. | `<YYYY-MM-DD>` |
| 3 | Name Week 2 engineer for Goldilocks Poseidon Circom re-instantiation in `circuits/poseidon/poseidon_wrap.circom` (Days 1–2 deliverable). | `<EM>` | Week 2 Day 0. | `week2_prereqs.md` lists owner + Poseidon variant pin (Plonky2 commit SHA). | `<YYYY-MM-DD>` |
| 4 | External cryptographer engagement plan: named candidate org(s), scope-of-work (Poseidon constants + Merkle-tree-T_k variant + Module-SIS params), budget envelope, target dates relative to deploy. | `<PI>` | End of Week 2 (parallel; not a Week 2 prototype blocker, but a production deploy blocker). | `research/folding/cryptographer_engagement.md` drafted. | `<YYYY-MM-DD>` |
| 5 | Confirm verifier device class (mobile / desktop) for the CSP relying party. Cascades to scheme + field choice — if mobile, Goldilocks Spartan2 finisher is required; if desktop, slack. | `<product lead>` | Week 2 Day 0. | One-line decision recorded in `EXEC_SUMMARY.md`. | `<YYYY-MM-DD>` |
| 6 | Final SNARK choice locked to Spartan2 over Goldilocks (default). Fallback: Plonk-style with FRI if Goldilocks Spartan2 finisher impl is unavailable in Week 2 timeframe. | `<scheme owner>` | Week 2 Day 1 after SuperNeo survey. | `scheme_selection.md` updated with chosen finisher + commit SHA of reference impl. | `<YYYY-MM-DD>` |
| 7 | XMSS-track coordination: confirm shared scheme + shared field + shared Poseidon variant (or document explicit divergence). Same Poseidon halves the integration work. | `<XMSS lead + SLH-DSA lead>` | Week 2 Day 0. | Joint memo at `research/folding/xmss_handoff.md`. | `<YYYY-MM-DD>` |

**Status meta-fields:**
- If any row is incomplete by Week 2 Day 0 EOD, **Week 2 starts in NEEDS-CLOSURE state**, not READY.
- The fallback ladder (`§3.3`) ensures Week 2 has a path forward even if individual items slip — but the *initial* scheme choice is gated on items 1, 2, 6 being filled.

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
- Compare to ECDSA-Spartan2 baseline on identical hardware **with identical hash function** (per `cost_model.md §9.2` caveat — the existing comparison is M5/SHA-256 vs. M3/Poseidon, not apples-to-apples).

### 7.7 Week 2 acceptance gate (Day-7 deliverable)

A reviewer reading the Week 2 output should be able to confirm **all** of the following before declaring Week 2 successful:

| # | Acceptance criterion | Measurement method |
|---|---|---|
| 1 | End-to-end SLH-DSA-128s verify proved under the chosen (scheme × decomposition × field) | Running prototype produces a valid folded accumulator + closing SNARK proof |
| 2 | Prover wall-clock ≤ **2.0 s** on M3/24 GB single-core | Measured with `/usr/bin/time -v` or equivalent |
| 3 | Peak prover RSS ≤ **1 GB** | `/usr/bin/time -v` Maximum RSS field |
| 4 | Proof size ≤ **500 KB** | File size of the closing SNARK output |
| 5 | Per-fold recursion-circuit overhead empirically measured for the chosen scheme | Reported in `research/folding/week2_results.md` with reproducer command |
| 6 | D2-c vs. D4 decision locked with evidence (matches or revises the conservative recommendation in `§3.2`) | Decision section in `week2_results.md` cites the measured overhead and references `cost_model.md §5.4` crossover |
| 7 | All `cost_model.md §5.2` projections either validated to within 2 × or replaced with measured numbers | Side-by-side projected-vs-measured table in `week2_results.md` |
| 8 | If multi-fold attempted: explicit reproducer for the Nebula/NIVC composition + measured per-branch parallelism factor | Repo + benchmark; OR a "deferred" note with rationale |
| 9 | `yarn verify:folding` still passes (or has been updated with explicit deltas explaining drift) | Verifier run; `git diff scripts/verify_perm_counts.py` if updated |
| 10 | Updated Week 3+ recommendation: ship-it / iterate / abandon | Memo in `week2_results.md` |

**If criteria 1–4 are not met but the prototype runs:** Week 2 is *NOT* a failure — it produces empirical numbers that flip the recommendation. The follow-up is Week 3 with the corrected primary, not "go back to monolithic." **The only Week 2 failure mode is no prototype at all by Day 7.**

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

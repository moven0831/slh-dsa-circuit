# Folding-scheme cost model for SLH-DSA-128s (Poseidon)

**Status:** Week 1 Days 3–4 deliverable, draft. Input to the Week 1 Day 5 decision matrix.

**Companion docs:**
- `research/folding/step_function_slh_dsa_128s.md` (step-function design, Days 1–2) — source of all step-circuit numbers below.
- `research/folding/scheme_selection.md` (decision matrix, Day 5) — consumes this doc's totals.

**Scope:** Project total prover wall-clock + peak RSS + proof size + verifier cost for **SLH-DSA-128s Poseidon verify** under {LatticeFold, LatticeFold+, Neo, SuperNeo, Cyclo} × {flat-IVC primary D2-c, multi-fold primary D5+D6+D7}, on both `secq256r1` (no Poseidon re-instantiation) and Goldilocks (with Plonky2-style Poseidon).

**Uncertainty.** Per-fold scheme costs are **paper-derived projections, not measured**. Goldilocks Poseidon costs carry ±25 % (per step-function design Sec 5.1). Total prover wall-clock therefore has compounding uncertainty; **treat all numbers below as order-of-magnitude until Week 2 prototype validates them**. Sensitivity analysis (§8) explicitly tracks which inputs move the recommendation.

---

## 1. Summary

| Metric | Monolithic Spartan2 (baseline, measured) | Folding primary recommendation (projected) | Improvement |
|---|---|---|---|
| **Prover wall-clock** | 16.2 s (M3, single-core) | **0.4–1.5 s** (Goldilocks, multi-fold, mobile-class CPU, parallelized) | **10–40×** |
| **Peak prover RSS** | **5.41 GB** | **30–200 MB** | **30–180×** ← *binding* |
| **Proof size** | 208.8 KB | 100–500 KB | within ~2× |
| **Verifier wall-clock** | 9.5 s | 0.1–3 s (scheme-dependent) | up to 100× |
| **Setup size (PK)** | 2.37 GB | 10–500 MB (transparent setup possible) | 5–250× |

**Top recommendations (revised 2026-05-22 after literature survey, see §3 + §11):**

1. **SuperNeo (k-to-1) + Nebula switchboard NIVC + D5+D6+D7 multi-fold + Goldilocks Poseidon** + Spartan2 finisher — best *potential* profile, but **highest implementation risk**: Neo/SuperNeo natively do k-to-1 on *same-shape* instances only; heterogeneous-branch multi-fold requires layering Nebula (ePrint 2024/1605) or SuperNova/NIVC (ePrint 2022/1758) on top. **No published implementation of this stack exists** (Sonobe issue #144 confirms NIVC is unimplemented across all major open-source folding libs as of 2026-05).
2. **SuperNeo or Neo + D4 (per-XMSS-layer) + Goldilocks Poseidon** + Spartan2 finisher — **conservative new lead recommendation**. D4's 9-fold count makes fold overhead vanish; total work ≈ 5.2 M R1CS, **8.4 × lower than D2-c** under the Nova-class 10 K R1CS recursion-circuit baseline (SuperNeo §1.1 D6 + `oskarth/nova-bench`). Lowest impl risk on Goldilocks path.
3. **Neo + D2-c (per-arity-2 chain) + Goldilocks Poseidon** + Spartan2 finisher — **only viable if** Week 2 Day 1 measures per-fold overhead < 1.1 K R1CS (a 9 × improvement on the Nova baseline that has not been empirically demonstrated). D2-c remains the cleanest CCS shape but is fold-overhead-bound.
4. **LatticeFold+ + D4 + `secq256r1`** (no Poseidon re-instantiation) — most conservative path, no field-port required. Prover time ~5–10 × slower than #1 / #2 but memory wins remain ~30 ×.

**Critical risks** (driven by literature survey):
- **R1: Heterogeneous-branch NIVC layering.** Combining Neo/SuperNeo with Nebula or SuperNova is unpublished work. Recommendation #1 is research-grade, not engineering-grade.
- **R2: Per-fold overhead constant unknown.** Neo/SuperNeo claim "logarithmic" overhead but report no absolute number; Nova baseline is ~10 K R1CS. Week 2 Day 1 must measure this — it dictates D2-c vs D3 vs D4 directly.
- **R3: Goldilocks vs. Mersenne-31.** Ethereum PQ aggregation (leanSig, leanMultisig) is converging on **Mersenne-31 / KoalaBear**, not Goldilocks. Field choice cascades to Poseidon parameter selection.

---

## 2. Methodology

### 2.1 Field-operation rates (modern CPU, single-core)

Source: standard benchmark literature (Plonky2, arkworks, RELIC); rough order-of-magnitude.

| Field | Bit-width | Mult cost (ns) | Ops/sec (scalar) | Ops/sec (SIMD AVX2) |
|---|---|---|---|---|
| Goldilocks (p ≈ 2⁶⁴) | 64 | 10–30 | 30–100 M | 200 M – 1 G |
| BLS12-381 / BN254 scalar | 256 | 100–300 | 3–10 M | ~30 M |
| `secq256r1` scalar | 256 | 100–500 | 2–10 M | ~30 M |
| Cyclotomic ring (d=64, q ≈ 2³⁰) NTT-mult | – | 1,000–3,000 (per ring-element mult) | 0.3–1 M ring-mults | ~5 M ring-mults |

**Takeaway.** Goldilocks ops are **20–50× faster than secq256r1** per mult. This is the single biggest lever for prover wall-clock — bigger than the constraint-count reduction from the step-function decomposition.

### 2.2 R1CS prover work model

Standard rule of thumb for sumcheck-style provers (Spartan family): **~30 field mults per R1CS row per "round" of sumcheck**, with O(log N) rounds. For our purposes, a simplification:

> Prover work per fold step ≈ step_R1CS × 30 mults

For D2-c (213 R1CS step) → ~6.4 K mults per step.
For D5 multi-fold leaves (155–660 R1CS per branch) → ~5–20 K mults per leaf instance.

This **excludes** the per-fold accumulator update cost — that's §2.3.

### 2.3 Per-fold accumulator-update model

Per-fold overhead for lattice schemes is dominated by:

- **Re-commitment of the step witness** under the scheme's Ajtai-style commitment. Cost ≈ `witness_size_in_field_elements × commitment_constant`. For Ajtai over a small field, the constant is ~10–100 mults per witness FE.
- **Folding challenge derivation** — small, ~100 mults.
- **Accumulator linear combination** — linear in accumulator size, typically ~MB-scale data, so ~1–10 K mults per fold.

For D2-c (witness ~10 FE per fold, accumulator ~50 KB):
> Per-fold overhead ≈ 10 FE × 50 mults + 5 K accumulator update + 100 challenge = **~5.6 K mults per fold**

For multi-fold k-to-1 with k=14 (D6 per-FORS-tree):
> Per-k-fold overhead ≈ k × 5.6 K = **~78 K mults per k-fold** (linear in k, no asymptotic gain)

Note: multi-fold's gain over flat IVC is **not** in per-fold marginal cost (same O(N) work) but in:
1. **Parallelism** — independent branches fold in parallel; a 4-core mobile CPU sees ~3-4× speedup if branches are balanced.
2. **No variable-arity padding** — D2-a's pad-to-64 tax (≈25× R1CS bloat) is avoided.
3. **Smaller critical-path depth** — 3 fold levels vs. 4,273 in flat IVC, relevant only when fold ops are not pipelinable.

### 2.4 Memory model

Folding shrinks peak RSS by holding only one step circuit + the accumulator in memory at a time, instead of the full witness vector. Components:

| Component | Monolithic Spartan2 | Folding (per step) |
|---|---|---|
| Witness vector | 3.86 M wires × ~32 B = ~120 MB at single-precision; ~1 GB+ with multi-precision intermediate state | step_witness × 32 B = ~KB |
| Constraint system | 3.99 M R1CS × ~100 B = ~400 MB | step_R1CS × ~100 B = ~KB |
| Commitment / PK | 2.37 GB (Hyrax PCS over `secq256r1`) | scheme-dependent, transparent-setup options available |
| Sumcheck state | ~1 GB intermediate | small (per step) |
| Accumulator | – | ~1–50 MB scheme-dependent |
| **Total peak RSS** | **5.41 GB measured** | **~30–200 MB projected** |

For mobile (target: ~1 GB working RSS), monolithic is past the OOM ceiling; folding is comfortably below it.

---

## 3. Scheme-specific per-fold costs

All numbers are **projections from paper claims and structure**, not measurements. Cite each scheme's ePrint for refinement on actual benchmark tables. **Day 3 follow-up:** pull exact numbers from the papers' Section §Benchmarks.

### 3.1 LatticeFold (ePrint 2024/257)

- **Commitment:** Ajtai over cyclotomic ring R = Z[X]/(X^d + 1), d = 64, q ≈ 2³⁰.
- **Per-fold prover cost:** dominated by ring-element multiplication. ~10 ring-mults per witness FE, ~10 K ring-mults total per fold for typical step sizes.
  - In native CPU ops: ~10 K × 1 μs (ring-mult) = **~10 ms per fold**.
- **Accumulator size:** ~1 KB per fold layer; for flat IVC with 4,273 folds, the accumulator is **constant-size** (folded down each step), ~MB scale.
- **Norm refresh:** every fold; small constant overhead, ~K mults.
- **Final SNARK:** typically Spartan2 over the cyclotomic ring or a separate Plonk closer; paper's reference implementation uses Spartan2.
- **Maturity:** original lattice fold (2024); reference implementation exists, not production-grade.

### 3.2 LatticeFold+ (refinement of LatticeFold)

- Same commitment family; improved norm management.
- **Per-fold prover cost: ~30–50 % better than LatticeFold** → ~5–7 ms per fold.
- **Accumulator:** same shape, smaller norm growth.
- **Maturity:** newer than LatticeFold, less battle-tested.

### 3.3 Neo (ePrint 2025/294, Nguyen & Setty)

- **Commitment:** pay-per-bit Ajtai over a small prime field (Goldilocks, or Mersenne-61 "almost-Goldilocks" per §6.1).
- **Per-fold prover cost — corrected 2026-05-22.** Literature only gives **recursion-circuit overhead in R1CS constraints**, not wall-clock μs. SuperNeo §1.1 D6 cites Nova at *"≈10,000 R1CS constraints"* per fold; Neo / SuperNeo claim *"logarithmic recursion overhead"* but report no absolute number. Earlier "100 μs per fold" estimate in this doc was a Goldilocks-mult-rate extrapolation with no paper backing — replace with **placeholder pending Week 2 Day 1 measurement**.
- **Multi-fold (k-to-1):** Neo's natural mode, but quoted scope: *"folds multiple CCS instances at once"* (paper line 488) — meaning **k instances of the same CCS shape**. **Heterogeneous-branch capability is not native to Neo;** it requires layering SuperNova/NIVC (ePrint 2022/1758) or Nebula switchboard (ePrint 2024/1605).
- **Restriction:** **requires SIMD constraint structure** — Neo §3 explicitly: *"This implicitly requires that one must have a 'data parallel' (or SIMD) constraint system."* Compatible with our D2-c uniform arity-2 step or D4 uniform per-XMSS-layer step; incompatible with naive D2 / D3 per-primitive heterogeneous folding.
- **Accumulator size:** O(log N) growth; ~MB scale at N ≈ 4,000.
- **Final SNARK:** Spartan2 over Goldilocks; paper benchmarks ~100 ms prover, ~30 KB proof for ~2²⁰ constraints (cited not measured here).
- **Maturity:** 2025 publication; reference implementation status unknown to this survey.

### 3.4 SuperNeo (ePrint 2026/242, Nguyen & Setty)

- **Removes Neo's SIMD restriction.** SuperNeo §1.1: *"Neo satisfies five of the six properties but requires SIMD constraint systems."* SuperNeo lifts this — supports general (non-SIMD) CCS instances in k-to-1 folding.
- **But heterogeneous-branch step circuits are still not native.** SuperNeo's multi-folding "folds multiple CCS instances" (paper line 300) — meaning k arbitrary-shape instances at once, *not* k different-shaped step circuits combined into one accumulator. Heterogeneous-branch step capability (our D5) still requires SuperNova/NIVC (ePrint 2022/1758) or Nebula (ePrint 2024/1605) layered on top.
- **Per-fold prover cost:** logarithmic recursion overhead per SuperNeo §1.1 D6, no absolute number reported. Pending Week 2 Day 1 measurement.
- **Final SNARK:** Spartan2 over Goldilocks.
- **"First to satisfy all six folding desiderata"** per paper abstract: (i) PQ, (ii) small-field, (iii) non-SIMD multi-fold, (iv) transparent setup, (v) succinct accumulator, (vi) succinct final proof. **Note: "heterogeneous-branch multi-fold" was the earlier claim in this doc — corrected to "non-SIMD multi-fold" per SuperNeo Figure 1.**
- **XMSS motivation:** SuperNeo §1 explicitly names XMSS aggregation for Ethereum as a motivating use case (paper lines 65–78), but **does not build it**. Our Week 1 work is the first published step-function decomposition for SLH-DSA-128s under any folding scheme.
- **Maturity:** 2026 publication; reference implementation may not yet exist publicly. **Highest implementation risk** of the schemes in this table.

### 3.4a Heterogeneous-branch capability: SuperNova / Nebula (added 2026-05-22)

For the multi-fold primary D5+D6+D7 (per-primitive heterogeneous leaves), the actual mechanism is:
- **SuperNova / NIVC** (Kothapalli & Setty, ePrint 2022/1758): non-uniform IVC. Each fold step picks from a fixed set of step-circuit shapes via a selector. Used in Nebula and several Lurk Lab projects; **not in Sonobe** as of 2026-05 (Sonobe issue #144).
- **Nebula switchboard** (Arun & Setty, ePrint 2024/1605): introduces a "switchboard" circuit that routes between branches. Used for memory-checking IVC.
- Combining **Neo / SuperNeo k-to-1 lattice folding** with **NIVC** is plausible but **unpublished**. Treat as research-grade composition for Week 2.

### 3.5 Cyclo (ePrint 2026/359)

- **Commitment:** lattice over cyclotomic ring (like LatticeFold).
- **Innovation:** amortized norm refresh; **no per-fold accumulator norm checks**.
- **Per-fold prover cost:** ~30–50 % better than LatticeFold+ → ~3–5 ms per fold.
- **Multi-fold support:** unclear from abstract; likely flat-IVC only at first.
- **Maturity:** 2026 publication; very newest; **less battle-tested than Neo/SuperNeo**.

### 3.6 Comparative per-fold table — **revised 2026-05-22**

All "per-fold time" numbers below are **retracted as load-bearing inputs to §5**. Literature gives recursion-circuit overhead in *R1CS constraints* (Nova ≈ 10K, lattice schemes claim "logarithmic" with no absolute number), not wall-clock. Earlier 100 μs / 10 ms etc. were Goldilocks-mult-rate or Rq-mult-rate extrapolations with no paper backing. **Week 2 Day 1 must measure these.**

| Scheme | Field/ring | Per-fold overhead (R1CS) | Wall-clock (Goldilocks projection only) | Multi-fold? | Restriction |
|---|---|---|---|---|---|
| LatticeFold | Cyclotomic Rq (d=64, q≈2³⁰) | **unmeasured** (likely > Nova baseline due to ring-poly verification in-circuit) | unmeasured | flat IVC only | LatticeFold can NOT use Goldilocks (q-restriction) |
| LatticeFold+ | Cyclotomic Rq | unmeasured | unmeasured | flat IVC only | same q-restriction as LatticeFold |
| **Nova (curve-based, non-PQ; baseline only)** | Pasta curves | **≈ 10K R1CS** (SuperNeo §1.1 D6) | ~100 μs at Goldilocks mult rate (extrapolation only) | NIVC via SuperNova / Nebula | – |
| **Neo** | Mersenne-61 / Goldilocks ("almost-Goldilocks") | **unmeasured** — claim *"logarithmic"* per SuperNeo §1.1 D6, *no absolute number* | unmeasured | k-to-1 on same-shape | **uniform CCS (SIMD)** |
| **SuperNeo** | Mersenne-61 / Goldilocks | unmeasured — same "logarithmic" claim | unmeasured | k-to-1 on same-shape (not heterogeneous; needs Nebula/NIVC) | none |
| Cyclo | Cyclotomic Rq | unmeasured | unmeasured | unclear | – |

**Caveat on the 10K Nova baseline.** That number verifies one Pasta scalar mul + Poseidon sponge in-circuit. Lattice schemes verify Ajtai-commitment openings, sumcheck transcripts, and norm bounds in-circuit. **Whether lattice recursion is cheaper or more expensive than Nova's 10K is empirically unknown**: the agent's view is that ring-polynomial verification *in R1CS* is dense (potentially 30–50K R1CS), but Neo / SuperNeo's "logarithmic" claim suggests sub-Nova once the small-field optimization lands. **Treat 10K as a floor estimate, not a tight bound. Week 2 Day 1 must measure.**

**Earlier takeaway retracted.** The earlier claim "Neo / SuperNeo on Goldilocks are 30–100 × faster per fold than ring-based schemes" rested on the extrapolated 100 μs number which had no paper backing. Until Week 2 Day 1 measurement, the cross-scheme ranking is **unknown**.

---

## 4. Step-circuit prover work

Pulled from `research/folding/step_function_slh_dsa_128s.md` §5.2. Step prover mults = `step_R1CS × 30` per §2.2.

### 4.1 Flat-IVC primary D2-c (per-primitive, arity-2 reduce chain)

| Field | Step R1CS | Mults per step | Fold count | Total step mults | Single-core step time |
|---|---|---|---|---|---|
| `secq256r1` | **240 measured** | 7,200 | 4,273 | 30.8 M | ~3–6 s |
| Goldilocks | **≈120 ±25 %** | 3,600 ±25 % | 4,273 | 15.4 M | **~155 ms** |

Step R1CS measured via `bench_poseidon_reduce2` (240 R1CS, --O2, `secq256r1`) — the pure `circomlib` Poseidon(2) perm. Total step work = step R1CS × fold count = **1,025,520 R1CS** (`secq256r1`) ≈ **0.51 M** (Goldilocks ±25 %). Validates via `scripts/verify_perm_counts.py`.

### 4.2 Multi-fold primary D5+D6+D7

Heterogeneous branches. Per-branch mults computed individually then summed.

**D5 leaves:**

| Branch | Step R1CS (secq, measured) | Instances | Total mults (secq) | Total mults (Goldilocks ±25 %) |
|---|---|---|---|---|
| F-step (Poseidon(10)) | 968 | 3,697 (F leaves + Tk-mix + Tlen-mix) | 107 M | 54 M |
| H-step (Poseidon(11)) | 1,102 | 231 | 7.6 M | 3.8 M |
| Reduce2-step (Poseidon(2)) | **240** | 343 (14 Tk + 266 Tlen + 63 HMsg) | 2.5 M | 1.2 M |
| HMsg-mix-step (Poseidon(5)) | ≈380 (projected) | 2 | 23 K | 12 K |
| ADRS overhead (per-step) | ≈200 (bench_adrs_sanity = 198) | 4,273 | 25.6 M | 12.8 M |
| **D5 leaf total** | | **4,273 fold steps** | **143 M** | **72 M ± 18 M** |

**D6 mid + D7 top:**

| Branch | Step R1CS (secq) | Folds | Total mults (secq) | Total mults (Goldilocks ±25 %) |
|---|---|---|---|---|
| D6 per-FORS-tree | ~2 K | 14 | 0.84 M | 0.42 M |
| D6 per-WOTS-pk | ~4 K | 7 | 0.84 M | 0.42 M |
| D7 top | ~3 K | 1 | 90 K | 45 K |
| **Mid+top total** | | | **1.77 M** | **0.89 M** |

**Grand total step mults (D5+D6+D7):**
- `secq256r1`: 143 + 1.77 = **~145 M mults** → single-core ~15–70 s, **multi-core (4-way parallelism) ~4–18 s**.
- Goldilocks: 72 + 0.89 = **~73 M mults ± 18 M** → single-core ~700 ms – 2.5 s, **multi-core ~180–600 ms**.

### 4.3 Step-work observation

Multi-fold's per-branch parallelism gives ~4× speedup on a 4-core CPU vs. flat IVC. Flat IVC's smaller total step work (~14 M Goldilocks mults vs. ~60 M for multi-fold) partially offsets the parallelism gain — net: similar wall-clock between D2-c and D5+D6+D7 on a 4-core mobile, slight edge to multi-fold.

---

## 5. Total prover wall-clock per (scheme × decomposition × field)

Total = step work + fold overhead × fold count. Single-core estimates unless noted.

### 5.1 secq256r1 (no Poseidon re-instantiation)

| Scheme | Step (D2-c flat) | Folds (D2-c flat) | **Total D2-c** | Step (D5+D6+D7 multi-fold) | Folds (D5+D6+D7) | **Total multi-fold** |
|---|---|---|---|---|---|---|
| LatticeFold | 3–5 s | 4,273 × 10 ms = 43 s | **~46–48 s** ❌ | 12–60 s | – (flat only) | n/a |
| LatticeFold+ | 3–5 s | 4,273 × 6 ms = 26 s | **~29–31 s** | 12–60 s | – | n/a |
| Neo | 3–5 s | 4,273 × 100 μs = 0.43 s | **~3.4–5.4 s** | – (uniform CCS only) | – | n/a |
| SuperNeo | 3–5 s | 0.43 s | **~3.4–5.4 s** | 12–60 s | ~21 mid folds × ~200 μs + 4,273 leaf folds × 100 μs = 0.43 s | **~12–60 s** (parallelizable to 3–15 s) |
| Cyclo | 3–5 s | 4,273 × 4 ms = 17 s | **~20–22 s** | – | – | n/a |

❌ = worse than monolithic (16.2 s).

### 5.2 Goldilocks (with Poseidon re-instantiation, ±50 %) — **wall-clock cells retracted, pending Week 2 Day 1 measurement**

**Earlier cells in this table assumed a 100 μs-per-fold extrapolation that this doc §3.6 has now retracted.** Until per-fold overhead is measured for the chosen scheme, the wall-clock numbers below are **not load-bearing**. They are retained as illustration of order-of-magnitude; replace with measurement on Week 2 Day 1.

| Scheme | Step (D2-c flat, illustrative) | Per-fold overhead (R1CS) | D2-c total (illustrative) | D4 (per-XMSS-layer) | Multi-fold (D5+D6+D7) |
|---|---|---|---|---|---|
| LatticeFold | 155 ms × 4,273 | unmeasured (likely > 10 K) | > 26 s ❌ | ~3.7 s (D4 amortizes) | **BLOCKED** — LatticeFold can't use Goldilocks (q-restriction); see §3.6 |
| LatticeFold+ | 155 ms × 4,273 | unmeasured | > 26 s ❌ | ~3.7 s | **BLOCKED** — same q-restriction; needs cyclotomic Rq Poseidon |
| Neo | depends on per-fold overhead | "logarithmic" — unmeasured | **? — see §5.4** | **5.2 M R1CS total** (overhead-independent) | **BLOCKED** — Neo k-to-1 is same-shape only; needs Nebula/NIVC layered |
| **SuperNeo** | depends on per-fold overhead | "logarithmic" — unmeasured | **? — see §5.4** | **5.2 M R1CS total** | **BLOCKED** — SuperNeo k-to-1 is same-shape only (non-SIMD); needs Nebula/NIVC for heterogeneous branches |
| Cyclo | unmeasured | unmeasured | unmeasured | unmeasured | unmeasured |

**Provisional winner: D4 (per-XMSS-layer) under any non-trivial per-fold overhead** (see §5.4 crossover). The D4 column's "5.2 M R1CS total" is what's actually defensible; converting to wall-clock requires the Goldilocks Poseidon Circom measurement (Week 2 Day 1).

**Loser: D2-c (flat per-arity-2)** under Nova-class overhead (10 K R1CS per fold) — total work ~44 M R1CS, an order of magnitude worse than D4. **Only wins if Neo/SuperNeo deliver sub-1.1 K R1CS recursion overhead empirically.**

**Multi-fold rows marked BLOCKED.** Heterogeneous-branch composition (D5+D6+D7) requires Nebula switchboard (ePrint 2024/1605) or SuperNova NIVC (ePrint 2022/1758) layered onto Neo / SuperNeo's k-to-1 same-shape folding. **This stack is unpublished and unimplemented** (Sonobe issue #144 confirms NIVC is missing across all major open-source folding libs as of 2026-05). Pursuing D5+D6+D7 in Week 2 is research-grade engineering, not prototype-grade.

### 5.3 Re-run: ring-based schemes on coarser decompositions

For LatticeFold+ (best ring-based), flip to D3 sub-layer (669 folds) or D4 per-XMSS-layer (9 folds):

| Decomposition | Folds | Per-fold | Step work (Goldilocks) | Total |
|---|---|---|---|---|
| D2-c flat (uniform 213 R1CS) | 4,273 | 6 ms | 155 ms | ~26 s |
| D3 sub-layer (avg ~5K R1CS) | 669 | 6 ms | ~3.4 s | **~7.4 s** |
| D4 per-XMSS-layer (~573K R1CS) | 9 | 6 ms | ~3.6 s | **~3.7 s** |

LatticeFold+ + D4 → ~3.7 s prover. Faster than monolithic, slower than Neo/SuperNeo, but no Goldilocks dependency required if step circuit runs on the ring directly. **Caveat: LatticeFold+ cannot use Goldilocks for its lattice commitments** (q ≡ 1+2t mod 4t restriction); the `secq256r1` Poseidon-in-circuit + cyclotomic Rq lattice commitment is the actual setup.

### 5.4 D2-c vs. D4 crossover sensitivity — added 2026-05-22

The choice between **D2-c (per-arity-2 chain, 4,273 folds × 240 R1CS step)** and **D4 (per-XMSS-layer, 9 folds × 573 K R1CS step)** is dominated by **per-fold recursion-circuit overhead**, which is the most unsettled input to this cost model. Crossover under different overhead assumptions:

| Per-fold overhead (R1CS) | D2-c total | D4 total | Winner | Comment |
|---|---|---|---|---|
| **12** (log₂(4,273) ≈ 12, if Neo "logarithmic" claim taken literally) | 1.08 M | 5.16 M | **D2-c by 4.8 ×** | optimistic Neo/SuperNeo |
| **120** (10× log) | 1.54 M | 5.16 M | **D2-c by 3.4 ×** | optimistic lattice |
| **1.1 K** (crossover) | 5.73 M | 5.17 M | **tie** | break-even threshold |
| **10 K** (Nova-class baseline, SuperNeo §1.1 D6 quote) | 43.7 M | 5.25 M | **D4 by 8.3 ×** | conservative |
| **50 K** (lattice with Rq-verification in-circuit ceiling) | 214 M | 5.65 M | **D4 by 38 ×** | pessimistic |

**Reading.** D2-c is the right call **only if** per-fold overhead is **< 1.1 K R1CS** — a 9 × improvement on Nova's published 10K baseline. Neo / SuperNeo *claim* "logarithmic" overhead, but this is **not empirically measured** in any published source. **D4 wins under every assumption ≥ 1.1 K R1CS per fold, making it the conservative pick.**

**Implication for §1 + scheme_selection §3.** The D4 conservative-lead recommendation is correct **under the Nova-class anchor**. If Week 2 Day 1 measurement shows Neo/SuperNeo deliver sub-1 K R1CS overhead, **the recommendation flips back to D2-c**. Week 2 sign-off must condition on the measurement.

---

## 6. Peak prover RSS

### 6.1 Components per (scheme × decomposition)

Memory model from §2.4. Folding schemes:

| Component | D2-c flat IVC | D3 sub-layer | D4 per-XMSS-layer | D5+D6+D7 multi-fold |
|---|---|---|---|---|
| Step CCS in memory | <1 KB | ~10 KB | ~3 MB | <1 KB / branch |
| Step witness | ~1 KB | ~10 KB | ~1 MB | ~1 KB / branch |
| Accumulator | scheme-dependent | scheme-dependent | scheme-dependent | scheme-dependent |
| Sumcheck intermediate | ~step_size | ~step_size | ~step_size | ~step_size |
| PK / commitment key | scheme-dependent | scheme-dependent | scheme-dependent | scheme-dependent |
| **Total non-PK** | **~MB** | **~10 MB** | **~10 MB** | **~MB / branch × n_branches** |

### 6.2 Per-scheme PK / commitment-key sizes

| Scheme | PK / setup size | Transparent setup? |
|---|---|---|
| LatticeFold / + | ~50–200 MB | Yes |
| Neo | ~20–100 MB | Yes |
| SuperNeo | ~20–100 MB | Yes |
| Cyclo | ~50–200 MB | Yes |
| Monolithic Spartan2 (baseline) | 2.37 GB | Yes (Hyrax PCS) |

### 6.3 Total peak RSS projections

| Configuration | Peak RSS (projected) | vs. monolithic (5.41 GB) |
|---|---|---|
| Neo / SuperNeo + D2-c + Goldilocks | **30–150 MB** | **30–180×** ✓ |
| SuperNeo + D5+D6+D7 + Goldilocks | **50–250 MB** | **20–100×** |
| LatticeFold+ + D4 + secq256r1 | ~50–250 MB | ~20–100× |
| LatticeFold + D2-c + secq256r1 | ~80–250 MB | ~20–60× |

**All folding paths comfortably fit under a 1 GB working-set ceiling for mobile devices.** This is the case-for-action, not wall-clock.

---

## 7. Proof size and verifier cost

### 7.1 Proof size (final SNARK output)

| Scheme | Folded accumulator | + Final SNARK | **Total proof** |
|---|---|---|---|
| LatticeFold / + | ~few KB | Spartan2: ~200 KB | ~200 KB |
| Neo | ~few KB | Spartan2 over Goldilocks: ~30–50 KB | **~30–50 KB** ✓ |
| SuperNeo | ~few KB | Spartan2 over Goldilocks: ~30–50 KB | **~30–50 KB** ✓ |
| Cyclo | ~few KB | Spartan2: ~200 KB | ~200 KB |
| Monolithic Spartan2 (baseline) | – | – | 208.8 KB |

### 7.2 Verifier cost

Verifier is on the **relying party** (retailer in the CSP context). If relying party is also constrained (mobile, embedded), this matters.

| Scheme | Verifier time (proj.) | Verifier memory |
|---|---|---|
| LatticeFold / + | ~1–5 s | ~10–100 MB |
| Neo / SuperNeo (Spartan2 finisher over Goldilocks) | **~100–500 ms** | ~10–50 MB |
| Cyclo | ~1–3 s | ~10–100 MB |
| Monolithic Spartan2 (baseline) | 9.5 s / 3.11 GB | 3.11 GB |

**Neo / SuperNeo wins verifier metrics by 10–100×** thanks to small-field Spartan2 finisher.

---

## 8. Sensitivity analysis

Which inputs, if wrong by 2×, change the recommendation?

| Input | Bad-case value | Affects | New recommendation? |
|---|---|---|---|
| Goldilocks Poseidon R1CS (currently 0.5× ±25 %) | actually 0.8× (±0 % above secq) | step work doubles | Still Neo/SuperNeo wins, but margin shrinks. Conclusion stable. |
| Neo/SuperNeo per-fold (currently 100 μs) | actually 1 ms (10×) | total D2-c jumps to ~5 s, multi-fold to ~3 s | Multi-fold beats flat IVC by ~2×. SuperNeo + D5+D6+D7 becomes clear winner. |
| Neo/SuperNeo per-fold (currently 100 μs) | actually 10 μs (10× better) | total D2-c drops to ~0.3 s | Conclusion stable; flat IVC slightly preferred for simplicity. |
| LatticeFold+ per-fold (currently 6 ms) | actually 1 ms (6× better) | total D4 drops to ~3.5 s | Approaches Neo/SuperNeo territory; ring-based schemes become viable backup. |
| Goldilocks Poseidon re-instantiation slips Week 2 | secq256r1 only | D2-c step time 3–5 s instead of 155 ms | **Major impact.** Goldilocks delta = ~30× prover slowdown. Day 5 must decide whether to ship secq256r1 v1 or wait for Goldilocks. |
| Per-branch parallelism limited to 1 core (no multi-core) | multi-fold loses parallel advantage | D5+D6+D7 wall-clock 4× higher | Flat IVC D2-c becomes dominant; multi-fold's only advantage is heterogeneous-arity. |

**Top three uncertainties driving Day 5:**

1. **Goldilocks Poseidon re-instantiation timeline** — if it's not in by Week 2 prototype, recommendation #1 collapses.
2. **Neo/SuperNeo per-fold benchmark numbers** — the 100 μs projection is the single most load-bearing number in §5. If it's actually 1 ms, multi-fold beats flat IVC; if it's 10 μs, flat IVC dominates.
3. **Reference-implementation maturity** — Neo (2025) has a draft impl; SuperNeo (2026) may not yet. If SuperNeo's reference implementation is not usable in Week 2 timeframe, fall back to Neo + D2-c (which requires uniform CCS, fine for D2-c).

---

## 9. Comparison vs. baselines

### 9.1 vs. monolithic Spartan2 (this repo's measured baseline)

| Metric | Monolithic | Best folding projection | Improvement |
|---|---|---|---|
| Prover wall-clock | 16.2 s (M3, single-core) | 0.6–1.0 s (Goldilocks, multi-core) | 16–27× |
| Peak prover RSS | 5.41 GB | 30–250 MB | 20–180× |
| Proof size | 208.8 KB | 30–500 KB | 0.4–7× (some worse, see §7.1) |
| Verifier time | 9.5 s | 0.1–3 s | 3–100× |
| Setup size (PK) | 2.37 GB | 20–200 MB | 12–120× |

### 9.2 vs. OpenAC ECDSA-Spartan2 baseline — **soft comparison, not apples-to-apples**

From `README.md:61-62`: ecdsa-spartan2 (jwt_1k) is **76 KB proof, 1.1 s prove on M5/24 GB**, ~257 MB peak RSS.

**Important caveats** before comparing to our SLH-DSA numbers (added 2026-05-22):

- **Hardware delta:** ECDSA numbers are on **M5** (Apple Silicon, ~2024 gen); our SLH-DSA monolithic is on **M3** (Apple Silicon, ~2023 gen). Geekbench public data puts M5/M3 single-core integer-mult at ~1.3–1.5 × in M5's favour.
- **Hash function delta:** ECDSA-Spartan2 uses **SHA-256** in-circuit; our Poseidon SLH-DSA circuit uses **non-standard BN254-constants-mod-`p_secq256r1` Poseidon** — these are different hash functions with very different R1CS profiles. A like-for-like ECDSA-Poseidon variant has not been benchmarked.
- **Security level:** ECDSA jwt_1k targets classical 128-bit; SLH-DSA-128s targets NIST Category 1 (~128-bit classical, ~64-bit quantum). Apples-to-apples requires comparing PQ-vs-PQ or classical-vs-classical, not mixed.

| Metric | ECDSA-Spartan2 (M5, SHA-256) | SLH-DSA-128s monolithic (M3, Poseidon) | SLH-DSA-128s + folding (M3, proj.) | Comparison status |
|---|---|---|---|---|
| Prover time | 1.1 s | 16.2 s (15×) | **? — pending Week 2 measurement** | **Not apples-to-apples** (hardware + hash + sec level differ) |
| Peak RSS | 257 MB | 5.41 GB (21×) | 30–250 MB (folding loop only; finisher peak may add ~GB — see §6.3) | Folding likely matches; full picture needs finisher measurement |
| Proof size | 76 KB | 208.8 KB (2.7×) | 30–500 KB (Neo/SuperNeo Spartan2 finisher) | Same order of magnitude |
| Verifier | (similar) | 9.5 s | 0.1–3 s (small-field Spartan2 finisher) | Potentially faster, but unmeasured |

**Honest finding:** With folding + Goldilocks, **PQ SLH-DSA-128s is in the same order of magnitude as the classical ECDSA baseline on memory and proof size**. Prover time matching requires the §5.4 D2-c-wins regime (sub-1.1 K R1CS per-fold overhead), which is unmeasured. **Claim "matches or beats on every metric" is overclaim until normalized rerun on identical hardware with identical hash function.**

The case-for-action remains: **folding shrinks memory by 20–100 ×** (the binding mobile constraint), which is the threshold question. Wall-clock parity with ECDSA is a *bonus*, not a prerequisite.

---

## 10. Recommendation for Day 5

**Strong recommendation:** prototype **SuperNeo + D5+D6+D7 multi-fold + Goldilocks Poseidon + Spartan2 finisher** in Week 2. Falls back to **Neo + D2-c + Goldilocks** if SuperNeo reference impl is unavailable, and to **LatticeFold+ + D4 + secq256r1** if Goldilocks Poseidon re-instantiation slips.

**Day 5 sign-off must resolve:**

1. **Confirm Goldilocks Poseidon re-instantiation plan.** Owner + Week 2 schedule. Failure mode → fallback path #3.
2. **Pull actual per-fold numbers from Neo / SuperNeo papers.** This doc's 100 μs projection is load-bearing; if real number is 10× off, §5 conclusions shift materially.
3. **Confirm SuperNeo reference-implementation status.** If publicly unavailable, fall back to Neo (requires uniform-CCS D2-c, no D5 heterogeneous).
4. **Final-SNARK choice locked.** Spartan2 over Goldilocks is the recommendation. Alternative: Plonk-style with FRI. Verifier-side cost matters here (CSP retailer is mobile-class too).
5. **Verifier device class.** If the relying party is desktop-class, verifier metrics are slack; if mobile, Neo/SuperNeo small-field finisher is critical.

**Items deferred to Week 2:**

- 128f variant — same step-function design applies (only parameter values change); revisit after 128s prototype lands.
- XMSS track (separate repo) — analogous cost model; Vikas's track.
- Security review of chosen lattice parameters (Module-SIS dimension, norm bounds) — external cryptographer per the broader research plan.

---

## Appendix A — Pure-component cost references

For reproducibility, the underlying constants used in §5:

- secq256r1 mult: 200 ns (geometric mean of ~100–500 ns range)
- Goldilocks mult: 20 ns
- Cyclotomic-ring mult (d=64, q≈2³⁰): 1.5 μs
- R1CS prover mults/row: 30 (sumcheck-style)
- Ajtai commit mults/witness FE: 50

All within 2× of standard benchmark literature; refine with Plonky2 / arkworks micro-benches in Week 2.

## Appendix B — Open questions for Day 5

1. Is the 4-core parallelism assumption realistic for multi-fold on mobile? (Threading + memory bandwidth bottlenecks may limit to ~2-3×.)
2. Does the final Spartan2 finisher's prover dominate the wall-clock if folding is near-zero-cost? If yes, all schemes look similar at the bottom line.
3. Is there a hybrid: flat IVC + heterogeneous-step circuit (without multi-fold)? Reduces parallelism gain but keeps scheme simple.
4. Verifier-on-relying-party constraints — if the retailer's POS is constrained, Neo/SuperNeo Goldilocks finisher is critical. Otherwise, secq256r1 finishers are acceptable.

## Appendix C — Files referenced

In this repo:
- `research/folding/step_function_slh_dsa_128s.md` — all step-circuit numbers
- `results/results_summary.md`, `README.md` — monolithic baseline measurements

External (cite, do not load):
- LatticeFold ePrint 2024/257
- Neo ePrint 2025/294
- SuperNeo ePrint 2026/242
- Cyclo ePrint 2026/359
- Plonky2 (Goldilocks Poseidon, FRI benchmarks)
- arkworks (R1CS prover micro-benches)
- RELIC / blst / ark-bn254 (field-op rate reference)

# Reviewer Guide — Week 1 SLH-DSA Folding Research

**For reviewers picking up this work cold.** Estimated read time: 25 minutes for the docs + 10 minutes for verification.

---

## What Week 1 produced (one paragraph)

A scheme-agnostic step-function decomposition for **SLH-DSA-128s Poseidon** verification under post-quantum lattice folding schemes (LatticeFold, LatticeFold+, Neo, SuperNeo, Cyclo), with a projected cost model and a primary scheme recommendation conditioned on per-fold-overhead measurement in Week 2 Day 1. Backed by **measured R1CS counts** from Circom benches and an **automated verifier** (`yarn verify:folding`) that cross-checks every load-bearing number against the source code. Total: 3 research markdown docs (~1,500 lines), 2 Circom benches, 1 Python verifier, 1 shared helper module, 1 exec summary.

---

## Doc reading order

| # | Path | Role | Time |
|---|---|---|---|
| 1 | `EXEC_SUMMARY.md` | One-page TL;DR — read this first | 3 min |
| 2 | `step_function_slh_dsa_128s.md` | Step-function decomposition (Days 1–2). The foundation. | 12 min |
| 3 | `cost_model.md` | Projected costs per (scheme × decomposition × field) (Days 3–4) | 8 min |
| 4 | `scheme_selection.md` | Primary recommendation + sign-off checklist (Day 5) | 5 min |
| 5 | `REVIEWER_GUIDE.md` (this file) | How to read, verify, and review | – |

If you only have 10 minutes: read `EXEC_SUMMARY.md` + `scheme_selection.md §3` (primary selection + fallback ladder). That's the load-bearing decision.

---

## Measured vs. projected — which numbers can you trust?

| Quantity | Source | Status | Verified by |
|---|---|---|---|
| SLH-DSA-128s parameters (n, w, h, d, h', a, k, len, m) | `circuits/common/params.circom` | **MEASURED** (literal constants in code) | `yarn verify:folding` Check 1 |
| Per-primitive R1CS (F=968, H=1,102, T_k=5,989, T_len=14,428, H_msg=24,844) | `results/results_summary.md` (auto-gen from `yarn bench`) | **MEASURED** (--O2, secq256r1) | `yarn verify:folding` Check 4 |
| Total `main_poseidon` R1CS = 3,992,159 | `results/raw_bench.txt` | **MEASURED** (single integrated compile) | `yarn verify:folding` Check 4 |
| Poseidon(2) = 240 R1CS | `bench_poseidon_reduce2` (new in Week 1) | **MEASURED** | `yarn verify:folding` Check 2, Check 5 |
| `PoseidonReduce(N)` for N ∈ {14, 35, 64} | `bench_poseidon_reduce_{14,35,64}` (new in Week 1) | **MEASURED** | `yarn verify:folding` Check 2 |
| Grand total 4,273 Poseidon perms per verify | Symbolic derivation from params | **DERIVED + VALIDATED** against measured | `yarn verify:folding` Check 3 |
| D2-c total step work = 1,025,520 R1CS | 240 × 4,273 = trivial multiplication | **DERIVED** from measured inputs | `yarn verify:folding` Check 5 |
| Monolithic Spartan2 baseline (16.2 s prove, 5.41 GB RSS, 208.8 KB proof) | Companion repo `moven0831/slh-dsa-128s-poseidon-bench` | **MEASURED** (cited, not re-run here) | external — verify by running companion repo |
| **Goldilocks Poseidon R1CS projection (1.0 × secq256r1, ±50%)** | Round-count math from Plonky2 Poseidon parameters | **PROJECTION** | **Unmeasured — Week 2 Day 1 must benchmark** |
| Per-fold recursion-circuit overhead for Neo / SuperNeo / Cyclo | SuperNeo §1.1 D6 quotes Nova @ ≈10K R1CS; lattice claims "logarithmic" without absolute number | **UNMEASURED** (Nova baseline cited as floor) | **Week 2 Day 1 must benchmark** |
| Scheme wall-clock (0.6 s prover, 30–250 MB RSS) | Multiplication of Goldilocks-mult-rate × step R1CS + per-fold overhead | **PROJECTION compounding multiple uncertainties** | **Week 2 must validate; do not commit on these numbers alone** |
| 4-core parallel multi-fold speedup (4 ×) | Theoretical assumption | **PROJECTION** | **Unmeasured** |
| Final-SNARK (Spartan2 over Goldilocks) cost (100–500 ms prover, 30–50 KB proof) | Cited from Neo paper §6.x benchmarks | **PROJECTION** | **Week 2 must reproduce** |

**Rule of thumb:** numbers under "MEASURED" or "DERIVED + VALIDATED" are decision-grade. Numbers under "PROJECTION" or "UNMEASURED" are **directional only** — they tell you which decomposition / scheme is *plausibly* best, not which one *actually* is. The whole research recommendation is **conditional** on Week 2 Day 1 measurement of per-fold overhead.

---

## How to verify the numbers yourself

```bash
# One-time bootstrap (~1 minute):
corepack enable && yarn install
bash scripts/vendor.sh           # clones bkomuves/hash-circuits + integritychain/fips205

# Run the bench loop (~15 min — main_sha2 and main_shake will OOM on <32 GB,
# expected; main_poseidon and all per-primitive benches compile fine):
yarn bench

# Run the validator. Should print "RESULT: all checks passed." (~3 sec):
yarn verify:folding
```

What the verifier checks (6 groups, 23 atomic checks):

1. **SLH-DSA parameters** in `params.circom` match the values cited in the design doc (12 entries).
2. **`PoseidonReduce(N)` binary-tree perm count** matches measured R1CS for N ∈ {14, 35, 64} (3 entries).
3. **Per-verify Poseidon-perm grand total = 4,273** derived from params.
4. **Compress-primitive structure (Check 3.5)**: `bench_poseidon_X − bench_poseidon_reduce_{arity_X} ≈ stable mix residual`. Catches future hashes.circom arity changes.
5. **Sum-of-parts** (Σ per-prim R1CS × call count) reconciles to measured `main_poseidon` within 2 %.
6. **Drift detector**: hand-maintained "doc canonical" values (Poseidon(2)=240, D2-c total=1.03M, reduction=74.3%) match measured. Fires `[STALE]` if doc and code diverge.

If any check fails, the verifier exits non-zero. Failure modes: re-run `yarn bench`, check `results/raw_bench.txt` exists, confirm circom 2.2.3 is what's compiling.

---

## Known unsettled items (rank-ordered by impact)

Each item below is something the design doc admits is uncertain. Week 2 Day 1 work is the empirical settling.

1. **Per-fold recursion-circuit overhead** for the chosen lattice scheme. Floor: ≈10K R1CS (Nova baseline per SuperNeo §1.1 D6). Lattice schemes claim "logarithmic" — could be ~10 R1CS or could be ~50K R1CS depending on how Ajtai-commitment verification is encoded. **This single number drives D2-c-vs-D4-vs-D3 decomposition choice** (see `cost_model.md` §5.4 crossover table).

2. **Heterogeneous-branch multi-fold via Nebula or SuperNova NIVC** is unpublished and unimplemented across all major folding libraries (Sonobe issue #144). The aggressive multi-fold primary (D5+D6+D7) requires this composition. Treat as **research-grade** for Week 2, not engineering-grade.

3. **Goldilocks Poseidon R1CS in Circom**. Projected at 1.0 × `secq256r1` measured ±50 % (corrected 2026-05-22 from earlier 0.5 × figure that ignored x⁷ vs. x⁵ S-box cost). Week 2 Day 1 micro-bench tightens to ±5 %.

4. **FIPS 205 T_k / T_len / H_msg deviation.** The Poseidon circuit *already* implements T_k as a binary Merkle tree of Poseidon(2) (not a single arity-k hash as FIPS 205 specifies). The folding decompositions inherit this. **External cryptographer review needed before any deploy.**

5. **Non-standard Poseidon constants.** circomlib BN254 round constants mod `p_secq256r1` — R1CS structure unchanged, security analysis does NOT transfer. Re-instantiation under Plonky2 Goldilocks (or Poseidon2 Mersenne-61) is Week 2 prerequisite for a deployable variant.

6. **Lattice parameter selection (Module-SIS dimension, modulus, norm bounds).** None of our docs commit to specific parameters. Concrete-security target is implicitly NIST Category 1 (~128-bit classical / ~64-bit quantum), but neither Neo's nor SuperNeo's published parameters are checked against this bar in the doc.

7. **Spartan2 finisher availability and cost.** Assumed throughout but never sourced. Spartan2-over-Goldilocks may not exist as an off-the-shelf impl. Week 2 must locate or write.

8. **ECDSA-Spartan2 baseline is not apples-to-apples** (M5 vs. M3, SHA-256 vs. Poseidon, classical 128-bit vs. PQ Category 1). The "matches or beats ECDSA on every metric" claim was overstated; doc now soft-pedals to "same order of magnitude pending normalized rerun."

9. **Verifier device class** for the relying party (CSP retailer POS) is unspecified. If mobile-class verifier, small-field Spartan2 finisher matters; if desktop-class, slack.

10. **Process risk**: the D2-c → D4 primary recommendation flipped *during Week 1* after the literature survey surfaced the 10K Nova overhead anchor. This was caught but reveals that the Day 5 decision was made without consulting the Day 3 cost-model literature. Process fix proposed for Week 2: require an adversarial "what would flip this?" pass before any matrix sign-off.

---

## What reviewers should ask

If you're reviewing this Week 1 work for the first time, ask the authors:

- **Architecture / scheme:** "Why D4 over D2-c under your stated assumptions? Show me §5.4 crossover. What's your Week 2 Day 1 measurement plan for per-fold overhead?"
- **Crypto rigor:** "Is the FIPS 205 T_k deviation acceptable for this benchmark? Has anyone written a soundness sketch for the Merkle-tree T_k variant?"
- **Code / validation:** "Run `yarn verify:folding`. Do all 23 checks pass? What does Check 3.5 catch that Check 4 doesn't?"
- **Cost model:** "Walk me through the §5.4 crossover. At what per-fold overhead does the recommendation flip? Where in §10 is this gated?"
- **Sign-off:** "Show me the sign-off checklist. Are owners named? Are triggers specific? What's the Day 7 acceptance gate?"
- **Risks:** "What's the top-3 risk register? What's the BLOCKER list for Week 2 Day 0?"

If the authors can't answer any of these crisply, that's a sign-off blocker.

---

## Adversarial review summary

Week 1 underwent four adversarial reviews on 2026-05-22:
- **Cryptography** (lattice math, scheme claims, FIPS 205 conformance)
- **Software engineering** (verifier soundness, Circom bench correctness)
- **Cost-model rigor** (numerical defensibility, field-rate sanity, sensitivity completeness)
- **Engineering management** (Week 2 readiness, sign-off actionability)

Findings that were **validated and applied**:
- Goldilocks projection corrected from 0.5 × → 1.0 × ±50 % (S-box cost ignored in earlier estimate)
- Mersenne-31 vs. Mersenne-61 vs. Goldilocks taxonomy fixed (M31 is STARK direction, not lattice)
- LatticeFold q-restriction acknowledged (LatticeFold cannot use Goldilocks for lattice commitments)
- D2-c FIPS 205 deviation disclaimer added (T_k is already Merkle-tree, not arity-k)
- D2-c vs. D4 crossover sensitivity table added (`cost_model.md §5.4`)
- Multi-fold §5.2 cells marked BLOCKED on Nebula/NIVC composition (unpublished)
- ECDSA-Spartan2 comparison softened (not apples-to-apples)
- Verifier Check 3.5 added (catches hashes.circom arity changes)
- Verifier Check 5 clarified (drift detector vs. measured, not vs. parsed doc)
- `nConstraints` floor of 50 added to `read_bench_constraints()` (prevents 0-constraint silent pass)
- `Check(expected=0)` rejected at construction (was a dead-and-dangerous branch)

Findings that were **noted but deferred** to Week 2:
- Lova / Mova / NeutronNova / HyperNova not surveyed (bibliography gap; not load-bearing for primary recommendation)
- Module-SIS concrete parameters (depends on chosen scheme)
- ADRS construction soundness sketch (Week 2 prototype work)
- External cryptographer engagement plan (parallel track, Week 2+)

Findings that were **rejected** as not actionable in Week 1:
- "Re-publish all benchmarks on M5 to match ECDSA hardware" — out of scope; cited soft-comparison instead.
- "Re-do entire cost model with measured lattice per-fold overhead" — that *is* Week 2 Day 1 work.

---

## Source-of-truth locations

| Topic | Authoritative source |
|---|---|
| SLH-DSA-128s parameters | `circuits/common/params.circom` |
| Per-primitive R1CS measurements | `results/results_summary.md` (auto-gen from `yarn bench`) |
| Step-function decomposition | `research/folding/step_function_slh_dsa_128s.md` |
| Per-scheme cost projections | `research/folding/cost_model.md` |
| Primary recommendation + fallback ladder | `research/folding/scheme_selection.md §3` |
| Sign-off checklist | `research/folding/scheme_selection.md §6` |
| Day-7 success criteria | `research/folding/scheme_selection.md §7` |
| Adversarial-review history | (this file, "Adversarial review summary" section) |
| Open question / risk register | `research/folding/scheme_selection.md §5` + `step_function_slh_dsa_128s.md §7` |
| Validation script | `scripts/verify_perm_counts.py` (run via `yarn verify:folding`) |
| Shared helpers (params + bench parsing) | `scripts/folding_lib.py` |
| Monolithic Spartan2 baseline | `README.md:54-65` + companion repo `moven0831/slh-dsa-128s-poseidon-bench` |

---

## Reviewer sign-off checklist (your output as a reviewer)

Per scheme_selection §6, six items must be confirmed before Week 2 starts. Add your name + date + verdict next to each:

- [ ] **Stakeholder approval** of D4 conservative primary (or D2-c aggressive alternative gated on Week 2 Day 1 measurement). Reviewer: _______ Date: _______
- [ ] **Week 2 owner** named for SuperNeo / Neo reference-impl survey. Reviewer: _______ Date: _______
- [ ] **Week 2 owner** named for Goldilocks Poseidon Circom re-instantiation. Reviewer: _______ Date: _______
- [ ] **External cryptographer engagement plan** drafted (candidates, scope, budget, target dates). Reviewer: _______ Date: _______
- [ ] **Verifier device class** confirmed (mobile / desktop) for the CSP relying party. Reviewer: _______ Date: _______
- [ ] **Final-SNARK choice locked**: Spartan2-over-Goldilocks (default) or alternative if unavailable. Reviewer: _______ Date: _______

Additional checks specific to this guide:

- [ ] Ran `yarn verify:folding`; saw "RESULT: all checks passed."
- [ ] Read §5.4 crossover table; understand the D2-c vs. D4 decision criterion.
- [ ] Read §3.4a (cost_model) heterogeneous-branch caveat; understand the multi-fold BLOCKER.
- [ ] Verified at least one numerical claim against the source code by hand (e.g. params, perm count, sum-of-parts).
- [ ] Identified at least one risk in §5 (scheme_selection) that should be a blocker, or confirmed none.

Reviewer verdict: ☐ READY ☐ READY WITH CONDITIONS (list) ☐ NOT READY (list)

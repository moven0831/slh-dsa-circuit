# Executive Summary — Week 1 SLH-DSA Folding Research

**Status:** Week 1 complete (Days 1–5). Sign-off conditions in `scheme_selection.md §6`.

---

## Question we set out to answer

Can client-side proving (≤1 GB RAM, ≤2 s wall-clock) of an SLH-DSA-128s signature verifier work on a mobile-class device using a post-quantum folding scheme?

Monolithic Spartan2 baseline (M3/24 GB, companion repo) measures **16.2 s prove / 5.41 GB peak RSS / 208.8 KB proof**. The 5.41 GB RSS is the **binding constraint** — past the mobile ceiling.

## What we decided

**Primary recommendation (conservative): D4 (per-XMSS-layer flat IVC) on Neo or SuperNeo + Goldilocks Poseidon + Spartan2 finisher.**

- 9 fold steps × 573 K R1CS step circuit = ~5.2 M R1CS total prover step-work
- 8.4 × less total prover work than the alternative D2-c (per-arity-2-chain, 4,273 folds × 240 R1CS) **under the published Nova-class fold-overhead baseline (≈10 K R1CS per fold)**
- Projected peak RSS: 30–250 MB (folding loop only) — well under the 1 GB mobile ceiling

**Conditional alternative (aggressive): D2-c flat IVC** — wins **only if** Week 2 Day 1 measurement shows the chosen lattice scheme delivers per-fold overhead < 1.1 K R1CS. Neo / SuperNeo claim "logarithmic recursion overhead" which would put us there, but the claim is **unmeasured**.

**Fallback ladder** (`scheme_selection.md §3.3`): A' → B' (LatticeFold+ + D4 + Goldilocks Poseidon) → C' (LatticeFold+ + D4 + secq256r1) → D' (LatticeFold+ + D3 sub-layer + secq256r1) → re-evaluate monolithic.

## Top 3 risks (Week 2 must close)

1. **Per-fold overhead is unmeasured.** Drives the entire D4 vs. D2-c vs. D3 decision. **Week 2 Day 1 micro-bench.** Floor estimate: 10 K R1CS (Nova baseline, SuperNeo §1.1 D6). Ceiling: 50 K R1CS (lattice ring-poly verification in-circuit). Until measured, all wall-clock numbers in §5 are directional.
2. **Heterogeneous-branch multi-fold (D5+D6+D7) is unpublished and unimplemented.** Neo / SuperNeo natively do k-to-1 *same-shape* folding only. The aggressive multi-fold path requires layering SuperNova/NIVC or Nebula switchboard — unpublished composition, Sonobe issue #144 confirms no open-source lib supports it as of 2026-05. **Treat as research-grade, not engineering-grade.**
3. **FIPS 205 deviation.** The Poseidon circuit *already* implements T_k as a binary Merkle tree of Poseidon(2), not the single arity-k hash FIPS 205 specifies. Plus circomlib BN254 constants used mod `p_secq256r1` — non-standard. **External cryptographer review required before any production deploy** — not a Week 2 blocker for prototype, but a release blocker.

## What's measured vs. projected

**Measured (decision-grade):**
- 12 SLH-DSA-128s parameters in `circuits/common/params.circom`
- Per-primitive R1CS: F=968, H=1,102, T_k=5,989, T_len=14,428, H_msg=24,844
- Monolithic `main_poseidon`: 3,992,159 R1CS
- Poseidon(2) = 240 R1CS (new in Week 1)
- PoseidonReduce(N) for N ∈ {14, 35, 64} = 3,357 / 9,108 / 15,120 R1CS (new in Week 1)
- 4,273 Poseidon perms per verify (derived from params + measured reduce structure, validated by `yarn verify:folding`)

**Projected (directional only):**
- Goldilocks Poseidon R1CS ≈ 1.0 × secq256r1 measured ± 50 % (corrected from earlier 0.5 × estimate which ignored x⁷ vs. x⁵ S-box cost)
- Per-scheme prover wall-clock (uses unmeasured per-fold overhead — Week 2 Day 1 settles)
- Peak prover RSS = 30–250 MB (folding loop) + finisher peak (unmeasured)

## How to verify

```bash
yarn install && bash scripts/vendor.sh && yarn bench && yarn verify:folding
```

Should print "RESULT: all checks passed." Six check groups, 23 atomic checks; each cross-references a specific load-bearing claim in the design doc against the source code or measured benches.

## Week 2 acceptance gate (proposed)

End of Week 2: prototype the chosen (scheme × decomposition × field) end-to-end. Acceptance:
- Full SLH-DSA-128s verify proved under chosen scheme.
- Prover wall-clock ≤ 2.0 s, peak RSS ≤ 1 GB, proof size ≤ 500 KB on M3/24 GB single-core.
- All §5.2 cost-model projections validated within 2 × or the recommendation revised.
- Per-fold overhead measurement landed; D2-c vs. D4 decision **locked with empirical evidence**.

## Recommended Week 2 Day 0 actions (before any prototyping starts)

1. Convert `scheme_selection.md §6` sign-off checklist boxes into actionable items: `[ ] decision — Owner: <name> — Trigger: <event> — Evidence: <artifact>`. ~2 hrs.
2. Write `research/folding/week2_prereqs.md`: env, pinned deps, reference-impl URLs (Neo / SuperNeo / Nethermind LatticeFold), Goldilocks Poseidon source pin. ~4 hrs.
3. Confirm verifier device class for the CSP relying party (mobile vs. desktop). Cascades to scheme + field choice. ~1 day stakeholder time.
4. XMSS-track coordination memo (same scheme? same field? shared Poseidon?). ~half day.

Total Week 2 Day 0 effort: **~1.5–2 engineer-days**, not a re-do.

---

**Reading order:** [REVIEWER_GUIDE.md](REVIEWER_GUIDE.md) → [step_function_slh_dsa_128s.md](step_function_slh_dsa_128s.md) → [cost_model.md](cost_model.md) → [scheme_selection.md](scheme_selection.md).

**Validation command:** `yarn verify:folding`.

**Authors / Owners:** _<to be filled before sign-off>_.

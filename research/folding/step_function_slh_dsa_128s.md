# Step-function design for SLH-DSA-128s folding (Poseidon variant)

**Status:** Week 1 Days 1–2 deliverable, draft. Input to the Week 1 Day 3 folding-scheme cost model.

**Scope:** SLH-DSA-128s only, Poseidon variant. Scheme-agnostic — covers both flat-IVC and multi-fold (Neo/SuperNeo-style hierarchical) decompositions. Cost columns for both `secq256r1` (measured) and Goldilocks (projected, ±25%).

**Companion plan:** the plan that produced this doc lives at `/Users/moventsai/.claude/plans/plan-for-the-step-function-purring-porcupine.md` (harness path) and may be archived to `research/folding/_plans/`.

---

## 1. Summary

- **3,929 SLH primitive calls** per SLH-DSA-128s verify (3,689 F + 231 H + 1 T_k + 7 T_len + 1 H_msg) ⇒ **4,273 Poseidon permutations** (binary `PoseidonReduce` expansion) ⇒ **3,992,159 R1CS** measured in `main_poseidon` (--O2, `secq256r1`).
- **Monolithic Spartan2 baseline** (companion repo, M3/24GB, T256HyraxEngine): 16.2 s prove / 5.41 GB peak / 208.8 KB proof / 2.37 GB proving key. **Memory is the binding constraint** for client-side proving — folding must shrink the peak RSS, not just the wall-clock.
- **Recommended primaries for Day 3 cost model:**
  - **Flat-IVC primary:** D2-c — *per-primitive step circuit with variable-arity `PoseidonReduce`s re-expressed as arity-2 Poseidon chains* (Sec 7.1 option c). Effective fold count **4,273**, uniform arity-2 step **= 240 R1CS measured** (`bench_poseidon_reduce2`, `secq256r1`, --O2) / **≈ 120 R1CS projected ±25 %** (Goldilocks), state width ≈ 16 FE. **Total D2-c step work ≈ 1.03 M R1CS, a 74 % reduction vs. the 3.99 M monolithic.**
  - **Multi-fold primary:** D5+D6+D7 — *per-primitive heterogeneous leaves, per-tree/per-WOTS-pk mid folds, single top fold* (Sec 4b). Maps SLH-DSA's natural tree structure 1:1 onto Neo/SuperNeo's k-to-1 + heterogeneous-branch shape.
- **Variable-arity reduces** (`SlhTk` = 14→1, `SlhTlen` = 35→1, `SlhHMsg` = 64→1) are the central design issue. Resolution: arity-2 chain for flat IVC (uniform step), native heterogeneous arity for multi-fold (no padding, no chain overhead). Both routes are mapped in Sec 7.1.
- **Largest open issue:** Goldilocks Poseidon re-instantiation. Current Poseidon uses circomlib BN254 constants mod `p_secq256r1` (non-standard, `CLAUDE.md:123-125`). Goldilocks projection here carries ±25% uncertainty; if Day 3 is sensitive to that band, allocate Day 4 to a quick Goldilocks Poseidon prototype.
- **Final-SNARK choice** (Spartan2-on-lattices vs. separate Plonk vs. recursive SNARK) is **not** a step-function decision — flagged for Day 5 scheme-selection.

---

## 2. Current verifier inventory

### 2.1 Per-primitive Poseidon-permutation and R1CS counts

Source: `circuits/poseidon/hashes.circom`, `circuits/poseidon/poseidon_wrap.circom`, `results/results_summary.md:9-13`.

| Primitive | Poseidon perms / call (binary `PoseidonReduce`) | Input shape (after byte packing) | Output | R1CS / call (--O2, `secq256r1`) | State carried? |
|---|---|---|---|---|---|
| `SlhF` | 1 (arity 11 — `Poseidon(10)`, t=11) | tag(1) + pk_seed(1) + ADRS(7) + M(1) = 10 FE | 16 B (low 128 bits of 1 FE) | **968** | no |
| `SlhH` | 1 (arity 12 — `Poseidon(11)`, t=12) | tag(1) + pk_seed(1) + ADRS(7) + M(2) = 11 FE | 16 B | **1,102** | no |
| `SlhTk` | 15 (14 reduce + 1 mix) | k=14 FE roots + ADRS + tag | 16 B | **5,989** | no |
| `SlhTlen` | 39 (38 reduce + 1 mix) | len=35 FE WOTS endpoints + ADRS + tag | 16 B | **14,428** | no |
| `SlhHMsg` | 65 (63 reduce + 2 mix `Poseidon(5)`) | R + pk_seed + pk_root + M[1024 B] | 30 B (low 128+112 bits) | **24,844** | no |

Reduce-tree counts derived from `circuits/poseidon/poseidon_wrap.circom:91-117`: `PoseidonReduce(N)` is a binary tree with `ceil(N/2)` pairs at each level (odd inputs paired with zero). Cost: `ceil(N/2) + ceil(N/4) + … + 1` Poseidon(2) perms. For N=14: 7+4+2+1 = 14. For N=35: 18+9+5+3+2+1 = 38. For N=64: 32+16+8+4+2+1 = 63.

**Validated against measurement** (`scripts/verify_perm_counts.py`, --O2, `secq256r1`):

| Reduce | Expected perms × P(2)=240 R1CS | Measured R1CS | Δ |
|---|---|---|---|
| `PoseidonReduce(14)` | 14 × 240 = 3,360 | 3,357 | −3 (−0.09 %) |
| `PoseidonReduce(35)` | 38 × 240 = 9,120 | 9,108 | −12 (−0.13 %) |
| `PoseidonReduce(64)` | 63 × 240 = 15,120 | 15,120 | 0 (exact) |

Residuals are wire-routing overhead, not extra perms. This confirms that **(i) every `PoseidonReduce(N)` invocation is exactly the binary-tree perm count above, and (ii) one Poseidon(2) costs 240 R1CS in this codebase** — the canonical step-circuit unit for the D2-c flat-IVC primary (Sec 8).

### 2.2 Per-layer R1CS breakdown

Source: `results/results.md` §C, integration delta validated at +0.9% against measured total.

| Layer | R1CS | Notes |
|---|---|---|
| H_msg | 24,844 | 1 call, M = 1024 B fixed (FIPS 205 §11.2.1 + non-standard Poseidon ADRS encoding) |
| FORS (leaves + auth + compress) | ≈199.7 K | 14·F + 168·H + 1·T_k |
| HT WOTS chains | ≈3.56 M | 3,675 × F (7 layers × 35 chains × 15 steps) |
| HT WOTS compress | ≈100.9 K | 7 × T_len |
| HT Merkle paths | ≈69.4 K | 63 × H (7 layers × 9 levels) |
| Glue (range, mux, decode) | ≈34.8 K | Non-hash overhead (digest parse, base-2b, ADRS construction) |
| **Total measured** | **3,992,159** | `main_poseidon`, --O2 |
| Sum-of-parts | 3,957,343 | Σ(per-prim R1CS × call count); integration delta = +0.9% |

### 2.3 Monolithic Spartan2 baseline (the bar folding must beat)

Source: `README.md:54-65` (companion repo `moven0831/slh-dsa-128s-poseidon-bench`, T256HyraxEngine / Hyrax-PC over `secq256r1`, M3/24GB).

| Phase | Time | Peak RSS | Artifact | Size |
|---|---|---|---|---|
| Setup | 23.1 s | **10.45 GB** | Proving key | 2.37 GB |
| Witness | 1.4 s | – | – | – |
| Prove | 16.2 s | **5.41 GB** | **Proof** | **208.8 KB** |
| Verify | 9.5 s | 3.11 GB | Verifying key | 2.37 GB |

**Critical observation:** setup-phase peak RSS is 10.45 GB — already past the OOM ceiling on a 24 GB device with any concurrent app load. Prove-phase peak is 5.41 GB, separately past the mobile ceiling (~1 GB working set). **Both phases need folding-class reshaping for a mobile target.** Schemes with transparent setup (LatticeFold, Neo, SuperNeo, Cyclo — all in scope here) sidestep the 10.45 GB number by deriving public parameters from a seed, so the cost-model only needs to compare against the prove-phase 5.41 GB. The case-for-action is memory, not wall-clock — folding lets the prover hold one step circuit (≈KB) plus the running accumulator (≈MB) in memory at a time, instead of the full witness + setup data (≈3.86 M wires × 32 B for the witness plus ~GB of commitment-tree intermediate state under Hyrax PCS).

### 2.4 Poseidon-variant caveat

Per `CLAUDE.md:123-125` and `README.md:11,132-134`: this circuit uses **circomlib BN254 Poseidon constants mod `p_secq256r1`**. The construction is non-standard — R1CS structure (and thus all R1CS numbers above) is unchanged from the BN254 instance, but **security analysis does not transfer**. These are benchmark numbers only.

The Goldilocks projections in Section 5 assume a re-instantiation under a Goldilocks-safe Poseidon variant (Plonky2-style: ~8 full + ~22 partial rounds at t=12). Section 7.2 flags the re-instantiation cost.

---

## 3. SLH-DSA-128s parameters + symbolic hash-call formulas

### 3.1 Parameter set (FIPS 205 Table 2, Category 1 "small")

Source: `circuits/common/params.circom`.

| Param | Value | Meaning | Source |
|---|---|---|---|
| n | 16 | hash output / security parameter (bytes) | `params.circom:6` |
| w | 16 | Winternitz parameter | `:13` (`lg_w = 4`, `:12`) |
| len1 | 32 | `ceil(8n / lg_w)` | `:15` |
| len2 | 3 | `floor(log2(len1·(w−1))/lg_w) + 1` | `:16` |
| **len** | **35** | **WOTS+ chains per signature** (len1 + len2) | `:17` |
| h | 63 | total hypertree height | `:7` |
| d | 7 | XMSS layers | `:8` |
| h' | 9 | XMSS subtree height (h/d) | `:9` |
| a | 12 | FORS auth path depth (2^a = 4,096 leaves/tree) | `:10` |
| k | 14 | FORS trees per signature | `:11` |
| m | 30 | H_msg digest length (bytes) | `:14` |

Project-specific: M (signed message) is fixed at 1024 B (`params.circom:20`); KATs are filtered accordingly.

### 3.2 Symbolic per-verify hash-call counts

| Primitive | Formula | Count |
|---|---|---|
| F | k + d·len·(w−1) | 14 + 7·35·15 = **3,689** |
| H | k·a + d·h' | 14·12 + 7·9 = 168 + 63 = **231** |
| T_k | 1 | **1** |
| T_len | d | **7** |
| H_msg | 1 | **1** |
| **Total SLH primitive calls** | | **3,929** |

### 3.3 Symbolic Poseidon-permutation count (binary `PoseidonReduce`)

| Source | Perms per call | Calls | Total perms |
|---|---|---|---|
| H_msg | 65 (63 reduce + 2 mix) | 1 | 65 |
| FORS F (leaves) | 1 | 14 | 14 |
| FORS H (auth) | 1 | 168 | 168 |
| FORS T_k (compress) | 15 (14 reduce + 1 mix) | 1 | 15 |
| FORS subtotal | | | **197** |
| HT F (WOTS chains) | 1 | 3,675 | 3,675 |
| HT T_len (compress) | 39 (38 reduce + 1 mix) | 7 | 273 |
| HT H (XMSS Merkle) | 1 | 63 | 63 |
| HT subtotal | | | **4,011** |
| **Grand total** | | | **4,273 Poseidon perms** |

**Discrepancy footnote:** `README.md:25` mentions "Poseidon 1× / SHA-2 31× / SHAKE 150× at F (3,675 invocations / verifier)" but does not give a total Poseidon-perm count for the verifier. An earlier rough estimate of "~5,500" appears in some upstream artifacts — likely an over-count from treating each `PackBytes16ToFe` as a Poseidon perm (it is not — it's `Num2Bits` + a linear combination). **4,273 is canonical for this doc.**

`3,929` is the natural fold count for **per-primitive flat-IVC**. `4,273` is the fold count for **per-Poseidon-perm flat-IVC**. Both appear in Section 5.

---

## 4. Candidate step-function decompositions

For each candidate: one paragraph defining the step circuit, what crosses the boundary (witness/state shape), and the natural fold count.

### 4a. Flat IVC (linear chain, 2-to-1 fold, uniform-shape step)

**D1 — Fine-grained (1 Poseidon perm / step).** Step circuit = one Poseidon permutation + state update. Native arity varies (2 for reduces, 5 for HMsg mixes, 11 for SlhF mix, 12 for SlhH mix). To keep a uniform step shape, pad all perms to a fixed arity — but padding arity-2 reduces to arity-12 is ≈3× wasteful; this option only makes sense if the folding scheme tolerates branching. State carried across steps: (running root[16 B], primitive-selector, ADRS[7 FE], layer/tree/chain/leaf indices, sub-step counter) ≈ 12–16 FE. **Fold count: 4,273.**

**D2 — Per-primitive (1 SLH primitive / step).** Step circuit selects among {F, H, T_k, T_len, H_msg} via a primitive-type selector. The variable-arity `PoseidonReduce` inside T_k, T_len, H_msg is the central design issue (Section 7.1) with three sub-variants:
- **D2-a (pad):** pad all reduces to fixed arity 64 — uniform step, ~60–70 % wasted work on T_k/T_len.
- **D2-b (unroll):** unroll each reduce inside the step — H_msg becomes a 65-perm step, dominating the cost; not uniform.
- **D2-c (chain):** re-express each reduce as a sequence of arity-2 Poseidon perms handled as separate fold steps — uniform arity-2 step, adds 116 fold steps total (14 + 38 + 63 + 1 mix-pair, distributed across T_k/T_len/HMsg). **Recommended.**

State carried: running root + indices ≈ 16 FE.

| D2 variant | Fold count | Step shape | Step R1CS (secq256r1) |
|---|---|---|---|
| D2-a (pad-64) | 3,929 | uniform arity-64 reduce step | ≈25K (H_msg dominates) |
| D2-b (unroll) | 3,929 | non-uniform (arity 1–65 inside step) | 968 – 24,844 |
| **D2-c (chain)** | **4,273** | **uniform arity-2 Poseidon** | **≈213 R1CS** |

**D3 — Sub-layer (one WOTS chain or one Merkle level / step).** Step circuit handles a bounded sequence of SLH calls: one WOTS chain (15 F-steps + ADRS update) **or** one auth-path level (1 H call + ADRS update). State carried: 32 FE (current root + path/chain index + layer counter + ADRS sub-fields). Fold count: 7·35 (WOTS chains) + 7·9 (XMSS Merkle) + 14·12 (FORS Merkle) + 14 (FORS leaves) + 7 (T_len) + 1 (T_k) + 1 (H_msg) = **669**. Step circuit ≈ 15 Poseidon perms worst case (a WOTS chain).

**D4 — Per-XMSS-layer (one HT layer per step, dedicated FORS and H_msg steps).** Step circuit handles a full XMSS subtree verification: 35 WOTS chains + 1 T_len compress + 9 Merkle hashes = 573 Poseidon perms. State carried: 16 FE (xmss_root forward + tree_idx + leaf_idx). Fold count: **9** (1 H_msg + 1 FORS + 7 HT layers).

### 4b. Multi-fold (hierarchical, Neo / SuperNeo-style)

Neo / SuperNeo support k-to-1 folding (multiple instances merged at once) **and** heterogeneous branches (different step-circuit shapes folded together at the same level). SLH-DSA-128s verification is naturally tree-shaped — 14 FORS trees with k=14 leaves each, 7 HT layers each with 35 WOTS chains — which maps 1:1 onto multi-fold.

**D5 — Leaf level: per-primitive heterogeneous step circuits.** Grouping by **Poseidon arity** (the shape that determines step-circuit CCS), there are **4 distinct branches**, with instance counts deriving from FIPS 205 §11.2.2:

| Branch | Poseidon arity | Sources | Instance count |
|---|---|---|---|
| **F-step** | Poseidon(10) | F leaves (3,689) + Tk-mix (1) + Tlen-mix (7) | **3,697** |
| **H-step** | Poseidon(11) | H leaves | **231** |
| **Reduce2-step** | Poseidon(2) | Tk reduce (14) + Tlen reduce (7 × 38 = 266) + HMsg reduce (63) | **343** |
| **HMsg-mix-step** | Poseidon(5) | The two final mix perms with domain-separation tags 0 and 1 | **2** |
| **Total** | — | — | **4,273** |

Tk-mix and Tlen-mix fold into the F-step branch because they share Poseidon(10) shape; the differing domain-separation tag (2 vs. 3 vs. 0) is a public-input choice, not a structural one. ADRS construction inside each branch is per-step overhead (~50–200 R1CS based on `bench_adrs_sanity` = 198), not a separate fold branch.

**D6 — Mid level: per-tree / per-WOTS-pk folds.**
- **Per-FORS-tree fold:** 14 FORS trees, each a leaf+auth-path bundle. Within each tree: 1 F (leaf) + 12 H (auth path) = 13 leaf instances. Mid fold combines 13 instances → 1 per-tree accumulator. 14 per-tree accumulators feed into the FORS-roots reduce (D2-c chain). **Fold operations: 14 (one per tree)**, each with k=13.
- **Per-WOTS-pk fold:** 7 HT layers, each containing 35 WOTS chains. Within each layer: 35 chain instances (each chain = 15 F leaves) + 14 (T_len reduce chain) + 1 (T_len mix) + 9 (Merkle H) = 59 leaf instances. Mid fold per layer combines these → 1 per-layer accumulator. **Fold operations: 7 (one per HT layer)**, each with k=59.

**D7 — Top level: single fold combining all branches.** Combines (1 H_msg accumulator + 1 FORS accumulator + 7 HT-layer accumulators) → 1 final accumulator. **Fold operations: 1**, k=9.

**State at fold boundaries:**
- Per-tree / per-layer accumulators: ≈16 FE (the layer's output root) + scheme-specific accumulator state.
- Top accumulator: ≈32 FE.

**Critical-path depth:** With native-k folds, multi-fold is **3 levels deep** (leaf → mid → top), versus flat IVC's 4,273-step linear chain. Same total prover work, but the tree shape enables per-branch parallelism on the prover and avoids the variable-arity padding tax.

### 4.6 Where these boundaries fall in code

| Decomposition | Code-boundary anchor |
|---|---|
| D1, D2, D5 | Inside `circuits/poseidon/hashes.circom` primitive call |
| D2-c reduce expansion | Inside `circuits/poseidon/poseidon_wrap.circom:91-117` `PoseidonReduce` recursion |
| D3 (WOTS chain) | `circuits/common/wots.circom` chain-step loop |
| D3 (Merkle level) | `circuits/common/{fors,xmss}.circom` auth-path loop |
| D4 (per-XMSS-layer) | `circuits/common/ht.circom:49-90` HT-layer iteration |
| D6 (per-WOTS-pk) | `circuits/common/xmss.circom` `XmssPkFromSig` template scope |
| D6 (per-FORS-tree) | `circuits/common/fors.circom` per-tree loop |
| D7 (top) | `circuits/common/slhdsa_verify.circom` top-level wiring |

---

## 5. Cost table

### 5.1 Goldilocks projection methodology

> **Goldilocks Poseidon** (e.g. Plonky2 t=12 with ~8 full + ~22 partial rounds) has roughly **0.4–0.6× the round count** of the current circomlib BN254 Poseidon (~8 full + ~57 partial rounds at comparable widths). R1CS row count per perm scales approximately linearly in round count (Circom partial-round optimization compresses but does not eliminate the cost difference). **Projected Goldilocks R1CS / perm ≈ 0.5 × secq256r1 measured ± 25%.** Mark all Goldilocks columns **PROJECTED ± 25%** — the Day 3 cost model must propagate this uncertainty. The 25% band tolerates (i) different Goldilocks Poseidon variants (Plonky2 vs. Poseidon2 vs. Tip5), (ii) Circom's per-field partial-round optimization differences, and (iii) the small contribution of byte-packing (Num2Bits) constraints whose cost is largely field-independent.

### 5.2 Cost table per decomposition

| ID | Decomposition | Step Poseidon perms | Step R1CS (secq256r1, measured base) | Step R1CS (Goldilocks, projected ±25%) | Fold count | State width (FE) | Σ Step·R1CS (informational, see footnote) | Notes |
|---|---|---|---|---|---|---|---|---|
| D1 | Flat fine (1 perm/step, padded arity-12) | 1 | ≈660 | ≈330 | 4,273 | ~16 | ≈2.82 M | Underestimate — excludes padding overhead in heterogeneous-arity case |
| D2-a | Flat per-primitive (pad-64) | up to 65 | ≈25 K | ≈12.5 K | 3,929 | ~16 | ≈98 M | Pathological — pad waste dominates |
| D2-b | Flat per-primitive (unroll) | 1–65 | 968 – 24,844 | 484 – 12,422 | 3,929 | ~16 | **3.96 M** (matches monolithic ± 1 %) | Non-uniform step shape |
| **D2-c** | **Flat per-primitive (arity-2 chain)** | **1** | **240 measured** | **≈120** | **4,273** | **~16** | **≈1.03 M** | **Uniform; recommended flat-IVC primary** |
| D3 | Flat sub-layer | 1–15 | ≈1.1 K – 15 K | ≈0.55 K – 7.5 K | 669 | ~32 | ≈3.0 M | Worst-case step: WOTS chain |
| D4 | Flat per-XMSS-layer | ≈573 | ≈573 K | ≈287 K | 9 | ~16 | ≈3.96 M | Single largest step; near-monolithic memory profile |
| **D5** | **Multi-fold leaves (heterogeneous)** | **1** (per branch) | **240 – 1,102** measured | **120 – 551** | **4,273** (distributed) | **~16 / branch** | **≈1.03 – 1.2 M** | **Recommended multi-fold primary, with D6+D7** |
| D6 | Multi-fold mid (per-tree / per-WOTS-pk) | accumulator only | ≈2 K – 4 K | ≈1 K – 2 K | 14 (FORS) + 7 (HT) = 21 | ~16 / branch | overhead only | Mid-level accumulator + verifier of branch summary |
| D7 | Multi-fold top | accumulator only | ≈3 K | ≈1.5 K | 1 | ~32 | overhead only | Combines all branches |

**Footnote on the Σ Step·R1CS column.** This is `step_R1CS × fold_count` — a **step-work proxy**, not the prover wall-clock. Total prover wall-clock = (Σ Step·R1CS × mults-per-R1CS) + (fold_count × per-fold accumulator-update overhead). The fold overhead depends on the scheme and is computed in `cost_model.md` §5. Do **not** read "D2-c is 1.03 M vs monolithic 3.99 M" as "D2-c is 4× faster" — it's the same arithmetic work, reshaped; the prover speedup comes from (i) Goldilocks field ops being 20–50× faster than `secq256r1`, (ii) fold overhead being amortized over many small steps. See cost_model §2.2.

**Σ Step·R1CS sanity check.** D2-b (flat per-primitive unroll) should equal monolithic within ~1 % since it is the same circuit reshaped. Indeed: 968·3,689 + 1,102·231 + 5,989·1 + 14,428·7 + 24,844·1 = **3,957,343 R1CS** vs. measured 3,992,159 ⇒ delta = +0.87 % (matches `README.md:35-36` integration delta). Automated check: `python3 scripts/verify_perm_counts.py`. Other rows differ from monolithic because reductions are double-counted (D2-a) or partially eliminated by replacing arity-k Poseidons with chains of arity-2 (D2-c, D5).

**Why D2-c gives lower Σ Step·R1CS than monolithic.** The arity-2 chain replaces every `Poseidon(t)` for t > 2 inside reduces with a Merkle tree of `Poseidon(2)` (240 R1CS each, measured by `bench_poseidon_reduce2`). For SlhTk (1 call): the monolithic does Poseidon(10) + reduce-perms ≈ 5,989 R1CS, the chain does 15 × 240 = 3,600 R1CS — 40 % cheaper at the constraint-count level. Summed over all primitives: 4,273 × 240 = 1.03 M R1CS vs. 3.96 M monolithic = **74 % step-work reduction**. The improvement is real but it is **step work**, not prover wall-clock; the dominant prover-side win comes from the Goldilocks field-op speedup in cost_model §5.

**Fold overhead (per scheme).** Day 3 must add scheme-specific fold-overhead numbers from the LatticeFold / Neo / SuperNeo benchmark tables. Approximate placeholders (re-derive on Day 3):
- LatticeFold: per-fold prover overhead dominated by Ajtai commitment of the new instance + accumulator-norm refresh. Order of ~10⁴–10⁵ Goldilocks-equivalent multiplications per fold.
- Neo (small-field Ajtai, pay-per-bit): per-fold overhead lower, ~10³–10⁴ mults.
- SuperNeo: removes Neo's SIMD restriction; per-fold cost similar to Neo.

For 4,273 folds at ~10⁴ mults each, fold overhead alone is ~4 × 10⁷ mults — comparable to step-circuit work for D2-c, so accumulator overhead is the binding cost, not step work. **Day 3 must verify this before finalizing.**

---

## 6. Step-circuit shape proposals

For the three decompositions that are viable as Day 3 primaries — D2-c (flat-IVC primary), D3 (flat-IVC fallback), D5+D6+D7 (multi-fold primary) — specify signal layout, sub-circuits, ADRS derivation, and selector logic.

### 6.1 D2-c — Flat per-primitive with arity-2 reduce chain

**Signal layout** (one fold step):
- **Public input `z_i`** (running state, ~16 FE): `(running_root_fe, primitive_type, layer, tree_idx_hi, tree_idx_lo, leaf_idx, chain_idx, wots_step, reduce_subidx)`. The `primitive_type` ∈ {F, H, Tk_mix, Tlen_mix, HMsg_mix, Reduce2} discriminates the step shape.
- **Witness `w_i`** (primitive-specific):
  - For F/H: ADRS sub-fields (the values that haven't already been derived from `z_i`) + the message FEs being hashed (1 for F, 2 for H).
  - For Tk_mix / Tlen_mix: ADRS + the previously-computed reduce output.
  - For HMsg_mix: (R, pk_seed, pk_root, reduce_output).
  - For Reduce2: the two children FEs being combined.
- **Public output `z_{i+1}`** (~16 FE): updated state with `running_root_fe` ← Poseidon output, indices advanced by selector logic.

**Sub-circuits reused** from `circuits/`:
- `circuits/poseidon/poseidon_wrap.circom` `PoseidonHash16` for arity ≤ 16 perms.
- `circuits/poseidon/poseidon_wrap.circom` `PackBytes16ToFe` / `UnpackFeToBytes16` for byte↔FE conversion at the H_msg input and primitive output (lift these *outside* the fold loop where possible).
- `circuits/common/{wots,fors,xmss,ht,slhdsa_verify}.circom` — *do not* reuse the integrated templates directly; instead reuse their ADRS-construction logic.

**ADRS derivation inside the step.** ADRS depends on `(layer, tree_high, tree_low, type_, keypair, chain, hash)`. To prevent the prover lying about which call is being verified, all 7 ADRS sub-fields **must be derived from public state `z_i`**, not passed as fresh witness. Concretely:
- `layer`, `tree_high`, `tree_low` are public-input state carried verbatim from the previous step.
- `type_` is set by the step's `primitive_type` selector (e.g. F-step inside WOTS sets `type_ = ADRS_TYPE_WOTS_HASH = 0` per `params.circom:36`).
- `keypair`, `chain`, `hash` are derived from `z_i.leaf_idx`, `z_i.chain_idx`, `z_i.wots_step` according to FIPS 205 §4.2.

**Selector logic.** A single one-hot vector `sel[6]` (one bit per primitive type) gates which branch contributes to the next-state update. Unused branches are zeroed cheaply with linear constraints `out_unused === 0` rather than skipped — Circom's --O2 will optimize away the dead constraints in synthesis, but the step circuit's CCS row count includes all branches' constraint counts. **Total step R1CS = max(F, H, Reduce2) + selector overhead ≈ max(968, 1102, 240) + ~50 ≈ 1,152** if the step circuit instantiates all branches. **For uniformity it is cheaper to commit only to the arity-2 Poseidon sub-step (Reduce2) and dispatch F/H as separate step types** — splitting the fold count further but keeping the uniform 240-R1CS step.

This is the "fully chain" extreme — every Poseidon perm of any arity becomes its own fold step, padded to arity-2 if smaller, decomposed if larger. **Reconsider on Day 3** whether the uniform-step cost (240 R1CS × 4,273 fold steps = 1.03 M) beats the heterogeneous-step cost (selector overhead × 4,273 fold steps) given the scheme's per-fold overhead.

### 6.2 D3 — Flat sub-layer (one WOTS chain / one Merkle level per step)

**Signal layout**:
- **Public input `z_i`** (~32 FE): `(current_root, layer, tree_idx, chain_idx, step_type)` where `step_type` ∈ {wots_chain, fors_merkle_level, xmss_merkle_level, fors_leaf, tk_chain, tlen_chain, hmsg_chain, finalize}.
- **Witness `w_i`** depends on step_type:
  - `wots_chain`: 16 B message digit, 15 ADRS variations (one per chain step), 15 intermediate hash outputs.
  - `*_merkle_level`: sibling node (16 B), ADRS for this level.
  - etc.
- **Public output `z_{i+1}`** (~32 FE): updated `current_root` + advanced indices.

**Sub-circuits reused**: same as D2-c plus the WOTS-chain unrolled `for`-loop from `circuits/common/wots.circom` (lift the loop body into the step).

**ADRS derivation**: ADRS for each sub-step inside the chain is derived from `z_i` + a sub-step counter that the step circuit increments internally. The step verifies the 15 internal ADRS instances against expected values derived from `z_i.chain_idx`.

**Selector logic**: 8-way selector on `step_type`. Step R1CS dominated by `wots_chain` branch (~15 × 968 ≈ 14.5K). Other branches are much smaller but still allocated CCS rows in the universal step.

**Caveat.** D3 is a useful fallback if D2-c's fold count (4,273+) makes per-fold overhead dominate. The 15:1 amortization vs. D2-c saves on accumulator cost but loses uniformity.

### 6.3 D5+D6+D7 — Multi-fold (per-primitive leaves, per-tree/per-WOTS-pk mid, single top)

**Leaf-level step circuits (D5).** Four branch shapes grouped by Poseidon arity (per Section 4b):
- **F-step**: Poseidon(10), R1CS ≈ 968 (measured, includes packing). 3,697 instances (F leaves + Tk-mix + Tlen-mix; tag-differentiated via public input).
- **H-step**: Poseidon(11), R1CS ≈ 1,102 (measured). 231 instances.
- **Reduce2-step**: Poseidon(2), **R1CS = 240 measured** (`bench_poseidon_reduce2`). 343 instances (14 Tk reduce + 266 Tlen reduce + 63 HMsg reduce).
- **HMsg-mix-step**: Poseidon(5), R1CS ≈ 380 (projected from circomlib Poseidon round structure; not separately benched). 2 instances.

ADRS construction inside each branch is per-step overhead (~50–200 R1CS based on `bench_adrs_sanity` = 198), not a separate fold branch. Each branch has its own public-input/witness/public-output shape but they share the same CCS form (Neo/SuperNeo can fold heterogeneous-shape branches into a single accumulator as long as each branch's CCS is uniform within itself).

**Per-tree / per-WOTS-pk mid step circuits (D6).**
- **Per-FORS-tree branch**: combines 13 leaf instances (1 F + 12 H per tree). The branch's step circuit verifies the leaf accumulator structure + computes the tree root. R1CS ≈ ~2K (dominated by the branch's Lasso-style lookup proving each leaf belongs to this tree).
- **Per-WOTS-pk branch**: combines 35 chain instances + 14 reduce-chain instances + 1 T_len-mix + 9 Merkle-H instances per HT layer. R1CS ≈ ~4K.

**Top step circuit (D7).** Combines 1 H_msg accumulator + 1 FORS accumulator (which itself combines 14 per-tree accumulators + a reduce-chain for the SlhTk mix) + 7 HT-layer accumulators. R1CS ≈ ~3K.

**ADRS derivation.** Each leaf branch derives its ADRS from the **mid-level accumulator's public-input state**, which the mid-step has committed to. The top step verifies that the per-tree and per-layer ADRS prefixes are consistent (e.g. `layer = 0` for FORS, `layer ∈ {1..7}` for HT layers). This is more constrained than flat-IVC's running ADRS state — the multi-fold scheme proves ADRS *correctness* once per fold level rather than per perm.

**Selector logic.** Heterogeneous branches use Neo/SuperNeo's native branch-selection mechanism (per the scheme's CCS form). No padding required.

---

## 7. Open design issues

### 7.1 Variable-arity `PoseidonReduce`

`SlhTk` reduces 14 → 1, `SlhTlen` 35 → 1, `SlhHMsg` 64 → 1 (`circuits/poseidon/hashes.circom:115,153,192`). Three options:

| Option | Description | Pros | Cons |
|---|---|---|---|
| **(a) Pad** | Pad all reduces to a single max arity (e.g. 64). | Uniform step. | Wasteful: 50–60 % padding on SlhTk, ~45 % on SlhTlen. |
| **(b) Native heterogeneous** | Per-primitive native arity in the step circuit. | No padding. | Needs heterogeneous-branch step support (multi-fold has this natively; flat IVC needs internal branch selection at constraint cost). |
| **(c) Arity-2 chain** | Re-express each reduce as a Merkle tree of `Poseidon(2)` steps; treat each `Poseidon(2)` as one fold step. | Uniform arity-2 step (~213 R1CS), no padding. | Adds (N−1) fold steps per reduce — 116 extra steps total. Increases accumulator overhead at the prover. |

**Recommendation.** (c) for flat IVC primary (D2-c) — fold scheme's per-step overhead is amortized over many tiny steps, and the uniformity simplifies the scheme integration. (b) for multi-fold primary (D5) — Neo/SuperNeo handle heterogeneous branches natively, no padding tax.

### 7.2 Goldilocks Poseidon re-instantiation

Current circuit uses **circomlib BN254 Poseidon constants** mod `p_secq256r1` (`CLAUDE.md:123-125`, `README.md:11,132-134`). For Neo / SuperNeo / Cyclo, which target small fields (Goldilocks-family), Poseidon must be re-instantiated under a Goldilocks-safe variant:

- **Constants:** Plonky2 / Poseidon2 / Tip5 publish ready-to-use round constants and MDS matrices for Goldilocks at common widths.
- **Implementation cost:** ~1–2 engineer-days to replace `circuits/poseidon/poseidon_wrap.circom` and re-generate all measurements.
- **Security:** Goldilocks Poseidon variants have published security analyses (see Poseidon2 paper). External review still recommended before any deploy.
- **R1CS impact:** Goldilocks Poseidon has 0.4–0.6× the round count of circomlib BN254 Poseidon ⇒ projected R1CS per perm shrinks by the same factor (Section 5.1 methodology).

**Action item.** If Day 3 cost model is sensitive to the Goldilocks ±25% band, allocate Week 1 Day 4 to a quick Goldilocks Poseidon prototype to tighten the constant to ±5 %.

### 7.3 Final SNARK choice

Folding produces an accumulated instance; a succinct closing proof is still required to fix the prover's claim. **Not a step-function decision** — flagged for Day 5 scheme-selection:

- **Spartan2 over the same lattice commitments.** Cleanest if achievable; Spartan2-on-lattices is research-grade (LatticeFold's authors have a prototype, but production-readiness is unclear).
- **Separate Plonk-style SNARK on the accumulator.** Forces an extra commitment scheme; verifier cost on the relying party matters here.
- **Recursive SNARK to compress.** Adds prover complexity for verifier ergonomics.

**Affects the step-function design only via verifier-side cost** — if the final SNARK is heavy, multi-fold's smaller accumulator (D7's ~32 FE top state) becomes more valuable than flat IVC's larger linear chain.

### 7.4 128f variant comparison

SLH-DSA-128f has ~3× more F invocations (11,583 vs. 3,689) but may benefit *more* from folding because amortization improves with fold count. From `results/hash_based_analysis.md` §2.1: 128f total R1CS ≈ 371 M (SHA-2) vs. 128s 122 M; Poseidon variant scales similarly (~3×). **Defer 128f prototyping to Week 2** after 128s lands; the step-function design here generalizes (only parameter values change).

---

## 8. Recommendation for Day 3 cost model

### 8.1 Primary decompositions to model

**Flat-IVC primary: D2-c** (per-primitive with arity-2 reduce chain).
- Step circuit: uniform arity-2 `Poseidon(2)` + state update.
- Step R1CS: **240 measured** (`bench_poseidon_reduce2`, `secq256r1`, --O2) / **≈ 120 projected ±25 %** (Goldilocks).
- Fold count: 4,273.
- State width: ~16 FE.
- Total step work: **1,025,520 R1CS** (`secq256r1`) ≈ **0.51 M** (Goldilocks).
- **Reduction vs. monolithic 3.99 M: 74 % step-work reduction.** Prover wall-clock reduction is larger because Goldilocks field ops are 20–50× faster than `secq256r1` (see cost_model §5).
- **Reason chosen:** smallest uniform step (exercises folding-scheme amortization maximally); uniform shape simplifies scheme integration (no heterogeneous-branch CCS); largest gap to monolithic baseline.

**Multi-fold primary: D5+D6+D7** (per-primitive heterogeneous leaves, per-tree/per-WOTS-pk mid, single top).
- Step circuits: 5 leaf branches (155–660 R1CS each, depending on arity) + 2 mid branches (≈2–4 K R1CS) + 1 top step (≈3 K R1CS).
- Fold operations: 4,273 leaves → 21 mid folds (14 FORS + 7 HT) → 1 top fold. Critical-path depth: 3 levels.
- State width: ~16 FE per branch, ~32 FE at top.
- **Reason chosen:** matches SLH-DSA's natural tree structure 1:1; avoids variable-arity padding entirely; supports per-branch parallelism on the prover (important for client-side multi-core CPUs); 3-level depth maps directly onto Neo/SuperNeo's k-to-1 + heterogeneous-branch shape.

### 8.2 What would change this recommendation

The Day 3 cost-model spreadsheet must compute total wall-clock prover time = step work + fold overhead × fold count. Specific numbers from the scheme papers that, if they come in *worse* than expected, would push us toward alternatives:

- **If LatticeFold/Neo/SuperNeo per-fold overhead at the prover is > ~10⁵ Goldilocks-mults per fold:** D2-c's 4,273 folds × 10⁵ = 4.3 × 10⁸ mults dominates the ≈ 0.46 M R1CS step work. Push toward D3 (sub-layer, 669 folds) or D4 (per-XMSS-layer, 9 folds) to reduce fold count even at the cost of larger steps.
- **If the scheme's accumulator size grows linearly in fold count:** multi-fold's logarithmic accumulator growth becomes essential; abandon flat IVC.
- **If the final SNARK over the accumulator costs > ~10× the prover step work:** the smaller accumulator from multi-fold (D7's compact top state) is critical; multi-fold becomes the only viable path.
- **If Goldilocks Poseidon prototype (Day 4) shows projected costs are > 0.7× secq256r1 (band's high end):** the Goldilocks advantage shrinks; consider staying on `secq256r1` and using a folding scheme that supports large fields (LatticeFold over cyclotomic rings) instead of Neo/SuperNeo over Goldilocks.

### 8.3 Hand-off to Day 3

The Day 3 cost-model spreadsheet should pull:

1. **Step R1CS** from Section 5 (one number per (decomposition × field) cell).
2. **Fold count** from Section 5.
3. **State width** from Section 5 (affects accumulator commitment cost).
4. **Per-fold overhead** from each scheme's paper benchmark table (LatticeFold ePrint 2024/257; Neo ePrint 2025/294; SuperNeo ePrint 2026/242). **Not in this doc** — Day 3 owner derives.
5. **Final-SNARK cost** — Day 5 deliverable; placeholder in the Day 3 spreadsheet for now.

---

## Appendix A — Numerical sanity checks performed

All numerical claims in this doc are validated by `scripts/verify_perm_counts.py` against measured benchmarks (`results/raw_bench.txt`). Run after `yarn bench` to regenerate; the script exits non-zero on any reconciliation failure.

- **All 12 SLH-DSA-128s parameters** in `circuits/common/params.circom` match the values cited in §3.1. ✓
- **`PoseidonReduce(N)` binary-tree perm count** validated by 3 measured benches:
  - `bench_poseidon_reduce_14` = 3,357 R1CS vs. expected 14 × 240 = 3,360 (Δ −0.09 %)
  - `bench_poseidon_reduce_35` = 9,108 R1CS vs. expected 38 × 240 = 9,120 (Δ −0.13 %)
  - `bench_poseidon_reduce_64` = 15,120 R1CS vs. expected 63 × 240 = 15,120 (Δ 0.00 %) ✓
- **Poseidon(2) = 240 R1CS measured** (`bench_poseidon_reduce2`). This is the canonical step-circuit unit for the D2-c flat-IVC primary.
- **Per-verify Poseidon-perm grand total = 4,273** derived from binary `PoseidonReduce` (Section 3.3); matches the script's symbolic derivation exactly. README's earlier "~5,500" figure remains an artifact of an older estimate (likely over-counted byte-packing as Poseidon perms) — not relied on by this doc. ✓
- **Sum-of-parts R1CS = 3,957,343** vs. measured `main_poseidon` = 3,992,159 ⇒ **delta +0.87 %** (glue: range checks, mux, digest parse, base-2b, ADRS construction). Matches `README.md:35-36` integration delta of +0.9 %. ✓
- **State-width composability** spot-check: D4 (per-XMSS-layer) carries 16 FE (xmss_root + tree_idx + leaf_idx); layer j+1's step circuit reads exactly this shape as its public input. ✓ D2-c carries 16 FE state across every fold step uniformly. ✓
- **D5 multi-fold leaf instance accounting**: 3,697 (F-step, Poseidon(10)) + 231 (H-step, Poseidon(11)) + 343 (Reduce2-step, Poseidon(2): 14 from Tk + 266 from Tlen × 7 + 63 from HMsg) + 2 (HMsg-mix-step, Poseidon(5)) = **4,273**. ✓ Matches §3.3 grand total.

## Appendix B — Files referenced

In this repo:
- `circuits/common/params.circom`
- `circuits/common/slhdsa_verify.circom`
- `circuits/common/{fors,wots,xmss,ht}.circom`
- `circuits/poseidon/hashes.circom`
- `circuits/poseidon/poseidon_wrap.circom`
- `circuits/main_poseidon.circom`
- `results/results.md`, `results/results_summary.md`, `results/hash_based_analysis.md`, `results/raw_bench.txt`
- `README.md`
- `CLAUDE.md`

External (cited but not loaded):
- Companion repo `moven0831/slh-dsa-128s-poseidon-bench` (Spartan2 baseline numbers, `README.md:64`).
- LatticeFold (Boneh, Chen) — ePrint 2024/257.
- Neo (Setty et al.) — ePrint 2025/294.
- SuperNeo — ePrint 2026/242.
- Cyclo — ePrint 2026/359.
- Plonky2 Poseidon, Poseidon2, Tip5 — Goldilocks-safe Poseidon variants for Section 7.2 re-instantiation.

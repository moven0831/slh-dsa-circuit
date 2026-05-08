# Hash-Based PQ Signatures — R1CS Suitability Heuristic

A paper analysis that extrapolates the measured SLH-DSA-128s cost model
in `results/results.md` to every other NIST-approved hash-based
signature scheme: SLH-DSA parameter variants, XMSS / XMSS^MT
(SP 800-208, RFC 8391), and LMS / HSS (SP 800-208, RFC 8554).

The goal is not to ship circuits for these schemes — it is to derive
defensible R1CS-cost projections from a single calibrated artifact
(the measured `main_poseidon` integration delta of +0.9 %) so the CSP
PQ VC research can be steered toward the right primitive without
spending a quarter compiling each candidate.

## TLDR

| Scheme | NIST level | Hash calls | SHA-256 blocks | **R1CS (SHA-2 midstate)** | Stateful |
|---|--:|--:|--:|--:|:-:|
| **LMS_SHA256_M24_H10/W4** | 3 | ~810 | 822 | **~25 M** | yes |
| **LMS_SHA256_M32_H10/W4** | 5 | ~1,090 | 1,076 | **~33 M** | yes |
| **LMS_SHA256_M32_H20/W4** (1 M sigs) | 5 | ~1,100 | 1,096 | **~34 M** | yes |
| **HSS L=2 / LMS_M32_H10/W4** (1 M sigs) | 5 | ~2,180 | 2,152 | **~66 M** | yes |
| **HSS L=2 / LMS_M32_H20/W4** (1 T sigs) | 5 | ~2,200 | 2,192 | **~67 M** | yes |
| **HSS L=3 / LMS_M32_H10/W4** (1 B sigs) | 5 | ~3,270 | 3,228 | **~99 M** | yes |
| **SLH-DSA-128s** *(measured)* | 1 | ~3,929 | 4,013 | **~122 M** | no |
| **XMSS-SHA2_10_256** | 5 | ~3,320 | 4,495 | **~138 M** | yes |
| **XMSS-SHA2_10_192** | 3 | ~2,540 | 5,088 | **~156 M** | yes |
| **XMSSMT-SHA2_20/2_256** (1 M sigs) | 5 | ~6,640 | 8,971 | **~275 M** | yes |
| **LMS_SHA256_M32_H10/W8** | 5 | ~8,710 | 8,725 | **~268 M** | yes |
| **SLH-DSA-128f** | 1 | ~11,840 | 12,095 | **~371 M** | no |
| **XMSSMT-SHA2_60/3_256** | 5 | ~9,960 | 13,627 | **~418 M** | yes |

(Hash-call total is the count of distinct SHA-256 invocations the
verifier performs; R1CS column applies the calibrated 30,700
constraints/SHA-256-block cost from `results/results.md`. Counts
above 1 M are signing capacity, not constraints.)

**Three findings worth changing your mind over.**

1. **LMS at NIST level 5 is ~3.7× cheaper than SLH-DSA-128s at level 1
   in R1CS** — `LMS_SHA256_M32_H10/W4` projects to ~33 M constraints
   versus SLH-DSA-128s's ~122 M, *at higher claimed security*. This
   is purely structural: LMS's chain function is a single SHA-256 call,
   whereas SLH-DSA's WOTS+ chain requires no per-step PRF either, but
   LMS's leaf compression and Merkle path are also cheaper because LMS
   does not embed a ZK-unfriendly hyper-tree (`d=7` for SLH-DSA-128s).

2. **XMSS at level 5 is *more* expensive in R1CS than SLH-DSA-128s at
   level 1** (~138 M vs ~122 M), despite being algorithmically simpler.
   The reason is RFC 8391's `RAND_HASH` construction: every "logical"
   tree-hash invocation in XMSS expands to 1 H plus 3 PRF calls, and
   every WOTS+ chain step expands to 1 F plus 2 PRF calls. SLH-DSA's
   FIPS 205 hashes are the **simple** SPHINCS+ variant — no PRF, no
   bitmask — so each chain step is a single SHA-256 compression.

3. **The dominant variable is SHA-256-compression-blocks-in-the-verifier**,
   not "what scheme name." Once the cost model is extracted to
   `R1CS ≈ blocks × 30,700`, choosing a scheme reduces to counting
   blocks under the FIPS / RFC hash structure of each candidate. The
   counts vary 12× across the table above for the same hash family.

**Heuristic.** A hash-based PQ signature is suitable for R1CS in our
pipeline if its verification has

```
total_SHA256_blocks(scheme) × 30,700 < R1CS_budget
```

and the scheme uses **simple-mode hashing** — i.e., a single SHA-256
invocation per logical tree node, with no per-step `PRF`/bitmask
masking. The simple-mode predicate is the line that separates
`SLH-DSA / LMS / HSS` (cheap) from `XMSS / XMSS^MT` (expensive).

---

## 1. Cost model

The repo's existing measurement gives one calibrated number that
makes everything below tractable: **the cost of a single SHA-256
compression block in this circom configuration is ~30,700 constraints,
and this number is independent of which template invokes it.**

To see why this is well-grounded, divide the per-call costs from
`results/results_summary.md` by the input-block count:

| Primitive  | constraints / call | input blocks | constraints / block |
|------------|--:|--:|--:|
| F          |    30,290 |  1 | **30,290** |
| H          |    30,662 |  1 | **30,662** |
| T_k        |   123,182 |  4 | **30,795** |
| T_len      |   307,106 | 10 | **30,710** |
| H_msg      |   583,273 | 19 | **30,698** |

Spread is ~1 % across primitives that differ by 19× in length and 4×
in invocation count. The number is a property of `circom v2.2.3 --O2`
running circomlib's `Sha256` template on `secq256r1`, not of any
SLH-DSA-specific structure. **It transfers verbatim to any other
scheme using SHA-256 in this pipeline.**

The matching constants for the other two families are equally clean:

| Family        | per-permutation | block size | rate (B / perm) |
|---------------|--:|--|--|
| SHA-256       |    ~30,700 | 64 B | full block |
| Keccak-f[1600] (SHAKE-256) | ~147,000 | n/a | 136 B absorb |
| Poseidon (secq256r1, arity ≤ 11) | ~1,000 | n/a | one permutation per call |

(Keccak ratio derived analogously from `results_summary.md`:
`F=145,568/1=145,568`, `T_k=440,736/3=146,912`, `H_msg=1,182,912/8=147,864`.
Poseidon does not have a "block" — every call is one permutation —
so its analysis below uses per-call counts directly.)

### 1.1 The approximation

For any hash-based signature whose verifier is a sequence of SHA-256
calls, R1CS cost decomposes as

```
R1CS ≈ Σ_call (input_bytes(call) + 9 padded up to 64) × 30,700 + glue
       ────────────────────────────────────────────────────
                      = total compression blocks
```

with `glue ≲ 1 %` empirically (the +0.9 % integration delta on
`main_poseidon` validates this within experimental noise — see §4
below). Per-byte ADRS encoding, `Multiplexer` selection, and bit
decomposition are all in the glue term.

**Important properties of this approximation.**

- **Linear in compression blocks.** Padded-input length is rounded up
  to the next 64-byte boundary (SHA-256's compression block size); each
  block contributes the same ~30,700 constraints whether it is the
  first or the seventeenth.
- **Midstate is a constant subtraction.** When a fixed prefix of the
  hash input fills exactly one or more 64-byte blocks (e.g., FIPS 205
  §11.2.2's `pk_seed || zeros[48]` for SLH-DSA, or RFC 8391's
  `toByte(3,32) || pk_seed` for XMSS PRF when `n=32`), that prefix is
  precomputed once at the top of the circuit. The per-call cost drops
  by `(prefix_blocks) × 30,700`. **Midstate works iff the fixed prefix
  fills an integer number of 64-byte blocks** — that is the algebraic
  precondition.
- **No double-counting.** Each scheme's reference uses *one* SHA-256
  primitive per logical hash; the model does not need to account for
  internal SHA-256 sub-operations. This is why the model's accuracy on
  SLH-DSA is ~1 %, not 10 %.
- **Family-portable.** Substituting `30,700 → 147,000` projects to
  SHAKE; substituting per-permutation Poseidon costs (~1 K each, with
  arity-dependent variation in the 5–25 K range for compressions)
  projects to the non-standard ZK-friendly hash. The total-blocks
  count does not change.

The blocks total is what changes between schemes, and it is a function
of three things: (a) how many "logical" hash invocations the verifier
performs, (b) how many SHA-256 compressions each invocation expands
to, and (c) how many of those compressions can be midstate-amortized.

The next two sections work through each candidate scheme on those
three axes.

---

## 2. Per-scheme derivation

### 2.1 SLH-DSA family (FIPS 205) — measured + parameter sensitivity

#### SLH-DSA-128s (NIST level 1) — *the calibration point*

Already measured in `results/results.md`. Reproducing the breakdown
here for parallelism with the other schemes:

| Component | invocations | blocks/call | blocks |
|---|--:|--:|--:|
| F (WOTS chains + FORS leaves) | 3,675 + 14 = 3,689 | 1 | 3,689 |
| H (FORS auth + XMSS Merkle)   | 168 + 63 = 231     | 1 | 231 |
| T_k (FORS root compression)   | 1                  | 4 | 4 |
| T_len (WOTS pubkey compress)  | 7                  | 10 | 70 |
| H_msg                         | 1                  | 19 | 19 |
| **TOTAL**                     | ~3,929 | | **4,013** |

Predicted: 4,013 × 30,700 = **123.2 M constraints**.
Measured projection (sum-of-parts × per-primitive bench): 121.7 M.
Model error: **+1.2 %**, well within the +0.9 % calibration band.

The blocks-per-call numbers come from FIPS 205 §11.2.2's hash mode:
`F/H/T_l(pk_seed, ADRS_c, M) = SHA-256(pk_seed || zeros[48] || ADRS_c || M)[0..n-1]`.
The 64-byte prefix `pk_seed || zeros[48]` is fixed across all F/H/T_l
calls in one verification, so it is midstate-amortized to one
precomputed `iv_state`. The remaining body is `ADRS_c (22 B) || M`,
which packs into 1, 4, or 10 SHA-256 blocks depending on `|M|`.

#### SLH-DSA-128f (NIST level 1)

Same hash structure as 128s, but with `(h, d, h', a, k) = (66, 22, 3, 6, 33)`
instead of `(63, 7, 9, 12, 14)`. This is the "fast-signing" variant —
it shifts work from the signer to the verifier (more layers, more WOTS
chains).

| Component | invocations | blocks/call | blocks |
|---|--:|--:|--:|
| F (WOTS chains across d=22 layers + FORS leaves) | 11,550 + 33 = 11,583 | 1 | 11,583 |
| H (FORS auth k·a + XMSS Merkle d·h')             | 198 + 66 = 264       | 1 | 264 |
| T_k (FORS root compression of k=33, body 550 B + 64 B prefix → 10 blocks − 1 midstate) | 1 | 9 | 9 |
| T_len (body 582 B + 64 B prefix → 11 blocks − 1 midstate) | 22 | 10 | 220 |
| H_msg                                             | 1                    | 19 | 19 |
| **TOTAL**                                         | | | **12,095** |

Projected: **~371 M constraints**. *Well over circom's hardware
ceiling on the 24 GB test machine; needs 32 GB+ to compile, plus
deeper circuit optimization to be tractable for proving.*

#### Sensitivity to (h, d) — the s-vs-f knob

For SLH-DSA-128s/128f at NIST level 1, halving `d` and increasing `h'`
moves cost from `d × h' × hash_calls_per_layer` (XMSS Merkle) toward
fewer `T_len` calls but more chain hashes per layer. The R1CS-optimal
parameter-set point in FIPS 205's parameter family is `128s`, by ~3×
versus `128f`. There is no published parameter set tuned more
aggressively for verifier cost than 128s.

### 2.2 XMSS family (SP 800-208 / RFC 8391) — the RAND_HASH penalty

XMSS was the simplest-looking candidate from a circuit perspective,
and ends up being one of the most expensive. The reason is structural,
not parameter-driven: RFC 8391's hash composition is the **robust**
SPHINCS+-style construction, where every tree-hash invocation
materializes a fresh per-node hash key and bitmask via `PRF`.

#### Hash structure (RFC 8391 §5.1)

Every SHA-2 instantiation in XMSS follows the form
`SHA-256(toByte(x, 32) || KEY || M)` with domain-separation byte
`x ∈ {0, 1, 2, 3}` for `F, H, H_msg, PRF` respectively. Crucially,
the `KEY` differs per call:

```
chain_step(X, ADRS, SEED):                    # WOTS+ chain advance
    KEY = PRF(SEED, ADRS|key_mask=0)          # 1 SHA-256
    BM  = PRF(SEED, ADRS|key_mask=1)          # 1 SHA-256
    return F(KEY, X XOR BM)                   # 1 SHA-256

RAND_HASH(L, R, ADRS, SEED):                  # binary tree node hash
    KEY  = PRF(SEED, ADRS|key_mask=0)         # 1 SHA-256
    BM_0 = PRF(SEED, ADRS|key_mask=1)         # 1 SHA-256
    BM_1 = PRF(SEED, ADRS|key_mask=2)         # 1 SHA-256
    return H(KEY, (L XOR BM_0) || (R XOR BM_1))  # 1 SHA-256
```

Each WOTS+ chain step costs **3 SHA-256 calls**, and each tree-node
combine in the L-tree and the Merkle path costs **4 SHA-256 calls**.
This is in contrast to FIPS 205 / RFC 8554 where the analogous
operations are *one* SHA-256 call.

#### Block accounting per call

| Primitive | input layout (n=32) | bytes | blocks | midstate? |
|---|---|--:|--:|---|
| F   | `toByte(0,32)` ‖ `KEY(32)` ‖ `M(32)`           |  96 | 2 | **no** (KEY varies) |
| H   | `toByte(1,32)` ‖ `KEY(32)` ‖ `L(32)` ‖ `R(32)` | 128 | 3 | **no** (KEY varies) |
| PRF | `toByte(3,32)` ‖ `SEED(32)` ‖ `ADRS(32)`       |  96 | 2→**1** | **yes** (`toByte‖SEED` = 64 B) |
| H_msg | `toByte(2,32)` ‖ `R‖SEED‖ROOT(96)` ‖ `M(1024)` | 1184 | 19 | no (special prefix) |

For the `n=24` (NIST level 3) parameter sets, `toByte(x, 32) || SEED`
totals 56 B which does **not** fill a SHA-256 block, so the PRF
midstate optimization is unavailable — every PRF call costs 2 blocks
in the n=24 case.

#### XMSS-SHA2_10_256 (NIST level 5) — closest to the candidate row

`(h, n, w) = (10, 32, 16)` ⇒ `len = 67`.

| Step | invocations | blocks/call | blocks |
|---|--:|--:|--:|
| WOTS+ F-step (worst-case `w-1` per chain × len) | 1,005 | 2 | 2,010 |
| WOTS+ PRF (2 per F-step)                        | 2,010 | 1 | 2,010 |
| L-tree H combine (len-1 = 66)                   | 66    | 3 | 198 |
| L-tree PRF (3 per RAND_HASH × 66)               | 198   | 1 | 198 |
| Merkle H combine (h = 10)                       | 10    | 3 | 30 |
| Merkle PRF (3 per RAND_HASH × 10)               | 30    | 1 | 30 |
| H_msg                                           | 1     | 19 | 19 |
| **TOTAL**                                       | | | **4,495** |

Projected: 4,495 × 30,700 = **~138 M constraints**.

Cross-check: total distinct SHA-256 calls = 1,005 + 2,010 + 66 + 198
+ 10 + 30 + 1 = **3,320** — slightly *fewer* than SLH-DSA-128s's
~3,929 calls, but each call is bigger on average (2.1 blocks vs 1.0
block) due to the `toByte‖KEY` prefix overhead.

#### Other XMSS / XMSS^MT parameter sets

| Parameter set | sigs (capacity) | total blocks | R1CS |
|---|--:|--:|--:|
| XMSS-SHA2_10_192       | 2^10 = 1,024  | 5,088 | ~156 M |
| XMSS-SHA2_10_256       | 2^10          | 4,495 | ~138 M |
| XMSS-SHA2_16_256       | 2^16 ≈ 65 K   | 4,531 | ~139 M |
| XMSS-SHA2_20_256       | 2^20 ≈ 1 M    | 4,555 | ~140 M |
| XMSSMT-SHA2_20/2_256   | 2^20 ≈ 1 M    | 8,971 | ~275 M |
| XMSSMT-SHA2_40/2_256   | 2^40          | 9,091 | ~279 M |
| XMSSMT-SHA2_40/4_256   | 2^40          | 17,923 | ~550 M |
| XMSSMT-SHA2_60/3_256   | 2^60          | 13,627 | ~418 M |
| XMSSMT-SHA2_60/6_256   | 2^60          | 26,875 | ~825 M |

**Key observations.**

- **Increasing tree height `h` is nearly free in R1CS** (~12 blocks
  per added level) — XMSS-SHA2_20_256 is only 1.4 % more expensive
  than `_10_256`. The dominant cost is the WOTS+ + L-tree per leaf,
  not the Merkle path.
- **Multi-tree depth `d` is the expensive knob**. Each additional
  XMSS layer is one more WOTS+ + L-tree, which re-incurs the ~4,500
  blocks. So `XMSSMT-SHA2_h/d_256 ≈ d × XMSS-SHA2_h'_256 + H_msg`.
- **The n=24 ("level 3") variants are *more* expensive than n=32**
  in our config, because the misaligned `toByte(x,32)‖SEED(24)`
  prefix breaks PRF midstate.

### 2.3 LMS / HSS family (SP 800-208 / RFC 8554) — direct hashing

LMS is XMSS's cousin in SP 800-208. The authoring choice that matters
for R1CS: LMS does **not** use RAND_HASH. Every hash is a direct
`SHA-256(I || u32(idx) || u16(D_TYPE) || data)` with no per-call PRF,
no bitmask.

#### Hash structure (RFC 8554 §4.3, §5.3)

```
chain step:    H(I || u32(q) || u16(i) || u8(j) || tmp)              55 B
pubkey final:  H(I || u32(q) || u16(D_PBLC=0x8080) || y[0..p-1])     22 + n·p
merkle node:   H(I || u32(r) || u16(D_INTR=0x8383) || L || R)        22 + 2n
message:       H(I || u32(q) || u16(D_MESG=0x8181) || C || M)        22 + n + |M|
```

Each call is a single SHA-256 invocation. The `I` is fixed across one
LMS instance but only 16 B (does not fill a SHA-256 block), so the
midstate optimization does **not** help here — but it does not hurt
either, because the chain step is already a single 64-byte block.

#### Block accounting per call (n=32)

| Primitive | bytes | blocks |
|---|--:|--:|
| chain step          |    55 | 1 |
| pubkey final (W4, p=67) | 16+4+2+32·67 = 2,166 | 34 |
| merkle node         |    86 | 2 |
| message hash (M=1024)   |  1,078 | 17 |

Each of these is **independent of `KEY`** (there is no RAND_HASH key),
so a chain step costs 1 block versus XMSS's 4 blocks per "logical"
chain step (1 F + 2 PRF, with PRF midstate-amortized to 1 block each).

#### LMS_SHA256_M32_H10/W4 (NIST level 5) — *the standout candidate*

`(n, h, w) = (32, 10, 4)` ⇒ `p = 67` (matches XMSS's WOTS+ length at
the same security level).

| Step | invocations | blocks/call | blocks |
|---|--:|--:|--:|
| Chain steps (worst case, p × (2^w - 1) = 67 × 15) | 1,005 | 1 | 1,005 |
| LM-OTS pubkey final (compresses 67 chain endpoints) | 1   | 34 | 34 |
| Merkle path (h = 10)                                | 10  | 2 | 20 |
| Message hash                                        | 1   | 17 | 17 |
| **TOTAL**                                           |     |   | **1,076** |

Projected: 1,076 × 30,700 = **~33 M constraints**.

Total SHA-256 calls = 1,005 + 1 + 10 + 1 = **1,017**. That is **3.9×
fewer hash calls** than SLH-DSA-128s and **3.3× fewer than
XMSS-SHA2_10_256**.

#### LMS-W parameter sensitivity

The Winternitz parameter `w` is LMS's most sensitive R1CS knob:

| LM-OTS choice | p | chain steps | total blocks | R1CS |
|---|--:|--:|--:|--:|
| W1 (p = 265) |  265 |    265 |   ~336 |  ~10 M  |
| W2 (p = 133) |  133 |    399 |   ~470 |  ~14 M  |
| W4 (p = 67)  |   67 |  1,005 |  1,076 |  **~33 M**  |
| W8 (p = 34)  |   34 |  8,670 |  8,725 |  ~268 M |

W1/W2 are R1CS-cheaper but the signature blows up to 8.5 / 4.3 KB
(versus W4's 2.1 KB and W8's 1.1 KB). W8 minimizes signature size at
the cost of an 8× R1CS blowup (because chain steps are `2^w - 1` per
chain). For our application — embed-in-ZK with mid-range mobile
proving — W4 is the sweet spot.

#### HSS — multi-tree LMS

`HSS L=N` chains N LMS instances: the top tree signs the next-level
LMS public key, recursively. Verification cost is `~N × LMS` plus
~constant overhead.

| HSS configuration | sigs (capacity) | blocks | R1CS |
|---|--:|--:|--:|
| HSS L=2, LMS_M32_H10/W4   | 2^20 ≈ 1 M    | 2,152 | ~66 M |
| HSS L=2, LMS_M32_H15/W4   | 2^30 ≈ 1 B    | 2,172 | ~67 M |
| HSS L=2, LMS_M32_H20/W4   | 2^40 ≈ 1 T    | 2,192 | ~67 M |
| HSS L=3, LMS_M32_H10/W4   | 2^30 ≈ 1 B    | 3,228 | ~99 M |

Even **HSS L=3 at 1 B-signature capacity (~99 M R1CS)** is cheaper
than SLH-DSA-128s (~122 M R1CS).

#### SHA-256/192 variants for level 3

`LMS_SHA256_M24_H10/W4` (n=24, NIST level 3) projects to ~**25 M
constraints** — the cheapest standardized hash-based option in the
table, but with the same operational stateful gating as the n=32
variants (see §6).

---

## 3. Comparison and observations

### 3.1 Block counts side by side

| Scheme | NIST level | sigs (capacity) | hash calls | total SHA-256 blocks | R1CS (M) |
|---|--:|--:|--:|--:|--:|
| LMS_M24_H10/W4    | 3 | 1 K   |    819 |   822 |  25 |
| LMS_M32_H10/W4    | 5 | 1 K   |  1,017 | 1,076 |  33 |
| LMS_M32_H15/W4    | 5 | 32 K  |  1,022 | 1,086 |  33 |
| LMS_M32_H20/W4    | 5 | 1 M   |  1,027 | 1,096 |  34 |
| HSS L=2 (H10/W4)  | 5 | 1 M   |  2,034 | 2,152 |  66 |
| HSS L=2 (H15/W4)  | 5 | 1 B   |  2,044 | 2,172 |  67 |
| HSS L=2 (H20/W4)  | 5 | 1 T   |  2,054 | 2,192 |  67 |
| HSS L=3 (H10/W4)  | 5 | 1 B   |  3,051 | 3,228 |  99 |
| **SLH-DSA-128s**      | 1 | unbounded | 3,929 | 4,013 | **122 (measured)** |
| XMSS-SHA2_10_256  | 5 | 1 K   |  3,320 | 4,495 | 138 |
| XMSS-SHA2_10_192  | 3 | 1 K   |  2,541 | 5,088 | 156 |
| XMSSMT 20/2_256   | 5 | 1 M   |  6,640 | 8,971 | 275 |
| LMS_M32_H10/W8    | 5 | 1 K   |  8,712 | 8,725 | 268 |
| SLH-DSA-128f      | 1 | unbounded | 11,839 | 12,095 | 371 |
| XMSSMT 60/3_256   | 5 | 1 Q (2^60) | 9,963 | 13,627 | 418 |

### 3.2 Why the ranking does not match intuition

The original write-up framed XMSS as "the simplest of the four
candidates from a circuit perspective" because its verification is
"just a sequence of SHA-256 calls following a Merkle authentication
path." That framing is correct at the level of *which primitive is
invoked*, but it under-counts *how many invocations* per logical
step. The ranking instead clusters as:

- **Cheap (≲ 4,000 blocks)**: LMS, HSS, SLH-DSA-128s — schemes whose
  hash mode is "one SHA-256 per logical hash."
- **Expensive (> 8,000 blocks)**: XMSS^MT, LMS-W8, SLH-DSA-128f —
  schemes that pay a structural multiplier (3× from XMSS RAND_HASH,
  2^w-1 from LM-OTS chain length, or 3× from SLH-DSA hyper-tree
  depth `d`).

The **simple-mode predicate** is the line that matters. It is the
single cleanest-cut feature for predicting R1CS cost across hash-based
candidates.

### 3.3 The ~3.7× LMS vs SLH-DSA gap, decomposed

SLH-DSA-128s pays ~3,929 hash calls; LMS_M32_H10/W4 pays ~1,017. The
difference comes from three structural choices:

1. **No FORS** (saves 14 leaf F + 168 auth-path H + 1 T_k root = 183
   hashes). FORS exists in SLH-DSA to enable *stateless* signing —
   you can pick a random keypair index and the few-time-signature
   security analysis still holds. LMS gives this up; you must carry
   state.
2. **No hyper-tree** (saves `(d - 1) × (FORS_replacement + WOTS+layer)`).
   SLH-DSA-128s has `d=7` layers; LMS has 1. HSS reintroduces this at
   `~+L × LMS_cost` per added layer.
3. **No T_len pubkey compression** at extra block cost. LMS still
   compresses the OTS pubkey, but as a single `34-block` hash rather
   than 7 separate `10-block` `T_len` calls.

The same arithmetic, applied to XMSS, would say: drop the (1) FORS
saving and (2) hyper-tree saving from the equation but pay (a) 3-PRF
overhead per RAND_HASH, (b) 2-PRF overhead per WOTS+ chain step,
and (c) larger blocks-per-call from the `toByte(x,32)‖KEY` prefix
mode. Net effect: XMSS-SHA2_10_256 ends up roughly tied with
SLH-DSA-128s at the block level, slightly worse.

### 3.4 What the same model predicts for SHAKE and Poseidon

The block counts above are scheme-intrinsic. Multiplying by the
appropriate per-permutation constant gives projections under each
hash family:

| Scheme | SHA-2 (~30.7 K/blk) | SHAKE (~147 K/perm) | Poseidon (~1 K/call*) |
|---|--:|--:|--:|
| LMS_M32_H10/W4    | ~33 M  | ~155 M  | ~1.0 M |
| HSS L=2 (H10/W4)  | ~66 M  | ~310 M  | ~2.0 M |
| HSS L=3 (H10/W4)  | ~99 M  | ~470 M  | ~3.0 M |
| SLH-DSA-128s      | ~122 M (measured) | ~577 M (projected) | **3,992,159 (measured)** |
| XMSS-SHA2_10_256  | ~138 M | ~490 M (SHAKE rate is 136 B → fewer permutations) | ~3.3 M |

*Poseidon entries are non-standard (no FIPS / RFC mapping); they are
shown as a lower bound on R1CS cost if the scheme were redefined over
a ZK-friendly hash. The non-standard caveat from `results.md` §C
("the construction is non-standard, security analysis does not
transfer") applies in full.

LMS-Poseidon at ~1 M constraints is suggestive: a hash-based scheme
with simple-mode hashing over a ZK-friendly hash would project to
*sub-million* R1CS, ~120× cheaper than the measured SLH-DSA-128s.
This is not a deployable target today — there is no NIST-approved
hash-based signature with a Poseidon-style hash — but it is the
ceiling that ZK-friendly hash standardization could unlock.

---

## 4. Validation

The model's accuracy claim — "~1 % on a hash-based PQ scheme in this
pipeline" — rests on one calibration point and one consistency check:

**Calibration: the +0.9 % integration delta on `main_poseidon`.**
The repo's existing measurement compiled the full Poseidon-instantiated
verifier and observed `3,992,159` constraints versus a sum-of-parts
prediction of `3,957,343`. The delta of +0.9 % is the empirical bound
on glue cost (range checks, byte-packing, address muxing, base-2b
digest decoding). All projections in this document use the same
sum-of-parts methodology, so the same +0.9 % calibration applies.

**Consistency: the model reproduces SLH-DSA-128s's measured 121.7 M.**
Recomputing from primitives:
`(3,689 × 1) + (231 × 1) + (1 × 4) + (7 × 10) + 19 = 4,013 blocks`,
× `30,700 ≈ 123.2 M`. Measured projection: 121.7 M. Error: **+1.2 %**.
This is within the calibration band, validating the model on the one
SLH-DSA family member we can verify it on.

**What the model does *not* predict.**

- **Compile-time RAM ceiling.** circom v2.2.3 RAM consumption scales
  ~60–100 B per constraint during R1CS emission. Any projection above
  ~50 M constraints will likely OOM on a 24 GB machine; above ~150 M
  needs 64 GB+. Hardware budget is orthogonal to the per-block model.
- **Witness-generation time.** Linear in nWires, but with substantial
  per-template overhead. Not modeled.
- **Wallet proving time on Spartan2.** Determined by the prover, not
  the constraint count alone. R1CS is the input to that, not the
  output.

**What could break the +1.2 % accuracy.**

- **A new family of glue gadgets.** Schemes with significantly more
  bit-decomposition than SLH-DSA — e.g., a hypothetical scheme that
  uses bitwise ADRS encoding instead of byte-level — would add
  glue cost outside the model. Not relevant for any in-scope scheme.
- **Non-standard hash modes.** The model assumes `Sha256BodyBytes`-style
  templates with midstate already factored. A scheme that demands a
  different SHA-256 wrapper (e.g., truncated initial IV for
  SHA-256/192) would shift the per-block constant by some amount we
  have not measured. The `n=24` rows in this document are flagged
  with this caveat.

---

## 5. The heuristic, refined

A hash-based PQ signature is suitable for R1CS in our pipeline iff
**all four** of the following hold:

1. **Block budget.** `total_SHA256_blocks(verify) × 30,700 ≤ R1CS_budget`,
   with `R1CS_budget` set by the wallet's proving target. For a
   ~50 M target on commodity hardware, the budget allows
   `≤ 1,650 blocks`; for a ~100 M target, `≤ 3,250 blocks`. (LMS_W4
   and HSS_L≤2 fit; SLH-DSA-128s and XMSS_SHA2_*_256 do not without
   bigger hardware.)
2. **Simple-mode hashing.** The scheme's hash function is invoked as
   `SHA-256(prefix || data)` with no per-call PRF-derived key and no
   bitmask. This excludes RFC 8391 XMSS / XMSS^MT — the RAND_HASH
   construction multiplies block count by ~3–4×.
3. **Bounded multi-tree depth `d`.** Every additional XMSS or LMS
   layer in the hyper-tree re-incurs a full WOTS+ + leaf-compression
   cost. Keep `d ≤ 2` if the budget is tight, `d ≤ 3` if it is loose.
4. **Winternitz `w = 4`.** Below `w=4` (`w=1, 2`) the signature
   blows up; above `w=4` (`w=8`) the chain length blows up the R1CS
   cost. `w=4` is the sweet spot for both.

Schemes passing all four predicates, ordered by R1CS cost and
operational complexity:

| Rank | Scheme | R1CS | Sig (KB) | Notes |
|---|---|--:|--:|---|
| **1** | LMS_SHA256_M32_H20/W4 | ~34 M | 2.1 | 1 M sigs, single-tree, W4 |
| **2** | HSS L=2 (H20/W4)      | ~67 M | 4.3 | 1 T sigs, two layers     |
| **3** | HSS L=3 (H10/W4)      | ~99 M | 6.5 | 1 B sigs, three layers   |
| **4** | SLH-DSA-128s          | ~122 M (measured) | 7.9 | **stateless**, level 1   |

The stateless / stateful axis is orthogonal to R1CS cost. Ranks
1–3 are gated on SP 800-208 operational requirements (see §6); rank
4 is gated only on R1CS budget and proving hardware.

For comparison, the **failing** schemes among the analyzed set, with
the predicate they violate:

| Scheme | Fails predicate |
|---|---|
| XMSS-SHA2_*_256       | (2) RAND_HASH |
| XMSS-SHA2_*_192       | (2) + lost PRF midstate |
| XMSSMT-SHA2_h/d_256, d ≥ 2 | (2) + (3) |
| LMS_M32_H10/W8        | (4) chain length |
| SLH-DSA-128f          | (3) hyper-tree depth `d=22` |

---

## 6. Caveats and open questions

### 6.1 Stateful operational requirements gate everything in §5

Every scheme passing the §5 heuristic except SLH-DSA-128s is **stateful**
under SP 800-208. The operational requirements — hardware-enforced
counter monotonicity, durable state commits before signature release,
backup/replication/DR design that cannot reuse a counter — apply to
LMS and HSS exactly as they do to XMSS. The original write-up's note
on XMSS ("gated on whether the WFP issuer can meet the SP 800-208
operational requirements") restates verbatim for LMS / HSS.

If WFP cannot meet those requirements, the entire stateful column
collapses and SLH-DSA-128s becomes the only viable option in this
table — at ~3.7× the R1CS cost of the cheapest stateful candidate.
That is a real cost to assign to the operational gate.

### 6.2 The `n=24` numbers are uncertain at ~10 % level

SP 800-208 §3.4 introduces the SHA-256/192 instantiations for both
XMSS and LMS at NIST level 3. Whether the `toByte(x, 32) || SEED`
prefix is preserved (as RFC 8391 specifies) or shortened to
`toByte(x, 32-n) || SEED` (which would re-enable midstate at `n=24`)
needs primary-source verification of SP 800-208 §3.4 — the public
PDF did not parse cleanly via WebFetch and a direct read is needed.
The `~25 M / ~156 M` figures for the `n=24` rows assume the longer
prefix; a shorter prefix could shave ~25–30 % off these numbers.
This does not move the qualitative ranking: LMS_M24 stays cheaper
than XMSS_192, SLH-DSA-128s stays the only stateless option.

### 6.3 The simple-mode predicate is a circuit choice, not a security
gap

Every projection above assumes the spec-defined hash mode. Nothing
prevents writing a non-standard "simple-mode XMSS" circuit that
ignores the RAND_HASH construction — that circuit would be ~3× cheaper
in R1CS but would *not* verify standard XMSS signatures. The same
caveat that gates the Poseidon results in `results.md` ("benchmarking
only — security analysis does not transfer") applies. We are not
proposing this; we are noting that the cost gap is structural, not
fundamental.

### 6.4 Compile-time RAM ceiling is a hard cliff

Every scheme above ~50 M constraints risks hitting circom's ~4 GB
RAM ceiling on a 24 GB M3 with active swap commit. The hardware
mitigation path (32–64 GB build host) has been validated cheap.
For the schemes above ~150 M (XMSS^MT, SLH-DSA-128f, LMS-W8), even
a 32 GB host may need additional circuit-level optimizations.

### 6.5 Open questions to resolve before fixing a candidate

1. **Operational feasibility of statefulness at WFP scale.** If
   answered "yes," the cheapest viable scheme is LMS_M32_H20/W4
   at ~34 M R1CS (1 M signatures per LMS instance).
2. **Verification of the SP 800-208 §3.4 hash mode for n=24.** Affects
   the ~10 % accuracy band on level-3 numbers.
3. **Wallet proving-time target.** R1CS budget is downstream of
   "what is the maximum acceptable proving time on a mid-range
   Android phone." With Spartan2's proving cost roughly linear in
   `nConstraints` plus a Poseidon-tree commitment cost, the 50 M
   target sets the LMS sweet spot; a 100 M target opens HSS L=2 or
   L=3.
4. **SLH-DSA parameter-set tuning.** Is there room to tune SLH-DSA's
   `(h, d, h', a, k)` further toward verifier cost than 128s? The
   FIPS 205 grid stops at 128s and 128f; a custom (non-standard) tune
   could shift the budget.

---

## 7. Sources

- **NIST SP 800-208**, *Recommendation for Stateful Hash-Based
  Signature Schemes*. October 2020.
  <https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-208.pdf>
  (PDF; binary stream did not parse via WebFetch — parameter-table
  verification cross-referenced via NIST's public summary
  <https://csrc.nist.gov/news/2020/stateful-hash-based-signature-schemes-sp-800-208>
  and the per-scheme RFCs below.)
- **RFC 8391**, *XMSS: eXtended Merkle Signature Scheme*. May 2018.
  <https://datatracker.ietf.org/doc/html/rfc8391>
  (Verified hash modes in §5.1 and the WOTS+ chain / RAND_HASH
  algorithms in §3.1, §4.1.)
- **RFC 8554**, *Leighton-Micali Hash-Based Signatures*. April 2019.
  <https://datatracker.ietf.org/doc/html/rfc8554>
  (Verified LM-OTS parameter table in §4.1, LMS parameter table in
  §5.1, and hash input formats in §4.3 / §5.3.)
- **RFC 9858**, *Additional Parameter Sets for HSS/LMS*. (Referenced
  for HSS; used to confirm that LMS parameter scaling extends to the
  capacity targets used here.)
- **NIST FIPS 205**, *Stateless Hash-Based Digital Signature Standard*
  (SLH-DSA). August 2024. Used for SLH-DSA-128s / 128f parameter
  values (§Table 2) and hash modes (§11.2.2). Vendored in
  `vendor/fips205` at commit `30bac08580aa61f653e5436d1bbacb5ffac446c4`.
- **In-repo measurements**:
  - `results/results.md` — the SLH-DSA-128s SHA-2 / SHAKE / Poseidon
    per-primitive bench results, including the +0.9 % `main_poseidon`
    integration delta that calibrates this document's ~1 % accuracy
    claim.
  - `results/results_summary.md` — auto-generated per-component
    constraint-count table.
  - `results/raw_bench.txt` — circom `--r1cs` raw output that the per-
    block constants were derived from.

---

## 8. Reproducing the projections

The Python snippet below reproduces every R1CS projection in this
document from first principles. It depends on nothing in this repo
except the calibrated `30,700 constraints/SHA-256-block` constant
that comes out of `results/results_summary.md`.

```python
SHA256_BLK = 30_700  # calibrated in results/results.md across F,H,Tk,Tlen,Hmsg

def sha2_blocks(n_bytes):
    # ceil((n_bytes + 9) / 64) — SHA-256 padding adds 0x80 + 8-byte length
    return (n_bytes + 9 + 63) // 64

# --- LMS — RFC 8554 ---
def lms_sha256(n=32, h=10, w=4, M_bytes=1024):
    p_table = {(32,1):265, (32,2):133, (32,4):67, (32,8):34,
               (24,1):200, (24,2):101, (24,4):51, (24,8):26}
    p = p_table[(n, w)]
    chain  = p * (2**w - 1)        * sha2_blocks(16+4+2+1+n)         # 1 blk for n=32
    pubkey = 1                     * sha2_blocks(16+4+2+n*p)
    merkle = h                     * sha2_blocks(16+4+2+2*n)         # 2 blk for n=32
    msg    = 1                     * sha2_blocks(16+4+2+n+M_bytes)
    return chain + pubkey + merkle + msg

# --- XMSS — RFC 8391 ---
def xmss_sha2(n=32, h=10, w=16, M_bytes=1024):
    import math
    lg_w = {2:1, 4:2, 16:4, 256:8}[w]
    len1 = (8*n + lg_w - 1) // lg_w
    len2 = math.floor(math.log2(len1*(w-1))/lg_w) + 1
    lenw = len1 + len2
    F_blk   = sha2_blocks(32 + n + n)              # toByte || KEY || M
    H_blk   = sha2_blocks(32 + n + 2*n)
    PRF_blk = sha2_blocks(32 + n + 32) - (1 if n == 32 else 0)  # midstate iff aligned
    Hmsg_blk = sha2_blocks(32 + 3*n + M_bytes)
    chain_steps = lenw * (w - 1)
    chain_prfs  = chain_steps * 2
    ltree_h     = lenw - 1
    ltree_prfs  = ltree_h * 3
    merk_prfs   = h * 3
    return (chain_steps*F_blk + chain_prfs*PRF_blk
            + ltree_h*H_blk + ltree_prfs*PRF_blk
            + h*H_blk + merk_prfs*PRF_blk
            + Hmsg_blk)

# --- SLH-DSA — FIPS 205 ---
def slh_dsa(n=16, h=63, d=7, hp=9, a=12, k=14, w=16, lenw=35, M_bytes=1024):
    # FIPS 205 §11.2.2 hash input: pk_seed(n) || zeros(64-n) || ADRS_c(22) || M
    # Midstate amortizes the 64-byte pk_seed-prefix block; remainder = body blocks.
    F_calls    = d * lenw * (w-1) + k
    H_calls    = k * a + d * hp
    F_blk      = sha2_blocks(64 + 22 + n)        - 1     # body |M|=n
    H_blk      = sha2_blocks(64 + 22 + 2*n)      - 1     # body |M|=2n
    Tk_blk     = sha2_blocks(64 + 22 + k*n)      - 1     # body |M|=k·n
    Tlen_blk   = sha2_blocks(64 + 22 + lenw*n)   - 1     # body |M|=lenw·n
    # H_msg = MGF1(R || pk_seed || SHA-256(R || pk_seed || pk_root || M), 30)
    Hmsg_inner = sha2_blocks(16 + 16 + 16 + M_bytes)     # R + pk_seed + pk_root + M
    Hmsg_outer = sha2_blocks(16 + 16 + 32 + 4)           # R + pk_seed + inner_digest + ctr
    Hmsg_blk   = Hmsg_inner + Hmsg_outer
    return F_calls*F_blk + H_calls*H_blk + 1*Tk_blk + d*Tlen_blk + Hmsg_blk

# Constants × blocks → R1CS in millions of constraints
def r1cs_M(blocks): return blocks * SHA256_BLK / 1e6

print(f"LMS_M32_H10/W4: {r1cs_M(lms_sha256()):.0f} M")
print(f"LMS_M32_H10/W8: {r1cs_M(lms_sha256(w=8)):.0f} M")
print(f"XMSS_10_256:    {r1cs_M(xmss_sha2()):.0f} M")
print(f"SLH-DSA-128s:   {r1cs_M(slh_dsa()):.0f} M  (measured: 122 M)")
print(f"SLH-DSA-128f:   {r1cs_M(slh_dsa(h=66, d=22, hp=3, a=6, k=33)):.0f} M")
```

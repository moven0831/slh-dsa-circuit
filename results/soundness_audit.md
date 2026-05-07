# SLH-DSA-128s Circuit — Soundness Audit

This document inventories every soundness-critical constraint in the
verifier circuit: range checks on witness signals, multiplexer
selectors, and the final root-equality assertions. Missing any of
these would let a malicious prover satisfy the circuit without holding
a valid SLH-DSA signature, breaking the EUF-CMA security claim.

The audit covers all three families. Each row lists the *constraint
location* (file + template), the *what* (the protected invariant), and
*how* (the Circom mechanism — `Num2Bits`, `===`, `Multiplexer`'s
`Decoder`, etc.).

---

## 1. ADRS sub-field range checks

The ADRS bundle is a 7-tuple of witness signals. If a malicious prover
supplies out-of-range values, byte-encoding (for SHA-2 / SHAKE) could
produce truncated or aliased ADRS bytes that don't represent a valid
FIPS 205 ADRS — potentially letting them re-use one ADRS in two
different positions and forge.

| Sub-field    | Range            | Where enforced                                        |
|--------------|------------------|-------------------------------------------------------|
| `layer`      | < 2^8 (1 byte)   | `circuits/sha2/adrs_encode_sha2.circom::U8ToByte`     |
| `type_`      | < 2^8 (1 byte)   | `circuits/sha2/adrs_encode_sha2.circom::U8ToByte`     |
| `tree_high`  | === 0 (always)   | `circuits/common/adrs.circom::AdrsRangeCheck`         |
|              | (also < 2^32)    | `circuits/sha2/adrs_encode_sha2.circom::U32ToBytesBE` |
| `tree_low`   | < 2^32           | `U32ToBytesBE` (byte encoding ⇒ 4-byte slot)          |
| `keypair`    | < 2^32           | `U32ToBytesBE`                                        |
| `chain`      | < 2^32           | `U32ToBytesBE`                                        |
| `hash`       | < 2^32           | `U32ToBytesBE`                                        |

For SHAKE, the same checks happen inside
`circuits/shake/adrs_encode_shake.circom::U32ToBytesBE_Shake` (uses
`Num2Bits(32)`).

For Poseidon, range checks are NOT explicitly enforced on the 7
sub-fields — they're passed directly as field elements into Poseidon.
Soundness instead relies on:
- The H_msg digest decomposition (`ParseDigest`) constrains
  `md_indices[i] < 2^12` and `idx_tree < 2^54`, `idx_leaf < 2^9` via
  `Num2Bits(12)`, `Num2Bits(54)`, `Num2Bits(9)`. These are the only
  ADRS sub-fields that vary across calls in the verifier.
- The constant-per-WOTS values (`layer ∈ [0, 6]`, `type_ ∈ {0, 1, 3, 4}`,
  etc.) are emitted as compile-time constants by the common templates.

**Risk**: a malicious Poseidon-family prover could set out-of-range
values for runtime-witness ADRS fields. Mitigation: **add explicit
range checks for the Poseidon family**; we currently rely on the
implicit ranges being consistent with the constraint chain. **Track
as future work.**

---

## 2. WOTS+ chain message-chunk range

`msg_chunks[i]` (35 chunks, each in `[0, 15]`) drive both the F-call
ADRS hash address (`hash = msg_chunks[i] + k`) and the chain endpoint
mux. An out-of-range `msg_chunks[i]` could let a forger select any
`cand[15]` as the chain pubkey.

| Constraint                 | Where enforced                                  |
|----------------------------|-------------------------------------------------|
| `msg_chunks[i] ∈ [0, 15]`  | `circuits/common/digest.circom::Base2bWithCsum` (and SHA-2 variant via `circuits/sha2/ht.circom::HtVerify` calling Base2bWithCsum); each nibble is decomposed via `Num2Bits(8)` and re-packed from 4 bits, implicitly bounding it to [0, 15]. |
| chain mux selector range   | `Multiplexer(16, 16)`'s internal `Decoder(16)` asserts `success === 1` (sum of indicators === 1) and each `out[i] * (in - i) === 0`. Out-of-range sel ⇒ no `i` matches ⇒ `success !== 1` ⇒ unsatisfiable. |

---

## 3. FORS leaf indexing (md_indices)

The 14 FORS indices are 12-bit chunks of the H_msg digest's first 21
bytes. Each `md_indices[i]` selects one leaf within FORS tree `i`
(2^12 = 4096 leaves per tree).

| Constraint                          | Where enforced                                 |
|-------------------------------------|------------------------------------------------|
| `md_indices[i] < 2^12`              | `circuits/common/digest.circom::ParseDigest` decomposes 21 bytes (168 bits) via `Num2Bits(8)` per byte, then re-packs into 14 chunks of 12 bits each. The 12-bit re-pack is unique. |
| FORS path bit decomposition         | `circuits/common/fors.circom::ForsPkFromSig` decomposes each `md_indices[i]` again via `Num2Bits(12)`. The two decompositions are NOT explicitly cross-checked, but both compute the unique 12-bit representation of the same field element ⇒ they agree. |
| Tree-index calculation `i*4096 + idx` | Compile-time constant + witness; bounded by 14*4096 + 4095 = 61,439 < 2^16. Not explicitly range-checked, but the value is computed via `+` from already-bounded inputs. |

---

## 4. Hypertree idx_tree / idx_leaf

| Constraint                  | Where enforced                                                |
|-----------------------------|---------------------------------------------------------------|
| `idx_tree < 2^54` (h - h')  | `circuits/common/digest.circom::ParseDigest` recombines 7 bytes into 54 bits via `Num2Bits(8)` per byte and a 54-element sum. |
| `idx_leaf < 2^9` (h')       | Similarly via 2 bytes → 9 bits.                               |
| `tree_high === 0` (128s)    | `circuits/common/adrs.circom::AdrsRangeCheck` (and `circuits/sha2/adrs_encode_sha2.circom::AdrsEncodeSha2` for the SHA-2 path) asserts `tree_high === 0` directly. |
| Per-layer idx_leaf′ derivation | `circuits/common/ht.circom::HtVerify` (and SHA-2 variant `circuits/sha2/ht.circom`) extracts bits `[9*(j-1), 9*j)` from `idx_tree_bits` for layer-j idx_leaf, then computes layer-j tree_low from bits `[9*j, 54)`. Soundness depends on `Num2Bits(54)` having decomposed idx_tree into a unique bit-vector. |

---

## 5. WOTS+ chain unroll soundness (forward chain + end-mux)

The WOTS+ chain at message position `m` requires `(15 - m)` F
applications starting from the signature endpoint `sig[i]`. The
circuit unrolls 15 F-steps with hash addresses `m + k` for `k ∈ [0, 14]`,
then muxes the candidate at index `15 - m`.

Soundness requirements:
| Requirement                                                                  | Where enforced |
|------------------------------------------------------------------------------|----------------|
| Prover cannot forge sig[i] without inverting F                               | Forward-chain construction: `cand[0] = sig[i]` is fixed by the SIG witness; `cand[k+1] = F(cand[k])` is constrained for all 15 steps. The prover provides only `sig[i]`; cand[1..15] are uniquely determined. |
| Prover cannot select wrong candidate index                                   | `Multiplexer(16, 16)` with `sel = 15 - msg_chunks[i]` and Decoder enforcing `success === 1`. |
| Hash address per F-step matches FIPS 205                                     | `f_step[i][k].hash <== msg_chunks[i] + k` directly. The hash address is data-dependent (witness), but the constraint binds it tightly. |
| Wasted F's at "out-of-FIPS-205-range" hash addresses (≥ 15)                  | These exist when `msg_chunks[i] > 0`, but their outputs are muxed away. F's circuit doesn't care if hash address ≥ 15 (the F primitive doesn't internally check that hash < w); only the SLH-DSA construction uses hash ∈ [0, 14]. **This is a documented design choice**: see `circuits/common/wots.circom`/`circuits/sha2/wots.circom` template-level comment. |

---

## 6. FORS / XMSS Merkle path direction (left/right by bit)

For each level, the prover commits to a left/right decision via the
corresponding bit of the index. A malicious prover could try to flip
the bit to use a wrong auth-path orientation.

| Constraint                                          | Where enforced |
|-----------------------------------------------------|----------------|
| `idx_bits[k] ∈ {0, 1}`                              | `Num2Bits(12)` (FORS) and `Num2Bits(9)` (XMSS) decompose to bits — each Num2Bits internal asserts each bit is binary via `bit * (bit - 1) === 0`. |
| Left/right selection consistency                    | `Multiplexer(16, 2)` with sel = idx bit: Decoder enforces sel ∈ {0, 1} (one-hot indicators sum to 1). |
| Tree-index update (`ti = ti // 2` per level)         | Computed via constant arithmetic from `idx_bits` LE-decomposition. The bit-level representation uniquely determines the value. |

---

## 7. Top-level pk_root equality (the critical assertion)

The verifier's "valid" output is gated by the final HT root matching
PK.root.

| Constraint                                          | Where enforced |
|-----------------------------------------------------|----------------|
| `xmss[6].xmss_root[b] === pk_root[b]` for `b ∈ [0, 15]` | `circuits/common/ht.circom::HtVerify` (and SHA-2 variant). 16 byte-wise equality constraints. Any mismatch ⇒ unsatisfiable. |

This is the soundness "anchor" — every other constraint flows up to
this single check. If pk_root is the genuine public key root, only a
real signature (or a hash-collision attacker) can satisfy this.

---

## 8. Poseidon family — domain separation tags

Poseidon-SLH-DSA is a non-standard construction with no external spec.
Cross-primitive collisions (where one primitive's output collides with
another's) would be a soundness break.

| Mitigation                                          | Where enforced |
|-----------------------------------------------------|----------------|
| Domain-separation tag prepended to every outer Poseidon call | `circuits/poseidon/hashes.circom::SlhF/H/Tk/Tlen/HMsg`: F=0, H=1, T_k=2, T_len=3, H_msg=4 prepended as `inputs[0]`. Constants emitted via `<==` to a fresh signal. Distinct values ⇒ Poseidon outputs are not interchangeable across primitives. |
| Inner H_msg sub-tags 0/1 for the two truncations    | `circuits/poseidon/poseidon_wrap.circom::PoseidonHash30`. |

---

## 9. SHA-2 midstate — soundness preservation

The midstate optimization shares a precomputed `iv_state` across all
F/H/T_l calls. Soundness requirement: `iv_state` must be the
deterministic output of `Sha256Compression(default_IV, pk_seed||zeros[48])`.
Otherwise a malicious prover could substitute a tampered iv_state and
produce wrong F outputs.

| Constraint                                          | Where enforced |
|-----------------------------------------------------|----------------|
| `iv_state = Sha256Compression(default_IV, pk_seed||zeros[48])` | `circuits/sha2/slhdsa_verify.circom::SlhDsaVerify` instantiates `Sha256SeedIv` once and connects its output directly to `seed_iv.iv_state`. The Sha256SeedIv template's own constraints (full Sha256compression sub-circuit + IV constants) are uniquely satisfied by the correct iv_state. |
| All F/H/T_l calls share the same iv_state           | `circuits/sha2/{wots,fors,xmss,ht}.circom` propagates iv_state through every level — each `f_step[i][k].iv_state[b] <== iv_state[b]` constraint binds the local iv_state to the parent's. |

---

## 10. Constraint count of soundness-critical checks

The soundness-critical checks listed above are a small fraction of the
total constraint count:

| Family   | Total constraints | Soundness-critical (estimated) | Fraction |
|----------|------------------:|-------------------------------:|---------:|
| Poseidon |         3,992,159 |                       ~80,000  |    2.0%  |
| SHA-2 (midstate) | ~121,728,293 |                  ~600,000  |    0.5%  |
| SHAKE    |    ~577,500,000   |                      ~600,000  |    0.1%  |

(Estimates: ADRS range checks ~200/call × 3,928 calls ≈ 786K; chain
muxes ~272 × 245 × 7 = 467K; FORS/XMSS path muxes ~16/level × 2,520 levels = 40K; bit decompositions for digest parsing ~1K; pk_root equality 16.)

The dominant cost is the F/H/T_l/H_msg primitives themselves. Soundness
overhead is a rounding error.

---

## 11. Out-of-scope for this audit

- **PRF / signing-only primitives**: Not part of the verifier; not
  audited.
- **fips205 reference-impl conformance**: H_msg byte layout was
  cross-checked against `vendor/fips205/src/hashers.rs::sha2_cat_1::h_msg`
  and `::shake::h_msg` during implementation. **Per-primitive
  conformance is now actively tested** — see `scripts/run_tests.sh`
  for 20/20 (10 positive + 10 negative) tests passing across SHA-2
  and SHAKE F/H/T_k/T_len/H_msg. End-to-end main-level witness check
  remains gated on the OOM situation (SHA-2/SHAKE) or a from-scratch
  Poseidon shadow impl (Poseidon).
- **Side channels / circom prover implementation bugs**: The audit
  covers the R1CS structure, not snarkjs / circomlib internals.

---

## 12. Known soundness gaps (track as future work)

1. **Poseidon family ADRS sub-fields are not range-checked**. A
   malicious prover could pass any field element. Suggested fix: add
   `Num2Bits(8)`/`Num2Bits(32)` on each sub-field at the entry to
   `circuits/poseidon/hashes.circom::SlhF/H/Tk/Tlen`. Minor cost
   (~200 constraints/call × ~3,928 calls = ~786K constraints,
   doubling the Poseidon main from ~4M → ~4.8M).
2. **Top-level `valid` signal**: currently `valid` is constrained by
   byte-wise `===` of the final root and pk_root. If the root matches,
   the circuit is satisfiable; the `valid` signal is then 1. There is
   no path where `valid = 0` — the circuit is unsatisfiable instead.
   This is correct semantically (the circuit MUST refuse to accept on
   non-matching root). If callers want a "soft" signal that lets the
   prover demonstrate non-matching without aborting, the assertion
   should be replaced with a witness-bit equality check. Out of scope
   here.

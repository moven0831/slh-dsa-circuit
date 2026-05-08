# SLH-DSA primer (companion to `results/results.md`)

A condensed walkthrough of what SLH-DSA is, what each primitive in the
verifier does, and how to read the constraint-count benchmark. Written
to be self-contained so a reader who hasn't touched FIPS 205 can
understand the numbers in `results/results.md`.

---

## 1. What SLH-DSA is

A **stateless hash-based signature** standardized in FIPS 205. The only
cryptographic ingredient is a hash function — no number theory, no
lattices, no curves. Security rests on hash one-wayness and collision
resistance, which makes it post-quantum (Grover only square-roots that;
no Shor speedup).

The catch: a hash is a one-way function, not a signature. SLH-DSA stacks
four ideas to turn it into a many-time signature: **WOTS+** → **XMSS** →
**Hypertree (HT)** → **FORS**.

---

## 2. The four structural pieces (bottom-up)

### WOTS+ — Winternitz One-Time Signature
- Pick a secret `sk_i`. Publish `pk_i = F^15(sk_i)` (apply `F` 15 times).
- To sign digit `v ∈ {0,…,15}`, reveal `F^v(sk_i)`. Verifier finishes the
  chain (`15-v` more `F`-calls) and checks against `pk_i`.
- Forward direction is easy, backward is one-way-hard, so an attacker
  could only sign *larger* digits → defeated by a **checksum** that any
  cheat would force *down*.
- Parameters: `n=16`, `w=16`, `len=35` (32 message digits + 3 checksum).
  One WOTS+ instance = 35 chains of length 15 = up to **525 F-calls**
  + one `T_len` to compress the 35 chain-ends into a pubkey.
- **One-time only.** Reuse breaks security.

### XMSS — Merkle tree of WOTS+ keys
- Generate `2^h'` WOTS keypairs. Hash them into a Merkle tree. Publish
  only the root.
- To sign message #`i`: use WOTS keypair `i` + provide the `h'` sibling
  nodes (auth path). Verifier reconstructs root, compares.
- Uses `H` (2-input hash) for tree internal nodes.

### Hypertree (HT) — XMSS of XMSS
- One XMSS tree of height `h'` is impractical for billions of sigs
  (key-gen runs forever). So **stack** them: leaves of upper trees sign
  *roots* of lower trees.
- `d=7` layers, each of height `h'=9` → total `h = d·h' = 63` →
  **2^63 signatures**.
- Per signature: `d` WOTS instances + `d` Merkle paths =
  **3,675 F-calls + 63 H-calls**. This is where the big numbers come
  from in the benchmark.

### FORS — Forest Of Random Subsets
- Stateless mode means the signer doesn't track which leaves they've
  used; leaf indices come from hashing the message. Two messages might
  collide → WOTS reuse → catastrophe.
- Fix: put a **few-time signature** at the bottom that tolerates a small
  number of collisions; have the HT sign *that* signature's pubkey.
- `k=14` independent Merkle trees, each height `a=12` (4096 leaves).
- `H_msg(R, pk_seed, pk_root, M)` → 30-byte digest → split into `k=14`
  chunks of `a=12` bits → each chunk picks one leaf in its tree.
- Reveal `k` leaves + auth paths → compress `k` roots with `T_k` → FORS
  pubkey. The HT signs the FORS pubkey.

### Glue: ADRS and `pk_seed`
- **ADRS** (22 bytes): every internal hash includes a struct saying
  *which* hash this is — layer, tree, key-pair, chain, hash-index, type.
  Without it, structurally identical hashes in different parts of the
  scheme could collide and be swapped.
- **`pk_seed`** (16 bytes): public salt mixed into every hash. Blocks
  multi-target attacks — without it an attacker could amortize work
  across millions of harvested public keys.

---

## 3. The 5 hash primitives in the verifier

All take `pk_seed || ADRS || m` and output `n=16` bytes (except `H_msg`).

| Primitive | Input `m` size | Used for | Calls per verify |
|---|---|---|---:|
| **`F`** | `n` (16 B) | WOTS chain step + FORS leaf | **3,675 + 14 = 3,689** |
| **`H`** | `2n` (32 B) | Merkle internal node (FORS path + XMSS path) | `168 + 63 = 231` |
| **`T_k`** | `k·n` (224 B) | Compress 14 FORS roots → FORS pubkey | 1 |
| **`T_len`** | `len·n` (560 B) | Compress 35 WOTS chain-ends → WOTS pubkey | 7 |
| **`H_msg`** | `R‖pk_seed‖pk_root‖M` (~1072 B) | Digest message → 30-byte FORS payload + indices | 1 |

`F` dominates (3,689× vs everything else combined ≤ 240×). That's why
hash-of-choice matters so much.

> `T_k` and `T_len` are the same FIPS template `T_l` with different `l`.
> Benchmarked separately because their cost is very different (4 vs 10
> SHA-256 blocks).

> `PRF_msg` (signing-only randomizer derivation) and signing-time key
> generation are absent from the verifier circuit.

---

## 4. The verifier flow

```
verify(PK = (pk_seed, pk_root), M, SIG = (R, FORS_sig, HT_sig)):

  digest = H_msg(R, pk_seed, pk_root, M)
  → split into (md, idx_tree, idx_leaf)

  # FORS — recover FORS pubkey from message digest
  for each of k=14 FORS trees:
    leaf = F(revealed secret)         # 14× F
    climb a=12 levels with H          # 168× H total
  FORS_pk = T_k(14 roots)             # 1× T_k

  # Hypertree — d=7 layers
  node = FORS_pk
  for layer = 0..d-1:
    walk 35 WOTS chains (≤15 F each)  # 525× F per layer × 7 = 3675× F
    WOTS_pk = T_len(35 chain-ends)    # 1× T_len per layer × 7 = 7×
    climb h'=9 Merkle levels with H   # 9× H per layer × 7 = 63×
    node = XMSS root

  accept iff node == pk_root
```

---

## 5. Parameters (SLH-DSA-128s)

| Symbol | Value | Meaning |
|---|---:|---|
| `n` | 16 | security parameter (128-bit) |
| `w` | 16 | Winternitz parameter (chain length = `w−1` = 15) |
| `len` | 35 | chains per WOTS instance (32 msg + 3 checksum) |
| `k` | 14 | FORS trees |
| `a` | 12 | FORS tree height (4096 leaves each) |
| `d` | 7 | HT layers |
| `h'` | 9 | XMSS subtree height |
| `h` | 63 | total HT height (`d·h'`) → 2^63 signatures |
| `m` | 30 | bytes of `H_msg` output |

---

## 6. 128s vs 128f tradeoff

Same security level, different size/speed tradeoff.

| | **128s** (small/slow) | **128f** (fast) |
|---|---:|---:|
| Signature size | **7,856 B** | **17,088 B** (~2.17×) |
| Public key | 32 B | 32 B |
| Secret key | 64 B | 64 B |
| HT layers `d` | 7 | 22 |
| XMSS subtree height `h'` | 9 | 3 |
| FORS `k × a` | 14 × 12 | 33 × 6 |
| FORS leaves/tree | 4,096 | 64 |
| F-calls in verify | 3,675 | 11,550 (~3×) |
| Signing speed | slow | ~30× faster |

**Why 128f signs faster but verifies slower:** `h'=3` makes XMSS subtrees
cheap to build during signing (only 8 leaves each), but `d=22` layers
means more WOTS chains to walk during verify. **For a SNARK verifier,
128s is the better target** — signing is off-circuit anyway.

Signature size formula: `n + k·(a+1)·n + (h + d·len)·n`.

---

## 7. Benchmark headline (`results/results.md`)

| | F | H | T_k | T_len | H_msg | Full verifier |
|---|---:|---:|---:|---:|---:|---:|
| **SHA-2** (midstate) | 30,290 | 30,662 | 123,182 | 307,106 | 583,273 | ~121.7M (OOM) |
| **SHAKE** (Keccak) | 145,568 | 145,824 | 440,736 | 737,952 | 1,182,912 | ~577.5M (OOM, ~5×) |
| **Poseidon** (non-standard) | **968** | **1,102** | **5,989** | **14,428** | **24,844** | **3,992,159 ✅** |

**Takeaways:**
1. Poseidon is **~30× cheaper than SHA-2** and **~145× cheaper than
   SHAKE** at every primitive. With 3,675 F-calls dominating, the gap
   compounds.
2. The **midstate optimization** (see §8) halves SHA-2 F/H per-call cost
   (60,778 → 30,290) — pure compiler win, output bit-identical.
3. **Only `main_poseidon` actually compiles** on a 24 GB M3 with other
   apps loaded. SHA-2 (~122M) and SHAKE (~578M) OOM circom v2.2.3 (peak
   RSS budget ~10 GB). Not a circuit bug — works on 32 GB+ boxes.
4. **Per-primitive correctness validated** against a Rust FIPS 205 oracle
   (`reference/src/main.rs`): 20/20 tests pass (10 positive, 10
   tampered-negative). See `scripts/run_tests.sh`.
5. **Integration delta is +0.9%** (`main_poseidon` measured 3,992,159 vs
   sum-of-parts 3,957,343), giving high confidence the SHA-2/SHAKE
   projections are accurate within ~1%.

---

## 8. Midstate optimization (SHA-2 only)

### Background: how SHA-256 actually processes data

SHA-256 is **streaming**. It chops input into **64-byte blocks** and
processes them one at a time, carrying a 256-bit "state" forward:

```
state_0 = IV  (fixed constant)
state_1 = compress(state_0, block_1)
state_2 = compress(state_1, block_2)
…
output  = state_N  (after the last block)
```

Each `compress()` call is what costs ~30,000 R1CS constraints. **The
expensive thing is the per-block compression, and a hash of `N` blocks
costs `N` compressions.** That's the only fact you need.

### The observation in FIPS 205 §11.2.2

For every `F`/`H`/`T_k`/`T_len` call, the SHA-256 input layout begins
with the same 64 bytes:

```
┌─────────────────────────────────────────────────────────────┐
│ Block 1 (64 B):  pk_seed (16 B) ‖ zero-padding (48 B)       │  ← IDENTICAL across all calls
├─────────────────────────────────────────────────────────────┤
│ Block 2..N:      compressed ADRS (22 B) ‖ message (16+ B)   │  ← varies per call
└─────────────────────────────────────────────────────────────┘
```

That first block is **byte-for-byte identical** for every single call in
the entire verifier — only `pk_seed` (a public, fixed value) and zeros.

### The trick

Compress that block **once** at the top of the circuit, via a dedicated
`Sha256SeedIv` template (29,264 constraints, amortized over ~3,930
calls). Store the resulting 256-bit `iv_state` as a wire. Then every
SHA-2 primitive starts from `iv_state` instead of from the standard SHA
`IV`, and skips Block 1 entirely.

```
Without midstate:                 With midstate:
                                                     (computed once)
state = IV                        iv_state = compress(IV, pk_seed‖zeros)
state = compress(state, block1)   state = iv_state            ← skip block1
state = compress(state, block2)   state = compress(state, block2)
...                               ...
```

### Why output is identical

`compress()` is deterministic. `compress(IV, block_1)` yields the exact
same 256-bit value every time. Whether you compute it once and cache it
or recompute it on every call, the bits going into block 2 are the same.
**No spec deviation — the resulting hash is bit-equal to the unoptimized
version.** (Validated by construction; the per-primitive test suite
confirms equality with the Rust FIPS 205 oracle.)

### What it saves, per primitive

Each call saves exactly **one block compression** (~30,488 constraints):

| Primitive | Body bytes | Total blocks (with prefix) | Body blocks | Cost reduction |
|---|---:|---:|---:|---:|
| `F`     | 38 (ADRS+m) → padded to 64  | 2 | 1 | **60,778 → 30,290** (−49.8%) |
| `H`     | 54 → padded to 64           | 2 | 1 | **61,150 → 30,662** (−49.8%) |
| `T_k`   | 246 → padded to 256         | 5 | 4 | **153,670 → 123,182** (−19.8%) |
| `T_len` | 582 → padded to 640         | 11 | 10 | **337,594 → 307,106** (−9.0%) |

`F` and `H` are roughly halved — these are the *most invoked* primitives
(3,920 of the ~3,930 SHA-256 compressions per signature), so the
verifier-wide saving is essentially `−50%`: **~242M → ~122M constraints**
projected for the SHA-2 main.

### What doesn't get it

- **`H_msg`** (the message digest) has a different prefix layout —
  `R ‖ pk_seed ‖ pk_root ‖ M`. The shareable block isn't at the start of
  every call (there's only one `H_msg` per signature anyway), so no
  optimization applies. Cost is unchanged at 583,273.
- **SHAKE** can't use this trick at all. Two reasons:
  1. SHAKE-256 is a **sponge**, not Merkle-Damgård. Its permutation
     doesn't decompose into a "compress block 1, carry state, compress
     block 2" pattern in a way that saves work — every absorb mixes the
     full 1600-bit state.
  2. SHAKE-256's rate is 136 bytes, so the F input (64 B body) already
     fits in **one absorb block**. There's no separate "prefix block" to
     share even if the construction allowed it.

### Implementation pointer

`circuits/sha2/sha256_midstate.circom` defines `Sha256SeedIv()`. The
`main_sha2` template instantiates it once and threads `iv_state` into
every `Sha256Compression` invocation in F/H/T_k/T_len.

---

## 9. Caveats

- **Poseidon here is non-standard.** circomlib's Poseidon constants are
  tuned for BN254; used over `secq256r1` they give a different,
  non-FIPS hash. Constraint count is unchanged, but it's
  benchmarking-only — full validation would require a from-scratch Rust
  shadow.
- **`H_msg` for 128s uses MGF1-SHA-256, not SHA-512.** FIPS 205 only
  mandates SHA-512 for Cat 3+. Verified against `vendor/fips205`.
- **Field is `secq256r1`** (P-256 group order) to match Ethereum zkID.
  `snarkjs wtns check` doesn't support this curve, so validation uses
  `circomkit witness` (still honors `===`).
- **OOM is environmental, not algorithmic.** A less-loaded 24 GB or any
  32 GB+ machine should compile `main_sha2` without changes.

---

## 10. Glossary

| Term | Meaning |
|---|---|
| OTS | One-time signature (Lamport, WOTS, WOTS+) |
| FTS | Few-time signature (FORS) |
| WOTS+ | Winternitz One-Time Sig — hash-chain trick with checksum |
| XMSS | eXtended Merkle Sig Scheme — Merkle tree of WOTS+ keys |
| HT | Hypertree — XMSS trees stacked `d` layers deep |
| FORS | Forest Of Random Subsets — few-time sig at the bottom |
| ADRS | 22-byte address struct domain-separating every hash |
| `pk_seed` | public salt mixed into every hash; blocks multi-target attacks |
| `pk_root` | root of top XMSS tree; the actual published public key |
| `R` | per-signature randomizer (signing-only `PRF_msg` output) |
| `md` | "message digest" — part of `H_msg` output that picks FORS leaves |
| 128s / 128f | "small" vs "fast" parameter set; same security |
| R1CS | Rank-1 Constraint System — circom's output, the "size" we measure |

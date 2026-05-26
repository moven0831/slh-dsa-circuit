# Week 2 prerequisites — pinned dependencies, toolchains, environment

**Status:** Week 2 Day 0 deliverable (Task 0.2 from `/Users/moventsai/.claude/plans/given-the-context-on-reactive-patterson.md`).
**Audience:** any engineer (or agent) picking up Week 2 execution.

This file pins every external dependency the Week 2 plan consumes — upstream commit SHAs, toolchain versions, license terms. Re-pin only when a new commit ships a feature we need or fixes a blocker we hit.

---

## 1. Upstream commit pins

All SHAs verified via `gh api repos/<org>/<repo>/git/refs/heads/main --jq '.object.sha'` on **2026-05-26**.

| # | Project | URL | Pin | License | Used by |
|---|---------|-----|-----|---------|---------|
| 1 | **plonky2** | https://github.com/0xPolygonZero/plonky2 | tag `v1.1.0` (published 2025-05-12). Main SHA at pin time: `5d9da5a65bbcba2c66eb29c035090eb2e9ccb05f`. | Apache-2.0 | Goldilocks Poseidon constants (Day 1) + reference test vectors. |
| 2 | **NethermindEth/latticefold** | https://github.com/NethermindEth/latticefold | main `15cc045c18ea92a50c23528d1e7b62dd392b8c42` (no tagged releases). | Apache-2.0 | Day 3+ LatticeFold prover. |
| 3 | **NethermindEth/stark-rings** | https://github.com/NethermindEth/stark-rings | main `a907aab35dd7afe105b30588eaf74008dea2f12b`. | Apache-2.0 | LatticeFold's cyclotomic-ring backend (transitive). |
| 4 | **LFDT-Nightstream/Nightstream** | https://github.com/LFDT-Nightstream/Nightstream | main `755c1595f3b34b5c2bc9eaa50417cdf9dfb871ec`. | Apache-2.0 | Day 5 measurement-spike (Neo folding scheme). |

For (2), (3) use these SHAs verbatim in `Cargo.toml` (`rev = "..."`). For (1) use the tagged release in `Cargo.toml` (`tag = "v1.1.0"`).

## 2. Toolchain pins

- **Rust nightly-2025-03-06** — required by Nethermind LatticeFold (`rust-toolchain.toml` upstream pins this exact channel).
  - Install: `rustup toolchain install nightly-2025-03-06`
  - Verify: `rustc +nightly-2025-03-06 --version`
- **Rust 1.88 stable** (or newer) — required by LFDT Nightstream (`rust-version = "1.88"` in upstream `Cargo.toml`).
  - On this M3 machine, `1.95.0` stable is already active and satisfies the floor.
- **Circom 2.2.3** — already installed at `~/.cargo/bin/circom`. **Confirmed to support `--prime goldilocks`** (smoke test Day 0). Supported primes: `bn128`, `bls12377`, `bls12381`, `goldilocks`, `grumpkin`, `pallas`, `secq256r1`, `vesta`. BabyBear and KoalaBear are *not* supported by Circom 2.2.3 (only matters if we ever need to fall back from Goldilocks).
- **snarkjs 0.7.6** — pinned via `package.json` resolutions; used for witness export.
- **Node 20.x** — for the Circom WASM witness calculator.

## 3. Goldilocks Poseidon — vendoring details (Day 1)

Source files extracted on 2026-05-26 from plonky2 v1.1.0:

- **Round constants** `ALL_ROUND_CONSTANTS[360]` from `plonky2/src/hash/poseidon.rs:59` (12 × 30 layout). Extracted via:
  ```
  awk '/pub const ALL_ROUND_CONSTANTS/,/^\];/' plonky2/src/hash/poseidon.rs \
    | grep -oE '0x[0-9a-fA-F]{16}' | tail -n +2  # skip leading doc-comment hex
  ```
  Persisted at `tools/gen_poseidon_gl_constants/all_round_constants.txt` (360 lines).
- **MDS matrix** from `plonky2/src/hash/poseidon_goldilocks.rs`:
  - `MDS_MATRIX_CIRC = [17, 15, 41, 16, 2, 28, 13, 13, 39, 18, 34, 20]`
  - `MDS_MATRIX_DIAG = [8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]`
  - Used in canonical `mds_row_shf` form: `result[r] = Σ_i state[(i+r) mod 12]·CIRC[i] + state[r]·DIAG[r]`.
- **Permutation params** (`plonky2/src/hash/poseidon.rs`):
  - `WIDTH = 12`, `RATE = 8`, `CAPACITY = 4`
  - `HALF_N_FULL_ROUNDS = 4` ⇒ 8 full rounds total (4 + 4)
  - `N_PARTIAL_ROUNDS = 22`, `N_ROUNDS = 30`
  - S-box exponent `7` (x⁷ via 4 mults: x² = x·x; x⁴ = x²·x²; x³ = x·x²; x⁷ = x³·x⁴).

**Note on Plonky2's "fast partial MDS" optimization.** Plonky2 uses `FAST_PARTIAL_ROUND_VS`, `FAST_PARTIAL_ROUND_W_HATS`, and `FAST_PARTIAL_ROUND_INITIAL_MATRIX` in partial rounds to reduce Rust per-round cost from O(t²) to ~O(t). For R1CS we use the canonical `mds_row_shf` form everywhere — MDS multiplication is linear (zero R1CS constraints under `--O2`), so the "fast" decomposition adds complexity without saving any constraints. Cryptographic equivalence: both forms produce the *same* MDS multiplication output; the decomposition is purely an arithmetic-cost optimization.

**Reproducibility:** rerun via `python3 tools/gen_poseidon_gl_constants/generate.py --in tools/gen_poseidon_gl_constants/all_round_constants.txt --out circuits/poseidon_gl/poseidon_gl_constants.circom` to regenerate the Circom constants file. To pull fresh constants from upstream, repeat the awk + grep + `tail -n +2` recipe above.

## 4. Verification — Day 1 smoke test

`bash scripts/test_poseidon_gl.sh` (created Day 1) does:

1. Compile `circuits/poseidon_gl/poseidon_gl_smoke.circom` with `circom --r1cs --wasm --O2 --prime goldilocks`.
2. Assert R1CS constraint count = **472** (8 full × 12 lanes × 4 S-box mults + 22 partial × 1 × 4 = 384 + 88).
3. Run the WASM witness calculator on each of 4 Plonky2 reference test vectors (`zeros`, `range`, `neg_one`, `random`) and assert all 12 output lanes match the published expected values byte-for-byte.

**Day 1 result:** all checks pass. R1CS = 472 exactly (matches `cost_model.md §5.1` corrected projection). All 4 × 12 = 48 output lanes match Plonky2's reference output.

This is **cryptographic-correctness validation**, not a security review. External cryptographer review still required before any production deploy (`scheme_selection.md §6` row 4 — separate parallel track).

## 5. Open Day 0 items still pending (not blockers for Day 1, but block Day 5 sign-off)

These come from `scheme_selection.md §6`. **Owners and trigger dates need fill-in by the project lead.**

| # | Decision | Owner | Trigger | Evidence artifact | Date |
|---|---|---|---|---|---|
| 1 | Approve D4 conservative primary + D2-c conditional alternative; fallback ladder A' → B' → C' → D'. | `<PI / project lead>` | Reviewer reading EXEC_SUMMARY + scheme_selection.md §3 confirms. | EXEC_SUMMARY.md approved-by line filled in. | `<YYYY-MM-DD>` |
| 2 | Name Week 2 engineer for SuperNeo/Neo reference-impl survey + per-fold-overhead micro-bench (Day 4 in our revised plan). | `<EM>` | Week 2 Day 0. | Owner listed in this file. | `<YYYY-MM-DD>` |
| 3 | Name Week 2 engineer for Goldilocks Poseidon Circom re-instantiation (Days 1–2 deliverable). | `<EM>` | Week 2 Day 0. | Owner listed in this file + Plonky2 pin in §1 above. | **COMPLETE 2026-05-26** (assistant; pin: plonky2 v1.1.0). |
| 4 | External cryptographer engagement plan: named candidate orgs, scope-of-work, budget envelope, target dates. | `<PI>` | End of Week 2 (parallel; not a prototype blocker, but a production-deploy blocker). | `research/folding/cryptographer_engagement.md` drafted. | `<YYYY-MM-DD>` |
| 5 | Confirm verifier device class (mobile / desktop) for the CSP relying party. | `<product lead>` | Week 2 Day 0. | One-line decision in EXEC_SUMMARY.md. | `<YYYY-MM-DD>` |
| 6 | Final SNARK choice locked to Spartan2 over Goldilocks (default). | `<scheme owner>` | Week 2 Day 4 after SuperNeo / LatticeFold survey. | scheme_selection.md updated with chosen finisher + commit SHA of reference impl. | `<YYYY-MM-DD>` |
| 7 | XMSS-track coordination: confirm shared scheme + shared field + shared Poseidon variant (or document explicit divergence). | `<XMSS lead + SLH-DSA lead>` | Week 2 Day 0. | Joint memo at `research/folding/xmss_handoff.md`. | `<YYYY-MM-DD>` |

## 6. Environment confirmed working

- **Platform:** Darwin 24.6.0 / aarch64-apple-darwin / M3 / 24 GB.
- **Circom 2.2.3 with Goldilocks:** trivial passthrough circuit + 472-R1CS PoseidonGlPermute both compile cleanly.
- **snarkjs wtns export json:** working over Goldilocks WASM witnesses.
- **gh CLI:** authenticated; used for SHA fetching.
- **Rust 1.95.0 stable** (default): builds cargo workspaces. nightly-2025-03-06 confirmed available for Day 3 LatticeFold work.

## 7. Files referenced

- This file: `research/folding/week2_prereqs.md`
- Generator: `tools/gen_poseidon_gl_constants/generate.py`
- Constants input: `tools/gen_poseidon_gl_constants/all_round_constants.txt`
- Generated constants: `circuits/poseidon_gl/poseidon_gl_constants.circom`
- Permutation template: `circuits/poseidon_gl/poseidon_gl.circom`
- Smoke wrapper: `circuits/poseidon_gl/poseidon_gl_smoke.circom`
- Test runner: `scripts/test_poseidon_gl.sh`
- Validator: `scripts/check_poseidon_gl.py`
- Plan: `/Users/moventsai/.claude/plans/given-the-context-on-reactive-patterson.md`
- Week 1 sign-off blockers: `research/folding/scheme_selection.md §6`

pragma circom 2.2.3;

include "poseidon_gl.circom";

// SLH-DSA primitive wrappers on top of Plonky2 Goldilocks Poseidon.
//
// **NON-STANDARD; FOR BENCHMARKING ONLY.**
// Same caveats as circuits/poseidon/hashes.circom — see CLAUDE.md and the main README.
// Additionally: Goldilocks (p = 2^64 - 2^32 + 1) is 64-bit, so a 16-byte SLH hash
// output cannot fit in one field element (128 bits > 64). We pack 16 bytes into
// TWO Goldilocks FEs (low_8_bytes, high_8_bytes), which roughly doubles the
// Poseidon input arity vs. the secq256r1 family.
//
// Day-2 deliverable per /Users/moventsai/.claude/plans/given-the-context-on-reactive-patterson.md §Day 2.
// Templates to implement (in order):
//   - PackBytes16To2Fe   : 16 bytes -> (lo: Fe, hi: Fe)  -- new helper
//   - UnpackFe2To16Bytes : (lo, hi) -> 16 bytes          -- new helper
//   - PoseidonGl(nInputs): sponge wrapper around PoseidonGlPermute (capacity=4, rate=8)
//   - SlhF_Gl            : F primitive — tag(1) + seed(2) + ADRS(7) + M(2) = 12 FE
//                          fits exactly into t=12 in one perm. R1CS ~ 472 + ADRS+pack overhead.
//   - SlhH_Gl            : H primitive — tag(1) + seed(2) + ADRS(7) + M(2+2) = 14 FE.
//                          14 > t=12 so REQUIRES a sponge over 2 permutations.
//                          Per-call R1CS ~ 2 × 472 + pack/squeeze overhead.
//   - SlhTk_Gl           : T_k — binary Merkle reduce of k=14 leaves (each 16 B = 2 FE)
//                          via PoseidonGl(4) chain, then final mix Poseidon(12).
//   - SlhTlen_Gl         : T_len — binary Merkle reduce of len=35 leaves, final mix Poseidon(12).
//   - SlhHMsg_Gl         : H_msg — binary Merkle reduce of 64 leaves, 2× final mix Poseidon(5)-class.
//
// Domain-separation tags (unchanged from circuits/poseidon/hashes.circom):
//   F = 0, H = 1, T_k = 2, T_len = 3, H_msg = 4
//
// Signal-width audit results will be recorded in research/folding/poseidon_gl_audit.md
// alongside per-primitive R1CS measurements (secq256r1 baseline vs. Goldilocks bloat factor).

// TODO Day 2: implement the templates above.
// Stub left intentionally empty — Day 1 ships only PoseidonGlPermute + the smoke test;
// Day 2 builds the SLH primitive layer on top.

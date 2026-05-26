pragma circom 2.2.3;

include "poseidon_gl_wrap.circom";

// Non-standard Plonky2-Goldilocks-Poseidon-based SLH-DSA primitives.
//
// **NON-STANDARD; FOR BENCHMARKING ONLY.**
// Same caveats as circuits/poseidon/hashes.circom — circomlib BN254 constants
// were swapped for Plonky2's Goldilocks constants (Apache-2.0, see
// research/folding/week2_prereqs.md), but the hash construction itself is
// the project-specific "permutation-as-fixed-arity-hash" — NOT Plonky2's
// standard rate-8 sponge. See PoseidonGl in poseidon_gl_wrap.circom.
//
// Field-size note (Goldilocks is 64-bit, p = 2^64 - 2^32 + 1):
//   - 16-byte SLH hash output ⇒ 2 Goldilocks FEs (lo, hi) via PackBytes16To2Fe.
//   - 4-byte ADRS sub-field   ⇒ 1 Goldilocks FE (any 32-bit value fits).
//   - Tag                     ⇒ 1 Goldilocks FE (constant, 0..4).
//   This roughly doubles Poseidon arity vs the secq256r1 family for primitives
//   that hash 16-byte slots — the audit in research/folding/poseidon_gl_audit.md
//   records the per-primitive bloat factor empirically.
//
// Template names are unsuffixed (SlhF, SlhH, SlhTk, SlhTlen) to match the
// family-agnostic include convention in circuits/common/{wots,xmss,fors,ht}.circom
// (those templates reference SlhF/SlhH/SlhTlen by unqualified name and expect
// the includer to provide them). Including this file BEFORE circuits/common/*.circom
// wires the verifier pipeline through Goldilocks Poseidon.
//
// Domain-separation tags (unchanged from circuits/poseidon/hashes.circom):
//   F = 0, H = 1, T_k = 2, T_len = 3, H_msg = 4   (H_msg deferred — D4-restricted)
//
// SlhHMsg is intentionally NOT implemented in this file — the Day 2 / D4-restricted
// fold only requires F/H/Tk/Tlen. HMsg goes inline in the closing SNARK (Week 3+).

// SlhF — F primitive, arity-12 (fits in one PoseidonGlPermute):
//   tag(1) + seed(2) + ADRS(7) + M(2) = 12 FEs.
// R1CS: ~472 (permutation) + ~128 (PackBytes16To2Fe pk_seed) + ~128 (PackBytes16To2Fe m)
//     + ~128 (UnpackFe2To16Bytes out) = ~856 baseline.
template SlhF() {
    signal input pk_seed[16];
    signal input layer;
    signal input tree_high;
    signal input tree_low;
    signal input type_;
    signal input keypair;
    signal input chain;
    signal input hash;
    signal input m[16];
    signal output out[16];

    component pack_pk = PackBytes16To2Fe();
    for (var b = 0; b < 16; b++) pack_pk.bytes[b] <== pk_seed[b];

    component pack_m = PackBytes16To2Fe();
    for (var b = 0; b < 16; b++) pack_m.bytes[b] <== m[b];

    component p = PoseidonGl(12);
    p.inputs[0]  <== 0;              // tag F
    p.inputs[1]  <== pack_pk.lo;
    p.inputs[2]  <== pack_pk.hi;
    p.inputs[3]  <== layer;
    p.inputs[4]  <== tree_high;
    p.inputs[5]  <== tree_low;
    p.inputs[6]  <== type_;
    p.inputs[7]  <== keypair;
    p.inputs[8]  <== chain;
    p.inputs[9]  <== hash;
    p.inputs[10] <== pack_m.lo;
    p.inputs[11] <== pack_m.hi;

    component unpack = UnpackFe2To16Bytes();
    unpack.lo <== p.out_lo;
    unpack.hi <== p.out_hi;
    for (var k = 0; k < 16; k++) out[k] <== unpack.bytes[k];
}

// SlhH — H primitive, arity-14 (needs the 2-perm Sponge14):
//   tag(1) + seed(2) + ADRS(7) + M1(2) + M2(2) = 14 FEs.
// Plonky2 sponge convention (rate=8, capacity=4): 2 permutations.
// R1CS: ~944 (sponge) + ~128 (pk_seed pack) + 2 × ~128 (M1, M2 packs)
//     + ~128 (out unpack) = ~1,456 baseline.
// The input m[32] is M1 || M2 (16 bytes each).
template SlhH() {
    signal input pk_seed[16];
    signal input layer;
    signal input tree_high;
    signal input tree_low;
    signal input type_;
    signal input keypair;
    signal input chain;
    signal input hash;
    signal input m[32];
    signal output out[16];

    component pack_pk = PackBytes16To2Fe();
    for (var b = 0; b < 16; b++) pack_pk.bytes[b] <== pk_seed[b];

    component pack_m1 = PackBytes16To2Fe();
    for (var b = 0; b < 16; b++) pack_m1.bytes[b] <== m[b];

    component pack_m2 = PackBytes16To2Fe();
    for (var b = 0; b < 16; b++) pack_m2.bytes[b] <== m[16 + b];

    component s = PoseidonGlSponge14();
    s.inputs[0]  <== 1;              // tag H
    s.inputs[1]  <== pack_pk.lo;
    s.inputs[2]  <== pack_pk.hi;
    s.inputs[3]  <== layer;
    s.inputs[4]  <== tree_high;
    s.inputs[5]  <== tree_low;
    s.inputs[6]  <== type_;
    s.inputs[7]  <== keypair;
    s.inputs[8]  <== chain;
    s.inputs[9]  <== hash;
    s.inputs[10] <== pack_m1.lo;
    s.inputs[11] <== pack_m1.hi;
    s.inputs[12] <== pack_m2.lo;
    s.inputs[13] <== pack_m2.hi;

    component unpack = UnpackFe2To16Bytes();
    unpack.lo <== s.out_lo;
    unpack.hi <== s.out_hi;
    for (var k = 0; k < 16; k++) out[k] <== unpack.bytes[k];
}

// SlhTk — T_k primitive, FORS k-tree-roots compression.
// Binary Merkle-reduce of k=14 leaves (each 16 B = 2 FE) via PoseidonGlReduce(14),
// then final mix Poseidon over arity-12: tag(1) + seed(2) + ADRS(7) + reduce_out(2) = 12.
// R1CS: 14 × 472 (reduce) + 472 (mix) + pack/unpack overhead ≈ 7.1K.
//
// Signal interface matches circuits/poseidon/hashes.circom SlhTk: m[k*16] = m[224].
template SlhTk() {
    signal input pk_seed[16];
    signal input layer;
    signal input tree_high;
    signal input tree_low;
    signal input type_;
    signal input keypair;
    signal input chain;
    signal input hash;
    signal input m[14 * 16];         // 14 leaves × 16 bytes
    signal output out[16];

    // Pack each 16-byte leaf into (lo, hi).
    component pack_leaves[14];
    signal leaves_lo[14];
    signal leaves_hi[14];
    for (var i = 0; i < 14; i++) {
        pack_leaves[i] = PackBytes16To2Fe();
        for (var b = 0; b < 16; b++) pack_leaves[i].bytes[b] <== m[i * 16 + b];
        leaves_lo[i] <== pack_leaves[i].lo;
        leaves_hi[i] <== pack_leaves[i].hi;
    }

    // Merkle-reduce 14 leaves down to 1 (2 FE).
    component reduce = PoseidonGlReduce(14);
    for (var i = 0; i < 14; i++) {
        reduce.inputs_lo[i] <== leaves_lo[i];
        reduce.inputs_hi[i] <== leaves_hi[i];
    }

    // Final mix: tag + seed + ADRS + reduce_out.
    component pack_pk = PackBytes16To2Fe();
    for (var b = 0; b < 16; b++) pack_pk.bytes[b] <== pk_seed[b];

    component mix = PoseidonGl(12);
    mix.inputs[0]  <== 2;            // tag T_k
    mix.inputs[1]  <== pack_pk.lo;
    mix.inputs[2]  <== pack_pk.hi;
    mix.inputs[3]  <== layer;
    mix.inputs[4]  <== tree_high;
    mix.inputs[5]  <== tree_low;
    mix.inputs[6]  <== type_;
    mix.inputs[7]  <== keypair;
    mix.inputs[8]  <== chain;
    mix.inputs[9]  <== hash;
    mix.inputs[10] <== reduce.out_lo;
    mix.inputs[11] <== reduce.out_hi;

    component unpack = UnpackFe2To16Bytes();
    unpack.lo <== mix.out_lo;
    unpack.hi <== mix.out_hi;
    for (var k = 0; k < 16; k++) out[k] <== unpack.bytes[k];
}

// SlhTlen — T_len primitive, WOTS+ chain-pubkey compression.
// Same structure as SlhTk but reduces 35 leaves instead of 14.
// R1CS: 38 × 472 (reduce — same tree shape as PoseidonReduce(35)) + 472 (mix)
//     + pack/unpack ≈ 18.4K.
//
// Signal interface matches circuits/poseidon/hashes.circom SlhTlen: m[35*16] = m[560].
template SlhTlen() {
    signal input pk_seed[16];
    signal input layer;
    signal input tree_high;
    signal input tree_low;
    signal input type_;
    signal input keypair;
    signal input chain;
    signal input hash;
    signal input m[35 * 16];
    signal output out[16];

    component pack_leaves[35];
    signal leaves_lo[35];
    signal leaves_hi[35];
    for (var i = 0; i < 35; i++) {
        pack_leaves[i] = PackBytes16To2Fe();
        for (var b = 0; b < 16; b++) pack_leaves[i].bytes[b] <== m[i * 16 + b];
        leaves_lo[i] <== pack_leaves[i].lo;
        leaves_hi[i] <== pack_leaves[i].hi;
    }

    component reduce = PoseidonGlReduce(35);
    for (var i = 0; i < 35; i++) {
        reduce.inputs_lo[i] <== leaves_lo[i];
        reduce.inputs_hi[i] <== leaves_hi[i];
    }

    component pack_pk = PackBytes16To2Fe();
    for (var b = 0; b < 16; b++) pack_pk.bytes[b] <== pk_seed[b];

    component mix = PoseidonGl(12);
    mix.inputs[0]  <== 3;            // tag T_len
    mix.inputs[1]  <== pack_pk.lo;
    mix.inputs[2]  <== pack_pk.hi;
    mix.inputs[3]  <== layer;
    mix.inputs[4]  <== tree_high;
    mix.inputs[5]  <== tree_low;
    mix.inputs[6]  <== type_;
    mix.inputs[7]  <== keypair;
    mix.inputs[8]  <== chain;
    mix.inputs[9]  <== hash;
    mix.inputs[10] <== reduce.out_lo;
    mix.inputs[11] <== reduce.out_hi;

    component unpack = UnpackFe2To16Bytes();
    unpack.lo <== mix.out_lo;
    unpack.hi <== mix.out_hi;
    for (var k = 0; k < 16; k++) out[k] <== unpack.bytes[k];
}

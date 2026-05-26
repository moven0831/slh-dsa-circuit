pragma circom 2.2.3;

include "poseidon_gl.circom";
include "circomlib/circuits/bitify.circom";

// Goldilocks (p = 2^64 - 2^32 + 1) packing helpers + Poseidon wrappers
// for the SLH-DSA Poseidon family ported to Goldilocks.
//
// **NON-STANDARD; FOR BENCHMARKING ONLY** — see hashes_gl.circom for caveats.

// PackBytes16To2Fe: 16 bytes (LE) → (lo, hi) two Goldilocks field elements.
// Goldilocks is 64-bit, so a 128-bit value needs 2 FEs.
//   out_lo = sum_{i=0}^{7}  bytes[i]      * 256^i      (low 8 bytes)
//   out_hi = sum_{i=0}^{7}  bytes[8 + i]  * 256^i      (high 8 bytes)
// Range-checks every byte to [0, 255] — required for soundness.
// R1CS cost: 16 × 8 = 128 bit-range checks. The two field-element sums are
// linear (no R1CS rows after --O2 simplification).
template PackBytes16To2Fe() {
    signal input  bytes[16];
    signal output lo;
    signal output hi;

    component to_bits[16];
    for (var i = 0; i < 16; i++) {
        to_bits[i] = Num2Bits(8);
        to_bits[i].in <== bytes[i];
    }

    var lc_lo = 0;
    for (var i = 0; i < 8; i++) lc_lo += bytes[i] * (256 ** i);
    lo <== lc_lo;

    var lc_hi = 0;
    for (var i = 0; i < 8; i++) lc_hi += bytes[8 + i] * (256 ** i);
    hi <== lc_hi;
}

// UnpackFe2To16Bytes: (lo, hi) two Goldilocks FEs → 16 bytes (LE).
// Decomposes each FE into 64 bits, then re-packs each byte from 8 bits.
// R1CS cost: 2 × 64 bit constraints (Num2Bits) + 16 linear assembly = 128 R1CS rows.
template UnpackFe2To16Bytes() {
    signal input  lo;
    signal input  hi;
    signal output bytes[16];

    component lo_bits = Num2Bits(64);
    component hi_bits = Num2Bits(64);
    lo_bits.in <== lo;
    hi_bits.in <== hi;

    for (var k = 0; k < 8; k++) {
        var s = 0;
        for (var b = 0; b < 8; b++) s += lo_bits.out[8 * k + b] * (1 << b);
        bytes[k] <== s;
    }
    for (var k = 0; k < 8; k++) {
        var s = 0;
        for (var b = 0; b < 8; b++) s += hi_bits.out[8 * k + b] * (1 << b);
        bytes[8 + k] <== s;
    }
}

// PoseidonGl(nInputs): one-shot Goldilocks Poseidon hash for nInputs ≤ 12.
// Initializes state[0..nInputs] = inputs, state[nInputs..12] = 0, applies one
// PoseidonGlPermute, and returns the first 2 lanes as output (16 bytes of hash).
//
// This is the same "permutation-as-fixed-arity-hash" construction used by
// circuits/poseidon/poseidon_wrap.circom's PoseidonHash16 over secq256r1 —
// NOT Plonky2's standard sponge (which would be rate=8, multiple perms for
// nInputs > 8). Cryptographic note: collision resistance follows from the
// underlying permutation being pseudorandom; this is the construction the
// project benchmarks (see CLAUDE.md spec deviations).
//
// R1CS: 472 (permutation) + 0 (linear initialization).
template PoseidonGl(nInputs) {
    assert(nInputs >= 1);
    assert(nInputs <= 12);
    signal input  inputs[nInputs];
    signal output out_lo;
    signal output out_hi;

    component p = PoseidonGlPermute();
    for (var i = 0; i < nInputs; i++) p.state_in[i] <== inputs[i];
    for (var i = nInputs; i < 12; i++) p.state_in[i] <== 0;

    out_lo <== p.state_out[0];
    out_hi <== p.state_out[1];
}

// PoseidonGlSponge14: arity-14 sponge for SlhH (14 input FEs > width=12).
// Uses Plonky2's overwrite-absorption sponge convention (rate=8, capacity=4):
//   state = [0; 12]
//   state[0..8]  = inputs[0..8];   permute → state'
//   state'[0..6] = inputs[8..14];  permute → state''
//   output       = state''[0..2]
// R1CS: 2 × 472 = 944 (two permutations) + 0 (linear absorption).
template PoseidonGlSponge14() {
    signal input  inputs[14];
    signal output out_lo;
    signal output out_hi;

    component p1 = PoseidonGlPermute();
    for (var i = 0; i < 8; i++)  p1.state_in[i] <== inputs[i];
    for (var i = 8; i < 12; i++) p1.state_in[i] <== 0;

    component p2 = PoseidonGlPermute();
    // Absorb chunk 2: overwrite first 6 lanes, retain lanes 6..12 from p1.
    for (var i = 0; i < 6; i++)  p2.state_in[i] <== inputs[8 + i];
    for (var i = 6; i < 12; i++) p2.state_in[i] <== p1.state_out[i];

    out_lo <== p2.state_out[0];
    out_hi <== p2.state_out[1];
}

// PoseidonGlReduce(N): binary Merkle reduce of N 16-byte values (each as 2 FEs)
// down to a single 16-byte value (2 FEs). Uses PoseidonGl(4) at each tree node
// over (left_lo, left_hi, right_lo, right_hi) → 2-FE output.
//
// For N=14: ceil(14/2) + ceil(7/2) + ceil(4/2) + ceil(2/2) = 7 + 4 + 2 + 1 = 14 nodes
// (the same tree shape as PoseidonReduce over secq256r1).
//
// Measured per-node cost: 440 R1CS (--O2 prunes zero-padded lanes 4..11 from
// PoseidonGl(4), shaving 32 mults vs the bare 472-R1CS permutation). For N=14
// reduce-only: 14 × 440 = 6,160 R1CS. Vs the secq256r1 baseline of 14 × 240 =
// 3,360 R1CS, this is a 1.83× bloat per node — expected from the t=12 Goldilocks
// permutation vs t=3 secq256r1 Poseidon(2). See research/folding/poseidon_gl_audit.md.
//
// Pads with zero leaves when N is odd (same convention as PoseidonReduce).
template PoseidonGlReduce(N) {
    signal input  inputs_lo[N];
    signal input  inputs_hi[N];
    signal output out_lo;
    signal output out_hi;

    if (N == 1) {
        out_lo <== inputs_lo[0];
        out_hi <== inputs_hi[0];
    } else {
        var n_pairs = (N + 1) \ 2;
        signal pair_lo[n_pairs];
        signal pair_hi[n_pairs];
        component p[n_pairs];
        for (var i = 0; i < n_pairs; i++) {
            p[i] = PoseidonGl(4);
            p[i].inputs[0] <== inputs_lo[2 * i];
            p[i].inputs[1] <== inputs_hi[2 * i];
            if (2 * i + 1 < N) {
                p[i].inputs[2] <== inputs_lo[2 * i + 1];
                p[i].inputs[3] <== inputs_hi[2 * i + 1];
            } else {
                p[i].inputs[2] <== 0;
                p[i].inputs[3] <== 0;
            }
            pair_lo[i] <== p[i].out_lo;
            pair_hi[i] <== p[i].out_hi;
        }
        component rec = PoseidonGlReduce(n_pairs);
        for (var i = 0; i < n_pairs; i++) {
            rec.inputs_lo[i] <== pair_lo[i];
            rec.inputs_hi[i] <== pair_hi[i];
        }
        out_lo <== rec.out_lo;
        out_hi <== rec.out_hi;
    }
}

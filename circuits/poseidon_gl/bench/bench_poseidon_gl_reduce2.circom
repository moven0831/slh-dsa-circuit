pragma circom 2.2.3;

include "../poseidon_gl_wrap.circom";

// Smallest GL bench — one PoseidonGl(4) over (lo_L, hi_L, lo_R, hi_R) — the
// per-node cost of PoseidonGlReduce's binary tree. Used as the Day-3 smoke-test
// circuit for the LatticeFold importer (analogous to the existing
// bench_poseidon_reduce2 at 240 R1CS over secq256r1).
template BenchPoseidonGlReduce2() {
    signal input  inputs[4];
    signal output out_lo;
    signal output out_hi;
    component p = PoseidonGl(4);
    for (var i = 0; i < 4; i++) p.inputs[i] <== inputs[i];
    out_lo <== p.out_lo;
    out_hi <== p.out_hi;
}

component main = BenchPoseidonGlReduce2();

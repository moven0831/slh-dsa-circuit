pragma circom 2.2.3;

include "../hashes_gl.circom";

// SlhF_Gl bench — measures per-call R1CS of the F primitive on Goldilocks Poseidon.
// See bench_slh_f_gl_smoke.circom note: inline `component main` because circomkit
// hardcodes secq256r1 (deviation explained in poseidon_gl_smoke.circom header).
template BenchSlhFGl() {
    signal input  pk_seed[16];
    signal input  layer;
    signal input  tree_high;
    signal input  tree_low;
    signal input  type_;
    signal input  keypair;
    signal input  chain;
    signal input  hash;
    signal input  m[16];
    signal output out[16];

    component f = SlhF();
    for (var b = 0; b < 16; b++) f.pk_seed[b] <== pk_seed[b];
    f.layer     <== layer;
    f.tree_high <== tree_high;
    f.tree_low  <== tree_low;
    f.type_     <== type_;
    f.keypair   <== keypair;
    f.chain     <== chain;
    f.hash      <== hash;
    for (var b = 0; b < 16; b++) f.m[b] <== m[b];
    for (var b = 0; b < 16; b++) out[b] <== f.out[b];
}

component main = BenchSlhFGl();

pragma circom 2.2.3;

include "../hashes_gl.circom";

template BenchSlhHGl() {
    signal input  pk_seed[16];
    signal input  layer;
    signal input  tree_high;
    signal input  tree_low;
    signal input  type_;
    signal input  keypair;
    signal input  chain;
    signal input  hash;
    signal input  m[32];
    signal output out[16];

    component h = SlhH();
    for (var b = 0; b < 16; b++) h.pk_seed[b] <== pk_seed[b];
    h.layer     <== layer;
    h.tree_high <== tree_high;
    h.tree_low  <== tree_low;
    h.type_     <== type_;
    h.keypair   <== keypair;
    h.chain     <== chain;
    h.hash      <== hash;
    for (var b = 0; b < 32; b++) h.m[b] <== m[b];
    for (var b = 0; b < 16; b++) out[b] <== h.out[b];
}

component main = BenchSlhHGl();

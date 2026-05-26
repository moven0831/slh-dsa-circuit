pragma circom 2.2.3;

include "../hashes_gl.circom";

template BenchSlhTlenGl() {
    signal input  pk_seed[16];
    signal input  layer;
    signal input  tree_high;
    signal input  tree_low;
    signal input  type_;
    signal input  keypair;
    signal input  chain;
    signal input  hash;
    signal input  m[35 * 16];
    signal output out[16];

    component t = SlhTlen();
    for (var b = 0; b < 16; b++) t.pk_seed[b] <== pk_seed[b];
    t.layer     <== layer;
    t.tree_high <== tree_high;
    t.tree_low  <== tree_low;
    t.type_     <== type_;
    t.keypair   <== keypair;
    t.chain     <== chain;
    t.hash      <== hash;
    for (var b = 0; b < 35 * 16; b++) t.m[b] <== m[b];
    for (var b = 0; b < 16; b++) out[b] <== t.out[b];
}

component main = BenchSlhTlenGl();

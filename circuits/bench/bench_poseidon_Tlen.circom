pragma circom 2.2.3;

include "../poseidon/hashes.circom";

template BenchPoseidonTlen() {
    signal input pk_seed[16];
    signal input layer;
    signal input tree_high;
    signal input tree_low;
    signal input type_;
    signal input keypair;
    signal input chain;
    signal input hash;
    signal input m[560];
    signal output out[16];

    component t = SlhTlen();
    for (var k = 0; k < 16; k++) t.pk_seed[k] <== pk_seed[k];
    t.layer     <== layer;
    t.tree_high <== tree_high;
    t.tree_low  <== tree_low;
    t.type_     <== type_;
    t.keypair   <== keypair;
    t.chain     <== chain;
    t.hash      <== hash;
    for (var k = 0; k < 560; k++) t.m[k] <== m[k];
    for (var k = 0; k < 16; k++) out[k] <== t.out[k];
}

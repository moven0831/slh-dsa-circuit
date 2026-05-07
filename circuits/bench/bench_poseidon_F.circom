pragma circom 2.2.3;

include "../poseidon/hashes.circom";

template BenchPoseidonF() {
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

    component f = SlhF();
    for (var k = 0; k < 16; k++) f.pk_seed[k] <== pk_seed[k];
    f.layer     <== layer;
    f.tree_high <== tree_high;
    f.tree_low  <== tree_low;
    f.type_     <== type_;
    f.keypair   <== keypair;
    f.chain     <== chain;
    f.hash      <== hash;
    for (var k = 0; k < 16; k++) f.m[k] <== m[k];
    for (var k = 0; k < 16; k++) out[k] <== f.out[k];
}

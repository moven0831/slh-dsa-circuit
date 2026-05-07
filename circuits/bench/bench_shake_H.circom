pragma circom 2.2.3;

include "../shake/hashes.circom";

template BenchShakeH() {
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

    component h = SlhH();
    for (var k = 0; k < 16; k++) h.pk_seed[k] <== pk_seed[k];
    h.layer     <== layer;
    h.tree_high <== tree_high;
    h.tree_low  <== tree_low;
    h.type_     <== type_;
    h.keypair   <== keypair;
    h.chain     <== chain;
    h.hash      <== hash;
    for (var k = 0; k < 32; k++) h.m[k] <== m[k];
    for (var k = 0; k < 16; k++) out[k] <== h.out[k];
}

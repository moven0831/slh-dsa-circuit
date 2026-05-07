pragma circom 2.2.3;

include "../sha2/hashes.circom";

template TestSha2H() {
    signal input iv_state[256];
    signal input layer;
    signal input tree_high;
    signal input tree_low;
    signal input type_;
    signal input keypair;
    signal input chain;
    signal input hash;
    signal input m[32];
    signal input expected_out[16];

    component h = SlhH();
    for (var k = 0; k < 256; k++) h.iv_state[k] <== iv_state[k];
    h.layer     <== layer;
    h.tree_high <== tree_high;
    h.tree_low  <== tree_low;
    h.type_     <== type_;
    h.keypair   <== keypair;
    h.chain     <== chain;
    h.hash      <== hash;
    for (var k = 0; k < 32; k++) h.m[k] <== m[k];
    for (var k = 0; k < 16; k++) h.out[k] === expected_out[k];
}

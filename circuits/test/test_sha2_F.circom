pragma circom 2.2.3;

include "../sha2/hashes.circom";

// Validation wrapper: asserts that SlhF's output matches Rust-computed
// expected_out. Witness gen succeeds iff the circuit and Rust agree.
template TestSha2F() {
    signal input iv_state[256];
    signal input layer;
    signal input tree_high;
    signal input tree_low;
    signal input type_;
    signal input keypair;
    signal input chain;
    signal input hash;
    signal input m[16];
    signal input expected_out[16];

    component f = SlhF();
    for (var k = 0; k < 256; k++) f.iv_state[k] <== iv_state[k];
    f.layer     <== layer;
    f.tree_high <== tree_high;
    f.tree_low  <== tree_low;
    f.type_     <== type_;
    f.keypair   <== keypair;
    f.chain     <== chain;
    f.hash      <== hash;
    for (var k = 0; k < 16; k++) f.m[k] <== m[k];
    for (var k = 0; k < 16; k++) f.out[k] === expected_out[k];
}

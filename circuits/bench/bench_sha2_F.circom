pragma circom 2.2.3;

include "../sha2/hashes.circom";

// Per-F-call cost in midstate-optimized SHA-2. The bench takes
// iv_state directly as a witness input — the seed compression is
// amortized once per circuit (see bench_sha2_seed_iv).
template BenchSha2F() {
    signal input iv_state[256];
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
    for (var k = 0; k < 256; k++) f.iv_state[k] <== iv_state[k];
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

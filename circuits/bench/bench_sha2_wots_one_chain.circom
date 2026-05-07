pragma circom 2.2.3;

include "../sha2/hashes.circom";
include "circomlib/circuits/multiplexer.circom";
include "circomlib/circuits/bitify.circom";

// Single-chain WOTS verifier (midstate) — 15 F invocations + 1 16-way mux.
// Takes iv_state directly (the seed compression cost is amortized
// elsewhere; see bench_sha2_seed_iv).
template BenchSha2WotsOneChain() {
    signal input iv_state[256];
    signal input layer;
    signal input tree_high;
    signal input tree_low;
    signal input keypair;
    signal input chain_idx;
    signal input msg_chunk;
    signal input sig[16];
    signal output chain_pk[16];

    component f_step[15];
    signal cand[16][16];
    for (var b = 0; b < 16; b++) cand[0][b] <== sig[b];

    for (var k = 0; k < 15; k++) {
        f_step[k] = SlhF();
        for (var b = 0; b < 256; b++) f_step[k].iv_state[b] <== iv_state[b];
        f_step[k].layer     <== layer;
        f_step[k].tree_high <== tree_high;
        f_step[k].tree_low  <== tree_low;
        f_step[k].type_     <== 0;
        f_step[k].keypair   <== keypair;
        f_step[k].chain     <== chain_idx;
        f_step[k].hash      <== msg_chunk + k;
        for (var b = 0; b < 16; b++) f_step[k].m[b] <== cand[k][b];
        for (var b = 0; b < 16; b++) cand[k+1][b] <== f_step[k].out[b];
    }

    component mux = Multiplexer(16, 16);
    for (var k = 0; k < 16; k++) {
        for (var b = 0; b < 16; b++) mux.inp[k][b] <== cand[k][b];
    }
    mux.sel <== 15 - msg_chunk;
    for (var b = 0; b < 16; b++) chain_pk[b] <== mux.out[b];
}

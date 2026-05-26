pragma circom 2.2.3;

// IMPORTANT: hashes_gl.circom defines SlhF, SlhH, SlhTlen (no suffix), so when
// ht_layer_step.circom → xmss.circom → wots.circom references those names,
// they resolve to the Goldilocks-Poseidon variants. Include order matters:
// hashes_gl.circom must come BEFORE ht_layer_step.circom.
include "../hashes_gl.circom";
include "../../common/ht_layer_step.circom";

template BenchHtLayerGl() {
    signal input  pk_seed[16];
    signal input  layer;
    signal input  tree_low;
    signal input  idx_leaf;
    signal input  prev_root[16];
    signal input  wots_sig[35][16];
    signal input  xmss_auth[9][16];
    signal output next_root[16];

    component step = HtLayerStep();
    for (var b = 0; b < 16; b++) step.pk_seed[b] <== pk_seed[b];
    step.layer    <== layer;
    step.tree_low <== tree_low;
    step.idx_leaf <== idx_leaf;
    for (var b = 0; b < 16; b++) step.prev_root[b] <== prev_root[b];
    for (var i = 0; i < 35; i++) {
        for (var b = 0; b < 16; b++) step.wots_sig[i][b] <== wots_sig[i][b];
    }
    for (var i = 0; i < 9; i++) {
        for (var b = 0; b < 16; b++) step.xmss_auth[i][b] <== xmss_auth[i][b];
    }
    for (var b = 0; b < 16; b++) next_root[b] <== step.next_root[b];
}

component main = BenchHtLayerGl();

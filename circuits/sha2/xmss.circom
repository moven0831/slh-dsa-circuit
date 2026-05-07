pragma circom 2.2.3;

include "../common/params.circom";
include "../common/adrs.circom";
include "wots.circom";        // SHA-2 WotsPkFromSig
include "hashes.circom";      // SHA-2 SlhH
include "circomlib/circuits/multiplexer.circom";
include "circomlib/circuits/bitify.circom";

// SHA-2 specific XmssPkFromSig — iv_state-based.
template XmssPkFromSig() {
    signal input iv_state[256];
    signal input layer;
    signal input tree_high;
    signal input tree_low;
    signal input idx_leaf;
    signal input wots_msg[35];
    signal input wots_sig[35][16];
    signal input xmss_auth[9][16];
    signal output xmss_root[16];

    component idx_bits = Num2Bits(9);
    idx_bits.in <== idx_leaf;

    component wots = WotsPkFromSig();
    for (var b = 0; b < 256; b++) wots.iv_state[b] <== iv_state[b];
    wots.layer     <== layer;
    wots.tree_high <== tree_high;
    wots.tree_low  <== tree_low;
    wots.keypair   <== idx_leaf;
    for (var i = 0; i < 35; i++) {
        wots.msg_chunks[i] <== wots_msg[i];
        for (var b = 0; b < 16; b++) wots.sig[i][b] <== wots_sig[i][b];
    }

    signal node[10][16];
    for (var b = 0; b < 16; b++) node[0][b] <== wots.wots_pk[b];

    component path_h[9];
    component left_mux[9];
    component right_mux[9];

    for (var k = 0; k < 9; k++) {
        var tree_index_at_k1 = 0;
        for (var b = 0; b < 9 - (k + 1) + 1; b++) {
            if (k + 1 + b <= 8) {
                tree_index_at_k1 += idx_bits.out[k + 1 + b] * (1 << b);
            }
        }

        left_mux[k] = Multiplexer(16, 2);
        right_mux[k] = Multiplexer(16, 2);
        for (var b = 0; b < 16; b++) {
            left_mux[k].inp[0][b]  <== node[k][b];
            left_mux[k].inp[1][b]  <== xmss_auth[k][b];
            right_mux[k].inp[0][b] <== xmss_auth[k][b];
            right_mux[k].inp[1][b] <== node[k][b];
        }
        left_mux[k].sel  <== idx_bits.out[k];
        right_mux[k].sel <== idx_bits.out[k];

        path_h[k] = SlhH();
        for (var b = 0; b < 256; b++) path_h[k].iv_state[b] <== iv_state[b];
        path_h[k].layer     <== layer;
        path_h[k].tree_high <== tree_high;
        path_h[k].tree_low  <== tree_low;
        path_h[k].type_     <== 2;
        path_h[k].keypair   <== 0;
        path_h[k].chain     <== k + 1;
        path_h[k].hash      <== tree_index_at_k1;
        for (var b = 0; b < 16; b++) {
            path_h[k].m[b]      <== left_mux[k].out[b];
            path_h[k].m[16 + b] <== right_mux[k].out[b];
        }
        for (var b = 0; b < 16; b++) node[k + 1][b] <== path_h[k].out[b];
    }

    for (var b = 0; b < 16; b++) xmss_root[b] <== node[9][b];
}

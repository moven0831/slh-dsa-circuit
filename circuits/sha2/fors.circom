pragma circom 2.2.3;

include "../common/params.circom";
include "../common/adrs.circom";
include "circomlib/circuits/multiplexer.circom";
include "circomlib/circuits/bitify.circom";
include "hashes.circom";   // SHA-2 SlhF/SlhH/SlhTk

// SHA-2 specific ForsPkFromSig — iv_state-based.
template ForsPkFromSig() {
    signal input iv_state[256];
    signal input layer;
    signal input tree_high;
    signal input tree_low;
    signal input keypair;
    signal input md_indices[14];
    signal input sig_fors[14][13][16];
    signal output fors_pk[16];

    component idx_bits[14];
    for (var i = 0; i < 14; i++) {
        idx_bits[i] = Num2Bits(12);
        idx_bits[i].in <== md_indices[i];
    }

    component leaf_f[14];
    component path_h[14][12];
    component left_mux[14][12];
    component right_mux[14][12];
    signal node[14][13][16];
    signal tree_root[14][16];

    for (var i = 0; i < 14; i++) {
        leaf_f[i] = SlhF();
        for (var b = 0; b < 256; b++) leaf_f[i].iv_state[b] <== iv_state[b];
        leaf_f[i].layer     <== layer;
        leaf_f[i].tree_high <== tree_high;
        leaf_f[i].tree_low  <== tree_low;
        leaf_f[i].type_     <== 3;
        leaf_f[i].keypair   <== keypair;
        leaf_f[i].chain     <== 0;
        leaf_f[i].hash      <== i * 4096 + md_indices[i];
        for (var b = 0; b < 16; b++) leaf_f[i].m[b] <== sig_fors[i][0][b];
        for (var b = 0; b < 16; b++) node[i][0][b] <== leaf_f[i].out[b];

        for (var z = 1; z <= 12; z++) {
            left_mux[i][z-1] = Multiplexer(16, 2);
            right_mux[i][z-1] = Multiplexer(16, 2);
            for (var b = 0; b < 16; b++) {
                left_mux[i][z-1].inp[0][b]  <== node[i][z-1][b];
                left_mux[i][z-1].inp[1][b]  <== sig_fors[i][z][b];
                right_mux[i][z-1].inp[0][b] <== sig_fors[i][z][b];
                right_mux[i][z-1].inp[1][b] <== node[i][z-1][b];
            }
            left_mux[i][z-1].sel  <== idx_bits[i].out[z-1];
            right_mux[i][z-1].sel <== idx_bits[i].out[z-1];

            var tree_index_shifted = i * (1 << (12 - z));
            for (var k = 0; k < 12 - z; k++) {
                tree_index_shifted += idx_bits[i].out[z + k] * (1 << k);
            }

            path_h[i][z-1] = SlhH();
            for (var b = 0; b < 256; b++) path_h[i][z-1].iv_state[b] <== iv_state[b];
            path_h[i][z-1].layer     <== layer;
            path_h[i][z-1].tree_high <== tree_high;
            path_h[i][z-1].tree_low  <== tree_low;
            path_h[i][z-1].type_     <== 3;
            path_h[i][z-1].keypair   <== keypair;
            path_h[i][z-1].chain     <== z;
            path_h[i][z-1].hash      <== tree_index_shifted;
            for (var b = 0; b < 16; b++) {
                path_h[i][z-1].m[b]      <== left_mux[i][z-1].out[b];
                path_h[i][z-1].m[16 + b] <== right_mux[i][z-1].out[b];
            }
            for (var b = 0; b < 16; b++) node[i][z][b] <== path_h[i][z-1].out[b];
        }

        for (var b = 0; b < 16; b++) tree_root[i][b] <== node[i][12][b];
    }

    component tk = SlhTk();
    for (var b = 0; b < 256; b++) tk.iv_state[b] <== iv_state[b];
    tk.layer     <== layer;
    tk.tree_high <== tree_high;
    tk.tree_low  <== tree_low;
    tk.type_     <== 4;
    tk.keypair   <== keypair;
    tk.chain     <== 0;
    tk.hash      <== 0;
    for (var i = 0; i < 14; i++) {
        for (var b = 0; b < 16; b++) {
            tk.m[i * 16 + b] <== tree_root[i][b];
        }
    }
    for (var b = 0; b < 16; b++) fors_pk[b] <== tk.out[b];
}

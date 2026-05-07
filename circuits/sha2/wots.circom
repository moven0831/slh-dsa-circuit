pragma circom 2.2.3;

include "../common/params.circom";
include "../common/adrs.circom";
include "circomlib/circuits/multiplexer.circom";
include "hashes.circom";   // SHA-2 SlhF/SlhTlen (midstate-based)

// SHA-2 specific WotsPkFromSig — see common/wots.circom for the
// algorithm details. This version takes `iv_state[256]` (the
// midstate-precomputed SHA-2 IV from pk_seed) instead of pk_seed.
template WotsPkFromSig() {
    signal input iv_state[256];
    signal input layer;
    signal input tree_high;
    signal input tree_low;
    signal input keypair;
    signal input msg_chunks[35];
    signal input sig[35][16];
    signal output wots_pk[16];

    component f_step[35][15];
    signal cand[35][16][16];
    component chain_mux[35];
    signal chain_pk[35][16];

    for (var i = 0; i < 35; i++) {
        for (var b = 0; b < 16; b++) {
            cand[i][0][b] <== sig[i][b];
        }

        for (var k = 0; k < 15; k++) {
            f_step[i][k] = SlhF();
            for (var b = 0; b < 256; b++) {
                f_step[i][k].iv_state[b] <== iv_state[b];
            }
            f_step[i][k].layer     <== layer;
            f_step[i][k].tree_high <== tree_high;
            f_step[i][k].tree_low  <== tree_low;
            f_step[i][k].type_     <== 0;
            f_step[i][k].keypair   <== keypair;
            f_step[i][k].chain     <== i;
            f_step[i][k].hash      <== msg_chunks[i] + k;
            for (var b = 0; b < 16; b++) {
                f_step[i][k].m[b] <== cand[i][k][b];
            }
            for (var b = 0; b < 16; b++) {
                cand[i][k + 1][b] <== f_step[i][k].out[b];
            }
        }

        chain_mux[i] = Multiplexer(16, 16);
        for (var k = 0; k < 16; k++) {
            for (var b = 0; b < 16; b++) {
                chain_mux[i].inp[k][b] <== cand[i][k][b];
            }
        }
        chain_mux[i].sel <== 15 - msg_chunks[i];
        for (var b = 0; b < 16; b++) {
            chain_pk[i][b] <== chain_mux[i].out[b];
        }
    }

    component tlen = SlhTlen();
    for (var b = 0; b < 256; b++) {
        tlen.iv_state[b] <== iv_state[b];
    }
    tlen.layer     <== layer;
    tlen.tree_high <== tree_high;
    tlen.tree_low  <== tree_low;
    tlen.type_     <== 1;
    tlen.keypair   <== keypair;
    tlen.chain     <== 0;
    tlen.hash      <== 0;
    for (var i = 0; i < 35; i++) {
        for (var b = 0; b < 16; b++) {
            tlen.m[i * 16 + b] <== chain_pk[i][b];
        }
    }
    for (var b = 0; b < 16; b++) {
        wots_pk[b] <== tlen.out[b];
    }
}

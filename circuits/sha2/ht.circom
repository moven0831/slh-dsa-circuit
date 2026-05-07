pragma circom 2.2.3;

include "../common/params.circom";
include "../common/digest.circom";   // Base2bWithCsum
include "xmss.circom";                // SHA-2 XmssPkFromSig
include "circomlib/circuits/bitify.circom";

// SHA-2 specific HtVerify — iv_state-based.
template HtVerify() {
    signal input iv_state[256];
    signal input pk_root[16];
    signal input idx_tree;
    signal input idx_leaf;
    signal input fors_root[16];
    signal input ht_sig[7][44][16];
    signal output valid;

    component idx_tree_bits = Num2Bits(54);
    idx_tree_bits.in <== idx_tree;

    component xmss[7];
    component chunks_compute[7];
    signal layer_msg[7][16];

    for (var b = 0; b < 16; b++) layer_msg[0][b] <== fors_root[b];

    for (var j = 0; j < 7; j++) {
        chunks_compute[j] = Base2bWithCsum();
        for (var b = 0; b < 16; b++) chunks_compute[j].digest[b] <== layer_msg[j][b];

        xmss[j] = XmssPkFromSig();
        for (var b = 0; b < 256; b++) xmss[j].iv_state[b] <== iv_state[b];
        xmss[j].layer     <== j;
        xmss[j].tree_high <== 0;

        if (j == 0) {
            xmss[j].tree_low  <== idx_tree;
            xmss[j].idx_leaf  <== idx_leaf;
        } else {
            var tl = 0;
            for (var b = 0; b < 54 - 9 * j; b++) {
                tl += idx_tree_bits.out[9 * j + b] * (1 << b);
            }
            xmss[j].tree_low <== tl;

            var il = 0;
            for (var b = 0; b < 9; b++) {
                il += idx_tree_bits.out[9 * (j - 1) + b] * (1 << b);
            }
            xmss[j].idx_leaf <== il;
        }

        for (var i = 0; i < 35; i++) {
            xmss[j].wots_msg[i] <== chunks_compute[j].chunks[i];
            for (var b = 0; b < 16; b++) xmss[j].wots_sig[i][b] <== ht_sig[j][i][b];
        }
        for (var i = 0; i < 9; i++) {
            for (var b = 0; b < 16; b++) {
                xmss[j].xmss_auth[i][b] <== ht_sig[j][35 + i][b];
            }
        }
        if (j < 6) {
            for (var b = 0; b < 16; b++) layer_msg[j + 1][b] <== xmss[j].xmss_root[b];
        }
    }

    signal acc[17];
    acc[0] <== 1;
    for (var b = 0; b < 16; b++) {
        xmss[6].xmss_root[b] === pk_root[b];
        acc[b + 1] <== acc[b];
    }
    valid <== acc[16];
}

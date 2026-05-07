pragma circom 2.2.3;

include "../sha2/hashes.circom";
include "../common/wots.circom";

template BenchSha2Wots() {
    signal input pk_seed[16];
    signal input layer;
    signal input tree_high;
    signal input tree_low;
    signal input keypair;
    signal input msg_chunks[35];
    signal input sig[35][16];
    signal output wots_pk[16];

    component w = WotsPkFromSig();
    for (var b = 0; b < 16; b++) w.pk_seed[b] <== pk_seed[b];
    w.layer <== layer;
    w.tree_high <== tree_high;
    w.tree_low <== tree_low;
    w.keypair <== keypair;
    for (var i = 0; i < 35; i++) {
        w.msg_chunks[i] <== msg_chunks[i];
        for (var b = 0; b < 16; b++) w.sig[i][b] <== sig[i][b];
    }
    for (var b = 0; b < 16; b++) wots_pk[b] <== w.wots_pk[b];
}

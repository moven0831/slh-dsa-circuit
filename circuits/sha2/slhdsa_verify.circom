pragma circom 2.2.3;

include "../common/params.circom";
include "../common/digest.circom";    // ParseDigest
include "hashes.circom";               // SHA-2 SlhHMsg + Sha256SeedIv (via sha256_midstate)
include "sha256_midstate.circom";      // Sha256SeedIv
include "fors.circom";                 // SHA-2 ForsPkFromSig
include "ht.circom";                   // SHA-2 HtVerify

// SHA-2 specific top-level SLH-DSA-128s verifier (midstate-optimized).
//
// Computes iv_state once from pk_seed via Sha256SeedIv (paid once per
// circuit, ~29K constraints), then passes iv_state down through HT.
//
// HMsg uses pk_seed directly (no midstate; its prefix is R||pk_seed
// rather than pk_seed||zeros).
template SlhDsaVerify() {
    signal input pk[32];
    signal input msg[1024];
    signal input r[16];
    signal input sig_fors[14][13][16];
    signal input sig_ht[7][44][16];
    signal output valid;

    signal pk_seed[16];
    signal pk_root[16];
    for (var i = 0; i < 16; i++) {
        pk_seed[i] <== pk[i];
        pk_root[i] <== pk[16 + i];
    }

    // Compute iv_state once for all SHA-2 F/H/T_l calls.
    component seed_iv = Sha256SeedIv();
    for (var i = 0; i < 16; i++) seed_iv.pk_seed[i] <== pk_seed[i];

    // H_msg digest (uses pk_seed directly, not iv_state).
    component hmsg = SlhHMsg();
    for (var i = 0; i < 16; i++)   hmsg.r[i] <== r[i];
    for (var i = 0; i < 16; i++)   hmsg.pk_seed[i] <== pk_seed[i];
    for (var i = 0; i < 16; i++)   hmsg.pk_root[i] <== pk_root[i];
    for (var i = 0; i < 1024; i++) hmsg.m[i] <== msg[i];

    component parse = ParseDigest();
    for (var i = 0; i < 30; i++) parse.digest[i] <== hmsg.out[i];

    // FORS pubkey from signature.
    component fors = ForsPkFromSig();
    for (var b = 0; b < 256; b++) fors.iv_state[b] <== seed_iv.iv_state[b];
    fors.layer     <== 0;
    fors.tree_high <== 0;
    fors.tree_low  <== parse.idx_tree;
    fors.keypair   <== parse.idx_leaf;
    for (var i = 0; i < 14; i++) fors.md_indices[i] <== parse.md_indices[i];
    for (var i = 0; i < 14; i++) {
        for (var j = 0; j < 13; j++) {
            for (var b = 0; b < 16; b++) fors.sig_fors[i][j][b] <== sig_fors[i][j][b];
        }
    }

    // HT verification.
    component ht = HtVerify();
    for (var b = 0; b < 256; b++) ht.iv_state[b] <== seed_iv.iv_state[b];
    for (var b = 0; b < 16; b++) ht.pk_root[b] <== pk_root[b];
    ht.idx_tree <== parse.idx_tree;
    ht.idx_leaf <== parse.idx_leaf;
    for (var b = 0; b < 16; b++) ht.fors_root[b] <== fors.fors_pk[b];
    for (var j = 0; j < 7; j++) {
        for (var i = 0; i < 44; i++) {
            for (var b = 0; b < 16; b++) ht.ht_sig[j][i][b] <== sig_ht[j][i][b];
        }
    }

    valid <== ht.valid;
}

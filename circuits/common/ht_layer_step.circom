pragma circom 2.2.3;

include "params.circom";
include "digest.circom";   // Base2bWithCsum
include "xmss.circom";     // XmssPkFromSig (transitively pulls in wots.circom)

// HtLayerStep — D4-restricted fold step circuit.
//
// One iteration of the HT-verification loop from circuits/common/ht.circom:49-90,
// extracted as a standalone template suitable for folding. Each call verifies
// one XMSS subtree at a specified HT layer: 35 WOTS chains (15 F-steps each)
// + 1 T_len compress + 9 Merkle H hashes ≈ 573K R1CS on secq256r1 (projected
// ~510K on Goldilocks Poseidon per poseidon_gl_audit.md).
//
// The fold-step state (public input z_i, public output z_{i+1}) carries:
//   - pk_seed[16]   : sticky (could be moved to non-folded public input for the IVC)
//   - layer         : current HT layer index ∈ [0, 6]
//   - tree_low      : ADRS.tree_low for this layer (idx_tree >> (h' * layer))
//   - idx_leaf      : ADRS.idx_leaf for this layer ((idx_tree >> (h' * (layer-1))) & 2^h' - 1)
//   - prev_root[16] : at layer 0, this is fors_root; at layer j>0, the previous
//                     layer's xmss_root
//
// Output:
//   - next_root[16] : this layer's xmss_root, which becomes the next layer's prev_root
//
// The driver advances (layer, tree_low, idx_leaf) per FIPS 205 §9 — see
// circuits/common/ht.circom:64-74 for the bit-slicing arithmetic. tree_high is
// always 0 in SLH-DSA-128s (idx_tree fits in 54 bits = tree_low's range).
//
// Soundness: prev_root, tree_low, idx_leaf, and layer are public — the driver
// commits to them as part of z_i. The witness (wots_sig, xmss_auth) is private.
// The output next_root is the only signal the step "produces"; everything else
// in z_{i+1} is either copied through (pk_seed) or advanced by the driver.
//
// Family-agnostic: relies on SlhF, SlhH, SlhTlen defined in the includer's
// hashes_gl.circom (or hashes.circom, etc.) — same convention as wots.circom.
template HtLayerStep() {
    signal input  pk_seed[16];
    signal input  layer;
    signal input  tree_low;
    signal input  idx_leaf;
    signal input  prev_root[16];
    signal input  wots_sig[35][16];
    signal input  xmss_auth[9][16];
    signal output next_root[16];

    component chunks_compute = Base2bWithCsum();
    for (var b = 0; b < 16; b++) chunks_compute.digest[b] <== prev_root[b];

    component xmss = XmssPkFromSig();
    for (var b = 0; b < 16; b++) xmss.pk_seed[b] <== pk_seed[b];
    xmss.layer     <== layer;
    xmss.tree_high <== 0;
    xmss.tree_low  <== tree_low;
    xmss.idx_leaf  <== idx_leaf;

    for (var i = 0; i < 35; i++) {
        xmss.wots_msg[i] <== chunks_compute.chunks[i];
        for (var b = 0; b < 16; b++) xmss.wots_sig[i][b] <== wots_sig[i][b];
    }
    for (var i = 0; i < 9; i++) {
        for (var b = 0; b < 16; b++) xmss.xmss_auth[i][b] <== xmss_auth[i][b];
    }

    for (var b = 0; b < 16; b++) next_root[b] <== xmss.xmss_root[b];
}

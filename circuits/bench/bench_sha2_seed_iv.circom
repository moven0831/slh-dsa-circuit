pragma circom 2.2.3;

include "../sha2/sha256_midstate.circom";

// One-time SHA-2 midstate seed-IV computation cost
// (Sha256Compression(default_IV, pk_seed||zeros[48])).
// This cost is paid once per circuit and amortized across all
// F/H/T_l calls.
template BenchSha2SeedIv() {
    signal input pk_seed[16];
    signal output iv_state[256];

    component s = Sha256SeedIv();
    for (var k = 0; k < 16; k++) s.pk_seed[k] <== pk_seed[k];
    for (var k = 0; k < 256; k++) iv_state[k] <== s.iv_state[k];
}

pragma circom 2.2.3;

// Monolithic SLH-DSA-128s verifier wired through the Goldilocks Poseidon hash
// family. Mirrors `circuits/main_poseidon.circom` (secq256r1) exactly in shape;
// the only difference is the include order — `hashes_gl.circom` is pulled in
// BEFORE the common verifier templates so the unsuffixed `SlhF / SlhH / SlhTk
// / SlhTlen / SlhHMsg` references resolve to the Goldilocks implementations.
//
// CONVENTION NOTE — inline `component main`.
// Same deviation as every other circuit under `circuits/poseidon_gl/`:
// circomkit hardcodes `prime: secq256r1`, so Goldilocks circuits are compiled
// via direct `circom --prime goldilocks` (see scripts/build_main_poseidon_gl.sh).
//
// Track 2 deliverable: feeds the `slh-dsa-128s-poseidon-bench` companion repo's
// `slh-dsa-spartan2-gl` bench crate (Spartan2-GL standalone prove + verify).
// Compile flag should mirror `main_poseidon`: `--O2` for constraint count
// comparability with the secq256r1 baseline.

include "hashes_gl.circom";
include "../common/slhdsa_verify.circom";

template MainPoseidonGl() {
    signal input pk[32];
    signal input msg[1024];
    signal input r[16];
    signal input sig_fors[14][13][16];
    signal input sig_ht[7][44][16];
    signal output valid;

    component v = SlhDsaVerify();
    for (var i = 0; i < 32; i++)   v.pk[i] <== pk[i];
    for (var i = 0; i < 1024; i++) v.msg[i] <== msg[i];
    for (var i = 0; i < 16; i++)   v.r[i] <== r[i];
    for (var i = 0; i < 14; i++) {
        for (var j = 0; j < 13; j++) {
            for (var b = 0; b < 16; b++) v.sig_fors[i][j][b] <== sig_fors[i][j][b];
        }
    }
    for (var j = 0; j < 7; j++) {
        for (var i = 0; i < 44; i++) {
            for (var b = 0; b < 16; b++) v.sig_ht[j][i][b] <== sig_ht[j][i][b];
        }
    }
    valid <== v.valid;
}

component main = MainPoseidonGl();

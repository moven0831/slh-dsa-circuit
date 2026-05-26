pragma circom 2.2.3;

include "poseidon_gl_constants.circom";

// Plonky2 Goldilocks Poseidon permutation.
//
// Layout per Plonky2 (mir-protocol / 0xPolygonZero plonky2 @ v1.1.0):
//   t = 12, full rounds = 8 (4 + 4), partial rounds = 22, total = 30, S-box = x^7.
//   Standard MDS multiplication (also used in partial rounds — Plonky2's "fast partial"
//   optimization is for Rust performance only; in R1CS, MDS is linear and free, so we
//   use the canonical mds_row_shf form everywhere).
//
// Round structure (rounds r = 0..29):
//   1. Add round constants:      tmp[i] = s[r][i] + ALL_ROUND_CONSTANTS[r][i]   (linear)
//   2. S-box layer:
//        - if r ∈ [0,4) ∪ [26,30)  (full):    post[r][i] = tmp[i]^7  for all i ∈ [0,12)
//        - if r ∈ [4, 26)         (partial):  post[r][0] = tmp[0]^7,   post[r][i] = tmp[i] for i > 0
//   3. MDS layer:                s[r+1][k] = sum_i post[r][(i+k) mod 12] * CIRC[i]
//                                            + post[r][k] * DIAG[k]              (linear)
//
// R1CS cost per permutation (counted by hand, --O2 should match within 5%):
//   S-box(x^7) = 4 quadratic constraints: x2 = x*x; x4 = x2*x2; x3 = x*x2; x7 = x3*x4.
//   Full rounds:    8 rounds × 12 lanes × 4 constraints = 384.
//   Partial rounds: 22 rounds × 1 lane × 4 constraints  =  88.
//   Total:                                                 472 R1CS.
//
// Validation: smoke-tested against Plonky2 reference vector
// (see circuits/poseidon_gl/poseidon_gl_smoke.circom + Day 1 review notes).

template PoseidonGlPermute() {
    signal input  state_in[12];
    signal output state_out[12];

    var RC[30][12] = getPoseidonGlRoundConstants();
    var CIRC[12]   = getPoseidonGlMdsCirc();
    var DIAG[12]   = getPoseidonGlMdsDiag();

    // State after each MDS layer: 31 snapshots (initial + 30 round outputs).
    signal s[31][12];

    // S-box intermediates for full rounds (8 full rounds × 12 lanes).
    // full_x{2,3,4,7}[fr_idx][lane]; fr_idx ∈ [0,8): rounds 0-3 use 0-3, rounds 26-29 use 4-7.
    signal full_x2[8][12];
    signal full_x3[8][12];
    signal full_x4[8][12];
    signal full_x7[8][12];

    // S-box intermediates for partial rounds (lane 0 only, 22 partial rounds).
    signal part_x2[22];
    signal part_x3[22];
    signal part_x4[22];
    signal part_x7[22];

    // Per-round post-S-box state (all 30 rounds × 12 lanes; linear from S-box or const-add).
    signal post[30][12];

    for (var i = 0; i < 12; i++) {
        s[0][i] <== state_in[i];
    }

    // -------- Full rounds 0..3 --------
    for (var r = 0; r < 4; r++) {
        for (var i = 0; i < 12; i++) {
            full_x2[r][i] <== (s[r][i] + RC[r][i]) * (s[r][i] + RC[r][i]);
            full_x4[r][i] <== full_x2[r][i] * full_x2[r][i];
            full_x3[r][i] <== (s[r][i] + RC[r][i]) * full_x2[r][i];
            full_x7[r][i] <== full_x3[r][i] * full_x4[r][i];
            post[r][i]    <== full_x7[r][i];
        }
        for (var k = 0; k < 12; k++) {
            var lc = 0;
            for (var i = 0; i < 12; i++) {
                lc += post[r][(i + k) % 12] * CIRC[i];
            }
            lc += post[r][k] * DIAG[k];
            s[r + 1][k] <== lc;
        }
    }

    // -------- Partial rounds 4..25 --------
    for (var r = 4; r < 26; r++) {
        var pr = r - 4;
        // S-box on lane 0 only.
        part_x2[pr] <== (s[r][0] + RC[r][0]) * (s[r][0] + RC[r][0]);
        part_x4[pr] <== part_x2[pr] * part_x2[pr];
        part_x3[pr] <== (s[r][0] + RC[r][0]) * part_x2[pr];
        part_x7[pr] <== part_x3[pr] * part_x4[pr];
        post[r][0]  <== part_x7[pr];
        // Lanes 1..11: linear (just add round constant — no S-box).
        for (var i = 1; i < 12; i++) {
            post[r][i] <== s[r][i] + RC[r][i];
        }
        // MDS.
        for (var k = 0; k < 12; k++) {
            var lc = 0;
            for (var i = 0; i < 12; i++) {
                lc += post[r][(i + k) % 12] * CIRC[i];
            }
            lc += post[r][k] * DIAG[k];
            s[r + 1][k] <== lc;
        }
    }

    // -------- Full rounds 26..29 --------
    for (var r = 26; r < 30; r++) {
        var fr = (r - 26) + 4; // map rounds 26..29 to full_x* indices 4..7
        for (var i = 0; i < 12; i++) {
            full_x2[fr][i] <== (s[r][i] + RC[r][i]) * (s[r][i] + RC[r][i]);
            full_x4[fr][i] <== full_x2[fr][i] * full_x2[fr][i];
            full_x3[fr][i] <== (s[r][i] + RC[r][i]) * full_x2[fr][i];
            full_x7[fr][i] <== full_x3[fr][i] * full_x4[fr][i];
            post[r][i]     <== full_x7[fr][i];
        }
        for (var k = 0; k < 12; k++) {
            var lc = 0;
            for (var i = 0; i < 12; i++) {
                lc += post[r][(i + k) % 12] * CIRC[i];
            }
            lc += post[r][k] * DIAG[k];
            s[r + 1][k] <== lc;
        }
    }

    for (var i = 0; i < 12; i++) {
        state_out[i] <== s[30][i];
    }
}

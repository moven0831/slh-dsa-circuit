pragma circom 2.2.3;

include "poseidon_gl.circom";

// Smoke-test wrapper: one PoseidonGlPermute call, all 12 input lanes as private inputs,
// all 12 output lanes as public outputs. Used to measure R1CS count (expected: ~472).
template PoseidonGlSmoke() {
    signal input  state_in[12];
    signal output state_out[12];

    component p = PoseidonGlPermute();
    for (var i = 0; i < 12; i++) {
        p.state_in[i] <== state_in[i];
    }
    for (var i = 0; i < 12; i++) {
        state_out[i] <== p.state_out[i];
    }
}

component main = PoseidonGlSmoke();

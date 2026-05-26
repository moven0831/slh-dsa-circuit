pragma circom 2.2.3;

include "poseidon_gl.circom";

// Smoke-test wrapper: one PoseidonGlPermute call, all 12 input lanes as private inputs,
// all 12 output lanes as public outputs. Used to measure R1CS count (expected: 472).
//
// CONVENTION NOTE — inline `component main`.
// CLAUDE.md says `circuits/main/` is the canonical location for circomkit-generated
// wrapper mains, and most circuits in this repo (verifier mains, bench wrappers, test
// wrappers) rely on circomkit auto-generating `component main = ...` from `circuits.json`.
// We deviate here because `circomkit.json` hardcodes `"prime": "secq256r1"` and there is
// no per-circuit prime override in circomkit's config schema. Goldilocks circuits must
// be compiled by direct `circom --prime goldilocks` invocation (see scripts/test_poseidon_gl.sh).
// When circomkit gains per-circuit prime overrides, migrate this to a circuits.json entry.
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

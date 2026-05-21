pragma circom 2.2.3;

include "circomlib/circuits/poseidon.circom";

// Pure circomlib Poseidon(2) — measures the R1CS cost of ONE arity-2
// Poseidon permutation. This is the step-circuit unit for the D2-c
// flat-IVC decomposition (per research/folding/step_function_slh_dsa_128s.md
// §4.1 D2-c and §6.1).
//
// The Week 1 design doc estimated this at ~213 R1CS by back-of-envelope;
// adversarial review (finding #1) flagged that as off by ~17 %. This bench
// settles the actual measured value, which propagates to D2-c step cost
// and the Section 8 D2-c headline ("~0.91 M R1CS total step work").
//
// Byte packing (PackBytes16ToFe, UnpackFeToBytes16) is deliberately OUTSIDE
// this bench — for the D2-c step, byte↔FE conversion happens at the
// fold-loop boundary (H_msg input and final output), not per step.
template BenchPoseidonReduce2() {
    signal input in[2];
    signal output out;

    component p = Poseidon(2);
    p.inputs[0] <== in[0];
    p.inputs[1] <== in[1];
    out <== p.out;
}

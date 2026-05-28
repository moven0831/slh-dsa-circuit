pragma circom 2.2.3;

include "../hashes_gl.circom";

// SlhHMsg_Gl bench — measures per-call R1CS of the message-digest primitive
// and emits a witness comparable to the Rust port in
// `slh-dsa-neo/crates/slh-poseidon-gl/src/primitives.rs::slh_hmsg`.
//
// Inline `component main` per the gitignored-mains convention deviation
// documented in poseidon_gl_smoke.circom.
template BenchSlhHMsgGl() {
    signal input  r[16];
    signal input  pk_seed[16];
    signal input  pk_root[16];
    signal input  m[1024];
    signal output out[30];

    component h = SlhHMsg();
    for (var b = 0; b < 16;   b++) h.r[b]       <== r[b];
    for (var b = 0; b < 16;   b++) h.pk_seed[b] <== pk_seed[b];
    for (var b = 0; b < 16;   b++) h.pk_root[b] <== pk_root[b];
    for (var b = 0; b < 1024; b++) h.m[b]       <== m[b];
    for (var k = 0; k < 30;   k++) out[k]       <== h.out[k];
}

component main = BenchSlhHMsgGl();

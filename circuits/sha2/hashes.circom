pragma circom 2.2.3;

include "sha256_midstate.circom";   // Sha256BodyBytes, Sha256SeedIv
include "sha256_wrap.circom";       // Sha256Bytes (used by H_msg, no midstate)
include "adrs_encode_sha2.circom";

// FIPS 205 §11.2.2 SLH-DSA-SHA2-128s tweakable-hash primitives.
//
// All of F, H, T_l have the form:
//   <prim>(pk_seed, ADRS, message_concat)
//     = SHA-256(pk_seed || toByte(0, 64-n) || ADRS_c || message_concat)[0..n]
//
// where n=16 and ADRS_c is the 22-byte compressed ADRS form.
//
// **MIDSTATE OPTIMIZATION** is applied: the 48 zero bytes pad pk_seed
// up to 64 bytes — exactly one SHA-256 block. Since pk_seed is fixed
// across all F/H/T_l calls in the verifier, we precompute
// `iv_state = Sha256Compression(default_IV, pk_seed||zeros[48])` once
// at the top of the circuit (Sha256SeedIv) and pass it to every
// F/H/T_l call. Each call then runs Sha256compression on the remaining
// blocks starting from `iv_state` (Sha256BodyBytes).
//
// This saves ~1 SHA-256 block (≈30K constraints) per F/H/T_l call.
//
// SlhF/H/Tk/Tlen take `iv_state[256]` (in `hin` / LSB-first format)
// instead of `pk_seed[16]`. SlhHMsg uses pk_seed directly (no midstate
// here because its prefix is R||pk_seed, not pk_seed||zeros).

// F(iv_state, ADRS, m)  — body = ADRS(22) + m(16) = 38 bytes
// Total message length: 102 bytes (= 1 prefix block + 1 body block).
template SlhF() {
    signal input iv_state[256];
    signal input layer;
    signal input tree_high;
    signal input tree_low;
    signal input type_;
    signal input keypair;
    signal input chain;
    signal input hash;
    signal input m[16];
    signal output out[16];

    component enc = AdrsEncodeSha2();
    enc.layer     <== layer;
    enc.tree_high <== tree_high;
    enc.tree_low  <== tree_low;
    enc.type_     <== type_;
    enc.keypair   <== keypair;
    enc.chain     <== chain;
    enc.hash      <== hash;

    component sha = Sha256BodyBytes(102, 38);
    for (var k = 0; k < 256; k++) sha.iv_state[k] <== iv_state[k];
    for (var k = 0; k < 22; k++) sha.body_bytes[k] <== enc.out_bytes[k];
    for (var k = 0; k < 16; k++) sha.body_bytes[22 + k] <== m[k];
    for (var k = 0; k < 16; k++) out[k] <== sha.out_bytes[k];
}

// H(iv_state, ADRS, m1||m2) — body = 22 + 32 = 54 bytes (still 1 body block).
template SlhH() {
    signal input iv_state[256];
    signal input layer;
    signal input tree_high;
    signal input tree_low;
    signal input type_;
    signal input keypair;
    signal input chain;
    signal input hash;
    signal input m[32];
    signal output out[16];

    component enc = AdrsEncodeSha2();
    enc.layer     <== layer;
    enc.tree_high <== tree_high;
    enc.tree_low  <== tree_low;
    enc.type_     <== type_;
    enc.keypair   <== keypair;
    enc.chain     <== chain;
    enc.hash      <== hash;

    component sha = Sha256BodyBytes(118, 54);
    for (var k = 0; k < 256; k++) sha.iv_state[k] <== iv_state[k];
    for (var k = 0; k < 22; k++) sha.body_bytes[k] <== enc.out_bytes[k];
    for (var k = 0; k < 32; k++) sha.body_bytes[22 + k] <== m[k];
    for (var k = 0; k < 16; k++) out[k] <== sha.out_bytes[k];
}

// T_k(iv_state, ADRS, 14 roots) — body = 22 + 224 = 246 bytes (4 body blocks).
template SlhTk() {
    signal input iv_state[256];
    signal input layer;
    signal input tree_high;
    signal input tree_low;
    signal input type_;
    signal input keypair;
    signal input chain;
    signal input hash;
    signal input m[224];
    signal output out[16];

    component enc = AdrsEncodeSha2();
    enc.layer     <== layer;
    enc.tree_high <== tree_high;
    enc.tree_low  <== tree_low;
    enc.type_     <== type_;
    enc.keypair   <== keypair;
    enc.chain     <== chain;
    enc.hash      <== hash;

    component sha = Sha256BodyBytes(310, 246);
    for (var k = 0; k < 256; k++) sha.iv_state[k] <== iv_state[k];
    for (var k = 0; k < 22; k++) sha.body_bytes[k] <== enc.out_bytes[k];
    for (var k = 0; k < 224; k++) sha.body_bytes[22 + k] <== m[k];
    for (var k = 0; k < 16; k++) out[k] <== sha.out_bytes[k];
}

// T_len(iv_state, ADRS, 35 endpoints) — body = 22 + 560 = 582 bytes (10 body blocks).
template SlhTlen() {
    signal input iv_state[256];
    signal input layer;
    signal input tree_high;
    signal input tree_low;
    signal input type_;
    signal input keypair;
    signal input chain;
    signal input hash;
    signal input m[560];
    signal output out[16];

    component enc = AdrsEncodeSha2();
    enc.layer     <== layer;
    enc.tree_high <== tree_high;
    enc.tree_low  <== tree_low;
    enc.type_     <== type_;
    enc.keypair   <== keypair;
    enc.chain     <== chain;
    enc.hash      <== hash;

    component sha = Sha256BodyBytes(646, 582);
    for (var k = 0; k < 256; k++) sha.iv_state[k] <== iv_state[k];
    for (var k = 0; k < 22; k++) sha.body_bytes[k] <== enc.out_bytes[k];
    for (var k = 0; k < 560; k++) sha.body_bytes[22 + k] <== m[k];
    for (var k = 0; k < 16; k++) out[k] <== sha.out_bytes[k];
}

// HMsg(R, pk_seed, pk_root, M) — uses pk_seed directly (no midstate).
//   = MGF1-SHA-256(R || pk_seed || SHA-256(R || pk_seed || pk_root || M), 30)
template SlhHMsg() {
    signal input r[16];
    signal input pk_seed[16];
    signal input pk_root[16];
    signal input m[1024];
    signal output out[30];

    component inner = Sha256Bytes(1072);
    for (var k = 0; k < 16; k++)   inner.in_bytes[k] <== r[k];
    for (var k = 0; k < 16; k++)   inner.in_bytes[16 + k] <== pk_seed[k];
    for (var k = 0; k < 16; k++)   inner.in_bytes[32 + k] <== pk_root[k];
    for (var k = 0; k < 1024; k++) inner.in_bytes[48 + k] <== m[k];

    component outer = Sha256Bytes(68);
    for (var k = 0; k < 16; k++) outer.in_bytes[k] <== r[k];
    for (var k = 0; k < 16; k++) outer.in_bytes[16 + k] <== pk_seed[k];
    for (var k = 0; k < 32; k++) outer.in_bytes[32 + k] <== inner.out_bytes[k];
    for (var k = 0; k < 4; k++)  outer.in_bytes[64 + k] <== 0;

    for (var k = 0; k < 30; k++) out[k] <== outer.out_bytes[k];
}

pragma circom 2.2.3;

include "adrs_encode_shake.circom";
include "keccak/sha3_bytes.circom";   // bkomuves SHAKE256_bytes

// SLH-DSA-SHAKE-128s tweakable-hash primitives (FIPS 205 §11.1).
// All primitives use SHAKE-256 with the 32-byte full ADRS form.
//
// F      = SHAKE256(pk_seed || ADRS_32 || M, 16)         input: 64 B
// H      = SHAKE256(pk_seed || ADRS_32 || M1 || M2, 16)  input: 80 B
// T_k    = SHAKE256(pk_seed || ADRS_32 || roots, 16)     input: 16+32+14*16 = 272 B
// T_len  = SHAKE256(pk_seed || ADRS_32 || endpoints, 16) input: 16+32+35*16 = 608 B
// HMsg   = SHAKE256(R || PK.seed || PK.root || M, 30)    input: 16+16+16+1024 = 1072 B

template SlhF() {
    signal input pk_seed[16];
    signal input layer;
    signal input tree_high;
    signal input tree_low;
    signal input type_;
    signal input keypair;
    signal input chain;
    signal input hash;
    signal input m[16];
    signal output out[16];

    component enc = AdrsEncodeShake();
    enc.layer     <== layer;
    enc.tree_high <== tree_high;
    enc.tree_low  <== tree_low;
    enc.type_     <== type_;
    enc.keypair   <== keypair;
    enc.chain     <== chain;
    enc.hash      <== hash;

    component shake = SHAKE256_bytes(64, 16);
    for (var k = 0; k < 16; k++) shake.inp_bytes[k] <== pk_seed[k];
    for (var k = 0; k < 32; k++) shake.inp_bytes[16 + k] <== enc.out_bytes[k];
    for (var k = 0; k < 16; k++) shake.inp_bytes[48 + k] <== m[k];
    for (var k = 0; k < 16; k++) out[k] <== shake.out_bytes[k];
}

template SlhH() {
    signal input pk_seed[16];
    signal input layer;
    signal input tree_high;
    signal input tree_low;
    signal input type_;
    signal input keypair;
    signal input chain;
    signal input hash;
    signal input m[32];
    signal output out[16];

    component enc = AdrsEncodeShake();
    enc.layer     <== layer;
    enc.tree_high <== tree_high;
    enc.tree_low  <== tree_low;
    enc.type_     <== type_;
    enc.keypair   <== keypair;
    enc.chain     <== chain;
    enc.hash      <== hash;

    component shake = SHAKE256_bytes(80, 16);
    for (var k = 0; k < 16; k++) shake.inp_bytes[k] <== pk_seed[k];
    for (var k = 0; k < 32; k++) shake.inp_bytes[16 + k] <== enc.out_bytes[k];
    for (var k = 0; k < 32; k++) shake.inp_bytes[48 + k] <== m[k];
    for (var k = 0; k < 16; k++) out[k] <== shake.out_bytes[k];
}

template SlhTk() {
    signal input pk_seed[16];
    signal input layer;
    signal input tree_high;
    signal input tree_low;
    signal input type_;
    signal input keypair;
    signal input chain;
    signal input hash;
    signal input m[224];
    signal output out[16];

    component enc = AdrsEncodeShake();
    enc.layer     <== layer;
    enc.tree_high <== tree_high;
    enc.tree_low  <== tree_low;
    enc.type_     <== type_;
    enc.keypair   <== keypair;
    enc.chain     <== chain;
    enc.hash      <== hash;

    component shake = SHAKE256_bytes(272, 16);
    for (var k = 0; k < 16; k++) shake.inp_bytes[k] <== pk_seed[k];
    for (var k = 0; k < 32; k++) shake.inp_bytes[16 + k] <== enc.out_bytes[k];
    for (var k = 0; k < 224; k++) shake.inp_bytes[48 + k] <== m[k];
    for (var k = 0; k < 16; k++) out[k] <== shake.out_bytes[k];
}

template SlhTlen() {
    signal input pk_seed[16];
    signal input layer;
    signal input tree_high;
    signal input tree_low;
    signal input type_;
    signal input keypair;
    signal input chain;
    signal input hash;
    signal input m[560];
    signal output out[16];

    component enc = AdrsEncodeShake();
    enc.layer     <== layer;
    enc.tree_high <== tree_high;
    enc.tree_low  <== tree_low;
    enc.type_     <== type_;
    enc.keypair   <== keypair;
    enc.chain     <== chain;
    enc.hash      <== hash;

    component shake = SHAKE256_bytes(608, 16);
    for (var k = 0; k < 16; k++) shake.inp_bytes[k] <== pk_seed[k];
    for (var k = 0; k < 32; k++) shake.inp_bytes[16 + k] <== enc.out_bytes[k];
    for (var k = 0; k < 560; k++) shake.inp_bytes[48 + k] <== m[k];
    for (var k = 0; k < 16; k++) out[k] <== shake.out_bytes[k];
}

template SlhHMsg() {
    signal input r[16];
    signal input pk_seed[16];
    signal input pk_root[16];
    signal input m[1024];
    signal output out[30];

    component shake = SHAKE256_bytes(1072, 30);
    for (var k = 0; k < 16; k++)   shake.inp_bytes[k] <== r[k];
    for (var k = 0; k < 16; k++)   shake.inp_bytes[16 + k] <== pk_seed[k];
    for (var k = 0; k < 16; k++)   shake.inp_bytes[32 + k] <== pk_root[k];
    for (var k = 0; k < 1024; k++) shake.inp_bytes[48 + k] <== m[k];
    for (var k = 0; k < 30; k++) out[k] <== shake.out_bytes[k];
}

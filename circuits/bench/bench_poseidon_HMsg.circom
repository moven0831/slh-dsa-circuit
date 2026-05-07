pragma circom 2.2.3;

include "../poseidon/hashes.circom";

template BenchPoseidonHMsg() {
    signal input r[16];
    signal input pk_seed[16];
    signal input pk_root[16];
    signal input m[1024];
    signal output out[30];

    component h = SlhHMsg();
    for (var k = 0; k < 16; k++)   h.r[k] <== r[k];
    for (var k = 0; k < 16; k++)   h.pk_seed[k] <== pk_seed[k];
    for (var k = 0; k < 16; k++)   h.pk_root[k] <== pk_root[k];
    for (var k = 0; k < 1024; k++) h.m[k] <== m[k];
    for (var k = 0; k < 30; k++)   out[k] <== h.out[k];
}

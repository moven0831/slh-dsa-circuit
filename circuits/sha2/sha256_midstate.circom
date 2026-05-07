pragma circom 2.2.3;

include "circomlib/circuits/sha256/sha256compression.circom";   // Sha256compression
include "circomlib/circuits/sha256/constants.circom";           // H(x), K(x)
include "circomlib/circuits/bitify.circom";                     // Num2Bits
include "../common/bytes.circom";                               // BitsBEToBytes

// MIDSTATE OPTIMIZATION for SLH-DSA-SHA2 primitives.
// FIPS 205 §11.2.2 specifies: F/H/T_l = SHA-256(pk_seed || zeros[48] || ADRS_22 || m)[0..n].
// The first 64 bytes (pk_seed || zeros[48]) form exactly one SHA-256 block,
// and pk_seed is fixed across ALL F/H/T_l calls in the verifier. We precompute
// `iv_state = Sha256Compression(default_IV, pk_seed||zeros[48])` once at the
// top of the circuit, then each F/H/T_l call runs Sha256compression on the
// remaining blocks starting from `iv_state` instead of the default IV.
//
// This saves ~1 block (≈30K constraints) per F/H/T_l call. For 3,689 F + 231
// H + 1 T_k + 7 T_len ≈ 3,928 calls: ≈117M constraint savings.

// Sha256SeedIv — compute iv_state from pk_seed by running one
// Sha256compression on the block (pk_seed || zeros[48]).
// Output is in `hin` (LSB-first per word) format.
template Sha256SeedIv() {
    signal input pk_seed[16];
    signal output iv_state[256];

    component compress = Sha256compression();
    // Default IV (H(0..7)) — bits in LSB-first format.
    component h0 = H(0);
    component h1 = H(1);
    component h2 = H(2);
    component h3 = H(3);
    component h4 = H(4);
    component h5 = H(5);
    component h6 = H(6);
    component h7 = H(7);
    for (var k = 0; k < 32; k++) {
        compress.hin[0  + k] <== h0.out[k];
        compress.hin[32 + k] <== h1.out[k];
        compress.hin[64 + k] <== h2.out[k];
        compress.hin[96 + k] <== h3.out[k];
        compress.hin[128 + k] <== h4.out[k];
        compress.hin[160 + k] <== h5.out[k];
        compress.hin[192 + k] <== h6.out[k];
        compress.hin[224 + k] <== h7.out[k];
    }

    // Block contents: pk_seed (16 bytes) || zeros (48 bytes) = 64 bytes = 512 bits.
    // BE bit ordering per byte (matches circomlib Sha256 input convention).
    component pk_bits[16];
    for (var i = 0; i < 16; i++) {
        pk_bits[i] = Num2Bits(8);
        pk_bits[i].in <== pk_seed[i];
    }
    for (var i = 0; i < 16; i++) {
        for (var b = 0; b < 8; b++) {
            // BE: bit 0 of inp's byte i = MSB of pk_seed[i]
            compress.inp[i * 8 + b] <== pk_bits[i].out[7 - b];
        }
    }
    for (var k = 16 * 8; k < 512; k++) {
        compress.inp[k] <== 0;
    }

    // Reverse bits within each 32-bit word (out is MSB-first within
    // each word; hin expects LSB-first). This matches the chain
    // pattern in circomlib's Sha256.
    for (var w = 0; w < 8; w++) {
        for (var k = 0; k < 32; k++) {
            iv_state[w * 32 + k] <== compress.out[w * 32 + (31 - k)];
        }
    }
}

// Sha256BodyBytes(total_byte_len, body_byte_len) — run SHA-256 starting
// from `iv_state` over `body_bytes`, with Merkle-Damgård padding using
// `total_byte_len` (= prefix_byte_len + body_byte_len) for length encoding.
//
// `iv_state` is in `hin` format. The output bytes are in standard
// big-endian per byte ordering.
template Sha256BodyBytes(total_byte_len, body_byte_len) {
    signal input iv_state[256];
    signal input body_bytes[body_byte_len];
    signal output out_bytes[32];

    var total_bits = total_byte_len * 8;
    // circomlib's nBlocks formula: ((total_bits + 64) \ 512) + 1
    var n_blocks_total = ((total_bits + 64) \ 512) + 1;
    // Prefix is exactly 1 SHA-256 block (64 bytes for our SLH-DSA layout).
    var n_blocks_body = n_blocks_total - 1;
    var n_bits_body = n_blocks_body * 512;
    var body_data_bits = body_byte_len * 8;

    // Decompose body bytes to BE bits.
    component byte_bits[body_byte_len];
    for (var i = 0; i < body_byte_len; i++) {
        byte_bits[i] = Num2Bits(8);
        byte_bits[i].in <== body_bytes[i];
    }

    signal padded_bits[n_bits_body];
    for (var i = 0; i < body_byte_len; i++) {
        for (var b = 0; b < 8; b++) {
            padded_bits[i * 8 + b] <== byte_bits[i].out[7 - b];
        }
    }
    // Append the padding bit '1' at position body_data_bits.
    padded_bits[body_data_bits] <== 1;
    // Zero pad up to the last 64 bits.
    for (var k = body_data_bits + 1; k < n_bits_body - 64; k++) {
        padded_bits[k] <== 0;
    }
    // Last 64 bits: 64-bit big-endian length of TOTAL message bits.
    // Following circomlib convention: position (n_bits_body - 1 - k) holds bit k of length (LE-indexed).
    for (var k = 0; k < 64; k++) {
        padded_bits[n_bits_body - 1 - k] <== (total_bits >> k) & 1;
    }

    // Run sha256compression on each body block, chained.
    component compress[n_blocks_body];
    for (var i = 0; i < n_blocks_body; i++) {
        compress[i] = Sha256compression();
        if (i == 0) {
            for (var k = 0; k < 256; k++) compress[i].hin[k] <== iv_state[k];
        } else {
            for (var w = 0; w < 8; w++) {
                for (var k = 0; k < 32; k++) {
                    compress[i].hin[w * 32 + k] <== compress[i - 1].out[w * 32 + (31 - k)];
                }
            }
        }
        for (var k = 0; k < 512; k++) {
            compress[i].inp[k] <== padded_bits[i * 512 + k];
        }
    }

    // Output: convert bits to bytes (MSB-first per byte).
    component to_bytes = BitsBEToBytes(32);
    for (var k = 0; k < 256; k++) to_bytes.bits[k] <== compress[n_blocks_body - 1].out[k];
    for (var k = 0; k < 32; k++) out_bytes[k] <== to_bytes.bytes[k];
}

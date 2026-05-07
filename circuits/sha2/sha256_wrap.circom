pragma circom 2.2.3;

include "circomlib/circuits/sha256/sha256.circom";   // Sha256(nBits)
include "../common/bytes.circom";                    // BytesToBitsBE, BitsBEToBytes

// Hash an array of `nBytes` bytes with SHA-256, returning a 32-byte digest.
// SHA-256 processes bytes MSB-first per byte, so we use BE bit ordering.
// Input bytes are range-checked to [0, 255] via the bit decomposition.
template Sha256Bytes(nBytes) {
    signal input in_bytes[nBytes];
    signal output out_bytes[32];

    component to_bits = BytesToBitsBE(nBytes);
    for (var k = 0; k < nBytes; k++) {
        to_bits.bytes[k] <== in_bytes[k];
    }

    component sha = Sha256(8 * nBytes);
    for (var i = 0; i < 8 * nBytes; i++) {
        sha.in[i] <== to_bits.bits[i];
    }

    component to_bytes = BitsBEToBytes(32);
    for (var i = 0; i < 256; i++) {
        to_bytes.bits[i] <== sha.out[i];
    }
    for (var k = 0; k < 32; k++) {
        out_bytes[k] <== to_bytes.bytes[k];
    }
}

// Convenience: SHA-256 truncated to the first n bytes.
// Used for F, H, T_l in SLH-DSA-SHA2 (n=16 for 128s).
template Sha256BytesTruncated(nBytes, outBytes) {
    signal input in_bytes[nBytes];
    signal output out_bytes[outBytes];

    component sha = Sha256Bytes(nBytes);
    for (var k = 0; k < nBytes; k++) {
        sha.in_bytes[k] <== in_bytes[k];
    }
    for (var k = 0; k < outBytes; k++) {
        out_bytes[k] <== sha.out_bytes[k];
    }
}

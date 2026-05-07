pragma circom 2.2.3;

include "circomlib/circuits/bitify.circom";   // Num2Bits

// Encode a 7-tuple ADRS into the 22-byte compressed form used by
// SLH-DSA-SHA2 (FIPS 205 §11.2.2).
//
// Per integritychain/fips205 helpers.rs::Adrs::to_22_bytes (which
// matches FIPS 205 verbatim):
//
//   ret[0]      = layer       (low byte of u32 BE)
//   ret[1..5]   = tree_high   (4 bytes, BE)         -- always zero for 128s
//   ret[5..9]   = tree_low    (4 bytes, BE)
//   ret[9]      = type        (low byte of u32 BE)
//   ret[10..14] = key_pair    (4 bytes, BE)
//   ret[14..18] = chain       (4 bytes, BE)
//   ret[18..22] = hash        (4 bytes, BE)
//
// The "low byte of u32 BE" is just the low 8 bits — it's a u8 we
// padded into a u32 slot. We range-check layer and type to <= 0xFF.

// Decompose `v` into 4 BE bytes (most significant first).
// Range-check: v < 2^32.
template U32ToBytesBE() {
    signal input v;
    signal output bytes[4];
    component n2b = Num2Bits(32);
    n2b.in <== v;
    // Reassemble into 4 bytes, MSB-first.
    for (var b = 0; b < 4; b++) {
        var sum = 0;
        for (var i = 0; i < 8; i++) {
            // Bit (3-b)*8 + i is the i-th bit of byte b (MSB-first).
            // n2b.out is little-endian, so index = (3-b)*8 + i in
            // n2b's notation = bit-position-from-LSB.
            sum += n2b.out[(3 - b) * 8 + i] * (1 << i);
        }
        bytes[b] <== sum;
    }
}

// Decompose v into 1 byte. Range-check: v < 2^8.
template U8ToByte() {
    signal input v;
    signal output byte_;
    component n2b = Num2Bits(8);
    n2b.in <== v;
    var sum = 0;
    for (var i = 0; i < 8; i++) {
        sum += n2b.out[i] * (1 << i);
    }
    byte_ <== sum;
}

// AdrsEncodeSha2: 7 ADRS sub-fields → 22 bytes (FIPS 205 §11.2.2).
template AdrsEncodeSha2() {
    signal input layer;
    signal input tree_high;
    signal input tree_low;
    signal input type_;
    signal input keypair;
    signal input chain;
    signal input hash;
    signal output out_bytes[22];

    // For 128s, tree_high must be zero. Enforce here as a soft
    // belt-and-braces check; the common AdrsRangeCheck also enforces.
    tree_high === 0;

    component layer_b = U8ToByte();      layer_b.v <== layer;
    component type_b  = U8ToByte();      type_b.v  <== type_;
    component th_b    = U32ToBytesBE();  th_b.v    <== tree_high;
    component tl_b    = U32ToBytesBE();  tl_b.v    <== tree_low;
    component kp_b    = U32ToBytesBE();  kp_b.v    <== keypair;
    component ch_b    = U32ToBytesBE();  ch_b.v    <== chain;
    component hs_b    = U32ToBytesBE();  hs_b.v    <== hash;

    out_bytes[0] <== layer_b.byte_;
    for (var i = 0; i < 4; i++) {
        out_bytes[1 + i] <== th_b.bytes[i];
        out_bytes[5 + i] <== tl_b.bytes[i];
    }
    out_bytes[9] <== type_b.byte_;
    for (var i = 0; i < 4; i++) {
        out_bytes[10 + i] <== kp_b.bytes[i];
        out_bytes[14 + i] <== ch_b.bytes[i];
        out_bytes[18 + i] <== hs_b.bytes[i];
    }
}

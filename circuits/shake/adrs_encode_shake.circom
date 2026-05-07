pragma circom 2.2.3;

include "circomlib/circuits/bitify.circom";

// AdrsEncodeShake — encode 7-tuple ADRS into the 32-byte full form
// used by SLH-DSA-SHAKE (FIPS 205 §11.1).
//
// Per integritychain/fips205 helpers.rs::Adrs::to_32_bytes:
//   ret[0..4]   = layer       (4 bytes BE)
//   ret[4..8]   = tree_high   (4 bytes BE)   -- f1 in fips205, but we treat as tree_high
//   ret[8..12]  = tree_low    (4 bytes BE)
//   ret[12..16] = type        (4 bytes BE)
//
// Wait — fips205 has 8 fields f0..f7 each 4 bytes. f0=layer, f1=zero,
// f2||f3 = 8-byte tree, f4=type, f5=keypair, f6=chain/tree_height,
// f7=hash/tree_index.
//
// Map our 7-tuple AdrsFields to 32 bytes:
//   ret[0..4]   = layer (BE)
//   ret[4..8]   = 0x00000000 (the f1 padding word — always zero)
//   ret[8..12]  = tree_high (BE)
//   ret[12..16] = tree_low (BE)
//   ret[16..20] = type_ (BE)
//   ret[20..24] = keypair (BE)
//   ret[24..28] = chain (BE)
//   ret[28..32] = hash (BE)

template U32ToBytesBE_Shake() {
    signal input v;
    signal output bytes[4];
    component n2b = Num2Bits(32);
    n2b.in <== v;
    for (var b = 0; b < 4; b++) {
        var sum = 0;
        for (var i = 0; i < 8; i++) {
            sum += n2b.out[(3 - b) * 8 + i] * (1 << i);
        }
        bytes[b] <== sum;
    }
}

template AdrsEncodeShake() {
    signal input layer;
    signal input tree_high;
    signal input tree_low;
    signal input type_;
    signal input keypair;
    signal input chain;
    signal input hash;
    signal output out_bytes[32];

    component layer_b = U32ToBytesBE_Shake(); layer_b.v <== layer;
    component th_b    = U32ToBytesBE_Shake(); th_b.v    <== tree_high;
    component tl_b    = U32ToBytesBE_Shake(); tl_b.v    <== tree_low;
    component type_b  = U32ToBytesBE_Shake(); type_b.v  <== type_;
    component kp_b    = U32ToBytesBE_Shake(); kp_b.v    <== keypair;
    component ch_b    = U32ToBytesBE_Shake(); ch_b.v    <== chain;
    component hs_b    = U32ToBytesBE_Shake(); hs_b.v    <== hash;

    for (var i = 0; i < 4; i++) {
        out_bytes[i]      <== layer_b.bytes[i];
        out_bytes[4 + i]  <== 0;                   // f1 padding (zero u32)
        out_bytes[8 + i]  <== th_b.bytes[i];
        out_bytes[12 + i] <== tl_b.bytes[i];
        out_bytes[16 + i] <== type_b.bytes[i];
        out_bytes[20 + i] <== kp_b.bytes[i];
        out_bytes[24 + i] <== ch_b.bytes[i];
        out_bytes[28 + i] <== hs_b.bytes[i];
    }
}

// SLH-DSA-128s per-primitive bench oracle.
//
// Computes FIPS 205 §11.1 / §11.2.2 reference outputs for the
// SHA-2 and SHAKE families, and emits circom witness JSONs for the
// per-primitive bench mains. A separate test wrapper circuit
// (circuits/test/test_<family>_<prim>.circom) asserts that the
// bench's output matches the Rust-computed expected output —
// `circomkit witness test_<family>_<prim> input.json` succeeds iff
// the bench is correct.
//
// Usage: `cargo run --release -- <family> <prim>`
//   family ∈ {sha2, shake}
//   prim   ∈ {F, H, Tk, Tlen, HMsg}

use sha2::compress256;
use sha2::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;
use std::env;
use std::fs;
use std::path::PathBuf;

const PK_SEED: [u8; 16] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
];
const PK_ROOT: [u8; 16] = [
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
];
const R_BYTES: [u8; 16] = [0x42; 16];

// Deterministic ADRS for benches (FORS_TREE leaf at idx 7).
const ADRS_LAYER: u32 = 0;
const ADRS_TREE_HIGH: u32 = 0;
const ADRS_TREE_LOW: u32 = 42;
const ADRS_TYPE: u32 = 0;       // WOTS_HASH
const ADRS_KEYPAIR: u32 = 7;
const ADRS_CHAIN: u32 = 3;
const ADRS_HASH: u32 = 5;

// SHA-256 default IV (H(0..7) constants).
const DEFAULT_IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

fn sha256_compress_block(state: &mut [u32; 8], block: &[u8; 64]) {
    compress256(state, &[(*block).into()]);
}

/// Compute the SHA-2 family iv_state by compressing pk_seed||zeros[48].
fn sha2_seed_iv(pk_seed: &[u8; 16]) -> [u32; 8] {
    let mut state = DEFAULT_IV;
    let mut block = [0u8; 64];
    block[..16].copy_from_slice(pk_seed);
    sha256_compress_block(&mut state, &block);
    state
}

/// Convert iv_state (as 8 u32 words) to circom's "hin" bit format
/// (LSB-first within each 32-bit word, 256 bits total).
fn iv_state_to_bits(state: &[u32; 8]) -> Vec<u32> {
    let mut bits = Vec::with_capacity(256);
    for w in 0..8 {
        for k in 0..32 {
            bits.push(((state[w] >> k) & 1) as u32);
        }
    }
    bits
}

/// Encode an ADRS as the 22-byte compressed form (FIPS 205 §11.2.2).
fn adrs_22_bytes(
    layer: u32, tree_high: u32, tree_low: u32, type_: u32,
    keypair: u32, chain: u32, hash: u32,
) -> [u8; 22] {
    let mut out = [0u8; 22];
    out[0] = layer as u8;
    out[1..5].copy_from_slice(&tree_high.to_be_bytes());
    out[5..9].copy_from_slice(&tree_low.to_be_bytes());
    out[9] = type_ as u8;
    out[10..14].copy_from_slice(&keypair.to_be_bytes());
    out[14..18].copy_from_slice(&chain.to_be_bytes());
    out[18..22].copy_from_slice(&hash.to_be_bytes());
    out
}

/// Encode an ADRS as the 32-byte full form (FIPS 205 §11.1).
fn adrs_32_bytes(
    layer: u32, tree_high: u32, tree_low: u32, type_: u32,
    keypair: u32, chain: u32, hash: u32,
) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[0..4].copy_from_slice(&layer.to_be_bytes());
    // bytes [4..8] are zero (f1 padding word)
    out[8..12].copy_from_slice(&tree_high.to_be_bytes());
    out[12..16].copy_from_slice(&tree_low.to_be_bytes());
    out[16..20].copy_from_slice(&type_.to_be_bytes());
    out[20..24].copy_from_slice(&keypair.to_be_bytes());
    out[24..28].copy_from_slice(&chain.to_be_bytes());
    out[28..32].copy_from_slice(&hash.to_be_bytes());
    out
}

/// Pad a message body for Merkle-Damgård SHA-256.
/// `total_bits` is the FULL message length (prefix + body) in bits.
fn pad_body(body: &[u8], total_bits: u64) -> Vec<u8> {
    let body_data_bits = (body.len() * 8) as u64;
    let n_blocks_total = ((total_bits + 64) / 512) + 1;
    let n_blocks_body = n_blocks_total - 1;
    let n_bytes_body = n_blocks_body * 64;
    let mut padded = vec![0u8; n_bytes_body as usize];
    padded[..body.len()].copy_from_slice(body);
    padded[body.len()] = 0x80;
    let len_offset = (n_bytes_body as usize) - 8;
    padded[len_offset..].copy_from_slice(&total_bits.to_be_bytes());
    padded
}

/// Compute SHA-256 starting from a given IV over `body`, with M-D padding.
fn sha256_from_iv(iv: [u32; 8], body: &[u8], total_bits: u64) -> [u8; 32] {
    let padded = pad_body(body, total_bits);
    let mut state = iv;
    for chunk in padded.chunks_exact(64) {
        let block: [u8; 64] = chunk.try_into().unwrap();
        sha256_compress_block(&mut state, &block);
    }
    let mut out = [0u8; 32];
    for (i, w) in state.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
    }
    out
}

/// SHA-256 over a full message (default IV + padding).
fn sha256_full(msg: &[u8]) -> [u8; 32] {
    let total_bits = (msg.len() as u64) * 8;
    let mut full = msg.to_vec();
    full.push(0x80);
    while (full.len() % 64) != 56 {
        full.push(0);
    }
    full.extend_from_slice(&total_bits.to_be_bytes());
    let mut state = DEFAULT_IV;
    for chunk in full.chunks_exact(64) {
        let block: [u8; 64] = chunk.try_into().unwrap();
        sha256_compress_block(&mut state, &block);
    }
    let mut out = [0u8; 32];
    for (i, w) in state.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
    }
    out
}

// ---------- SHA-2 family primitives ----------

fn sha2_f(iv_state: [u32; 8], adrs: [u8; 22], m: &[u8; 16]) -> [u8; 16] {
    let mut body = Vec::with_capacity(38);
    body.extend_from_slice(&adrs);
    body.extend_from_slice(m);
    let total_bits = (16 + 48 + 22 + 16) as u64 * 8; // 102 bytes
    let digest = sha256_from_iv(iv_state, &body, total_bits);
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

fn sha2_h(iv_state: [u32; 8], adrs: [u8; 22], m: &[u8; 32]) -> [u8; 16] {
    let mut body = Vec::with_capacity(54);
    body.extend_from_slice(&adrs);
    body.extend_from_slice(m);
    let total_bits = 118u64 * 8;
    let digest = sha256_from_iv(iv_state, &body, total_bits);
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

fn sha2_tk(iv_state: [u32; 8], adrs: [u8; 22], m: &[u8]) -> [u8; 16] {
    assert_eq!(m.len(), 224);
    let mut body = Vec::with_capacity(246);
    body.extend_from_slice(&adrs);
    body.extend_from_slice(m);
    let total_bits = 310u64 * 8;
    let digest = sha256_from_iv(iv_state, &body, total_bits);
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

fn sha2_tlen(iv_state: [u32; 8], adrs: [u8; 22], m: &[u8]) -> [u8; 16] {
    assert_eq!(m.len(), 560);
    let mut body = Vec::with_capacity(582);
    body.extend_from_slice(&adrs);
    body.extend_from_slice(m);
    let total_bits = 646u64 * 8;
    let digest = sha256_from_iv(iv_state, &body, total_bits);
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

fn sha2_hmsg(r: &[u8; 16], pk_seed: &[u8; 16], pk_root: &[u8; 16], m: &[u8]) -> [u8; 30] {
    // inner = SHA-256(R || pk_seed || pk_root || M)
    let mut inner_input = Vec::with_capacity(48 + m.len());
    inner_input.extend_from_slice(r);
    inner_input.extend_from_slice(pk_seed);
    inner_input.extend_from_slice(pk_root);
    inner_input.extend_from_slice(m);
    let inner = sha256_full(&inner_input);
    // outer = SHA-256(R || pk_seed || inner || ctr_be32(0))
    let mut outer_input = Vec::with_capacity(68);
    outer_input.extend_from_slice(r);
    outer_input.extend_from_slice(pk_seed);
    outer_input.extend_from_slice(&inner);
    outer_input.extend_from_slice(&0u32.to_be_bytes());
    let outer = sha256_full(&outer_input);
    let mut out = [0u8; 30];
    out.copy_from_slice(&outer[..30]);
    out
}

// ---------- SHAKE family primitives ----------

fn shake_xof(input: &[&[u8]], out_len: usize) -> Vec<u8> {
    let mut hasher = Shake256::default();
    for piece in input {
        hasher.update(piece);
    }
    let mut reader = hasher.finalize_xof();
    let mut out = vec![0u8; out_len];
    reader.read(&mut out);
    out
}

fn shake_f(pk_seed: &[u8; 16], adrs: &[u8; 32], m: &[u8; 16]) -> [u8; 16] {
    let v = shake_xof(&[pk_seed, adrs, m], 16);
    let mut out = [0u8; 16]; out.copy_from_slice(&v); out
}

fn shake_h(pk_seed: &[u8; 16], adrs: &[u8; 32], m: &[u8; 32]) -> [u8; 16] {
    let v = shake_xof(&[pk_seed, adrs, m], 16);
    let mut out = [0u8; 16]; out.copy_from_slice(&v); out
}

fn shake_tk(pk_seed: &[u8; 16], adrs: &[u8; 32], m: &[u8]) -> [u8; 16] {
    assert_eq!(m.len(), 224);
    let v = shake_xof(&[pk_seed, adrs, m], 16);
    let mut out = [0u8; 16]; out.copy_from_slice(&v); out
}

fn shake_tlen(pk_seed: &[u8; 16], adrs: &[u8; 32], m: &[u8]) -> [u8; 16] {
    assert_eq!(m.len(), 560);
    let v = shake_xof(&[pk_seed, adrs, m], 16);
    let mut out = [0u8; 16]; out.copy_from_slice(&v); out
}

fn shake_hmsg(r: &[u8; 16], pk_seed: &[u8; 16], pk_root: &[u8; 16], m: &[u8]) -> [u8; 30] {
    let v = shake_xof(&[r, pk_seed, pk_root, m], 30);
    let mut out = [0u8; 30]; out.copy_from_slice(&v); out
}

// ---------- circom witness JSON emission ----------

fn json_bytes(b: &[u8]) -> serde_json::Value {
    serde_json::Value::Array(
        b.iter().map(|x| serde_json::Value::String(x.to_string())).collect()
    )
}

fn json_bits(bits: &[u32]) -> serde_json::Value {
    serde_json::Value::Array(
        bits.iter().map(|x| serde_json::Value::String(x.to_string())).collect()
    )
}

fn json_num<N: ToString>(n: N) -> serde_json::Value {
    serde_json::Value::String(n.to_string())
}

fn write_input(name: &str, fields: serde_json::Map<String, serde_json::Value>) -> PathBuf {
    let path = PathBuf::from(format!("kat/inputs/{}.json", name));
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let v = serde_json::Value::Object(fields);
    fs::write(&path, serde_json::to_string_pretty(&v).unwrap()).unwrap();
    println!("Wrote {}", path.display());
    path
}

fn build_test_message(prim: &str) -> Vec<u8> {
    // Deterministic byte pattern depending on primitive size requirements.
    let len = match prim {
        "F" => 16,
        "H" => 32,
        "Tk" => 224,
        "Tlen" => 560,
        "HMsg" => 1024,
        _ => panic!("unknown prim {prim}"),
    };
    (0..len).map(|i| (i as u8).wrapping_mul(0x9d).wrapping_add(0x4f)).collect()
}

fn emit_sha2(prim: &str) -> serde_json::Map<String, serde_json::Value> {
    let iv_state = sha2_seed_iv(&PK_SEED);
    let iv_bits = iv_state_to_bits(&iv_state);
    let adrs = adrs_22_bytes(
        ADRS_LAYER, ADRS_TREE_HIGH, ADRS_TREE_LOW, ADRS_TYPE,
        ADRS_KEYPAIR, ADRS_CHAIN, ADRS_HASH,
    );
    let m = build_test_message(prim);

    let (out_bytes, _expected_len) = match prim {
        "F" => {
            let mut m16 = [0u8; 16];
            m16.copy_from_slice(&m);
            (sha2_f(iv_state, adrs, &m16).to_vec(), 16)
        }
        "H" => {
            let mut m32 = [0u8; 32];
            m32.copy_from_slice(&m);
            (sha2_h(iv_state, adrs, &m32).to_vec(), 16)
        }
        "Tk"   => (sha2_tk(iv_state, adrs, &m).to_vec(), 16),
        "Tlen" => (sha2_tlen(iv_state, adrs, &m).to_vec(), 16),
        "HMsg" => (sha2_hmsg(&R_BYTES, &PK_SEED, &PK_ROOT, &m).to_vec(), 30),
        _ => panic!("unknown prim {prim}"),
    };

    let mut fields = serde_json::Map::new();
    if prim == "HMsg" {
        fields.insert("r".into(), json_bytes(&R_BYTES));
        fields.insert("pk_seed".into(), json_bytes(&PK_SEED));
        fields.insert("pk_root".into(), json_bytes(&PK_ROOT));
        fields.insert("m".into(), json_bytes(&m));
    } else {
        fields.insert("iv_state".into(), json_bits(&iv_bits));
        fields.insert("layer".into(),     json_num(ADRS_LAYER));
        fields.insert("tree_high".into(), json_num(ADRS_TREE_HIGH));
        fields.insert("tree_low".into(),  json_num(ADRS_TREE_LOW));
        fields.insert("type_".into(),     json_num(ADRS_TYPE));
        fields.insert("keypair".into(),   json_num(ADRS_KEYPAIR));
        fields.insert("chain".into(),     json_num(ADRS_CHAIN));
        fields.insert("hash".into(),      json_num(ADRS_HASH));
        fields.insert("m".into(),         json_bytes(&m));
    }
    fields.insert("expected_out".into(), json_bytes(&out_bytes));

    println!("[sha2/{}] expected_out = {}", prim, hex::encode(&out_bytes));
    fields
}

fn emit_shake(prim: &str) -> serde_json::Map<String, serde_json::Value> {
    let adrs = adrs_32_bytes(
        ADRS_LAYER, ADRS_TREE_HIGH, ADRS_TREE_LOW, ADRS_TYPE,
        ADRS_KEYPAIR, ADRS_CHAIN, ADRS_HASH,
    );
    let m = build_test_message(prim);

    let out_bytes: Vec<u8> = match prim {
        "F"    => { let mut m16=[0u8;16]; m16.copy_from_slice(&m); shake_f(&PK_SEED, &adrs, &m16).to_vec() }
        "H"    => { let mut m32=[0u8;32]; m32.copy_from_slice(&m); shake_h(&PK_SEED, &adrs, &m32).to_vec() }
        "Tk"   => shake_tk(&PK_SEED, &adrs, &m).to_vec(),
        "Tlen" => shake_tlen(&PK_SEED, &adrs, &m).to_vec(),
        "HMsg" => shake_hmsg(&R_BYTES, &PK_SEED, &PK_ROOT, &m).to_vec(),
        _ => panic!("unknown prim {prim}"),
    };

    let mut fields = serde_json::Map::new();
    if prim == "HMsg" {
        fields.insert("r".into(), json_bytes(&R_BYTES));
        fields.insert("pk_seed".into(), json_bytes(&PK_SEED));
        fields.insert("pk_root".into(), json_bytes(&PK_ROOT));
        fields.insert("m".into(), json_bytes(&m));
    } else {
        fields.insert("pk_seed".into(),   json_bytes(&PK_SEED));
        fields.insert("layer".into(),     json_num(ADRS_LAYER));
        fields.insert("tree_high".into(), json_num(ADRS_TREE_HIGH));
        fields.insert("tree_low".into(),  json_num(ADRS_TREE_LOW));
        fields.insert("type_".into(),     json_num(ADRS_TYPE));
        fields.insert("keypair".into(),   json_num(ADRS_KEYPAIR));
        fields.insert("chain".into(),     json_num(ADRS_CHAIN));
        fields.insert("hash".into(),      json_num(ADRS_HASH));
        fields.insert("m".into(),         json_bytes(&m));
    }
    fields.insert("expected_out".into(), json_bytes(&out_bytes));

    println!("[shake/{}] expected_out = {}", prim, hex::encode(&out_bytes));
    fields
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: {} <family> <prim>", args[0]);
        eprintln!("  family ∈ {{sha2, shake, all}}");
        eprintln!("  prim   ∈ {{F, H, Tk, Tlen, HMsg, all}}");
        std::process::exit(1);
    }
    let family = &args[1];
    let prim = &args[2];

    let prims: Vec<&str> = if prim == "all" {
        vec!["F", "H", "Tk", "Tlen", "HMsg"]
    } else {
        vec![prim.as_str()]
    };
    let families: Vec<&str> = if family == "all" {
        vec!["sha2", "shake"]
    } else {
        vec![family.as_str()]
    };

    for fam in &families {
        for p in &prims {
            let fields = match *fam {
                "sha2" => emit_sha2(p),
                "shake" => emit_shake(p),
                other => panic!("unknown family {other}"),
            };
            let name = format!("test_{}_{}", fam, p);
            write_input(&name, fields);
        }
    }
}

// Poseidon-SLH-DSA-128s signer for benchmarking the slh-dsa-circuit
// main_poseidon verifier on the privacy-ethereum/zkID Spartan2 stack.
//
// **NON-STANDARD; FOR BENCHMARKING ONLY.** Uses circomlib's BN254-tuned
// Poseidon constants reduced modulo p_secq256r1 — matches the circuit
// exactly, but not a vetted cryptographic primitive.
//
// Emits a witness JSON in the shape MainPoseidon expects:
//   pk[32]               — pk_seed[16] || pk_root[16] (public)
//   msg[1024]            — message bytes              (public)
//   r[16]                — H_msg randomizer           (private)
//   sig_fors[14][13][16] — FORS signature             (private)
//   sig_ht[7][44][16]    — hypertree signature        (private)
//
// Algorithm: FIPS 205 §11.1 slh_sign_internal adapted with Poseidon-based
// Slh* primitives (per circuits/poseidon/hashes.circom). Optimized to
// only compute the auth-path siblings needed (full ~2M Poseidon calls
// for the bottom-XMSS layers + 270K for keygen).
//
// Usage: node poseidon_sign.mjs [output_path]
// Default output: ../inputs/main_poseidon/1k/default.json

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CONSTANTS_PATH = path.resolve(
    __dirname,
    '../../slh-dsa-128s-poseidon-bench/wallet-unit-poc/circom/node_modules/circomlibjs/src/poseidon_constants_opt.json'
);

// circom's `--prime secq256r1` actually uses the secp256r1 BASE field
// (despite the naming). Empirically verified by comparing
// Poseidon(2)([1,2]) outputs between this signer and the compiled circuit.
const P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;

const mod = (x) => { const r = x % P; return r < 0n ? r + P : r; };
const fadd = (a, b) => mod(a + b);
const fmul = (a, b) => mod(a * b);
const fpow5 = (a) => { const a2 = fmul(a, a); const a4 = fmul(a2, a2); return fmul(a4, a); };

// Load Poseidon optimized constants (BN254-derived, used over secq256r1).
const rawConsts = JSON.parse(fs.readFileSync(CONSTANTS_PATH, 'utf8'));
const C   = rawConsts.C.map(arr => arr.map(s => mod(BigInt(s))));
const M_  = rawConsts.M.map(mat => mat.map(row => row.map(s => mod(BigInt(s)))));
const P_  = rawConsts.P.map(mat => mat.map(row => row.map(s => mod(BigInt(s)))));
const S_  = rawConsts.S.map(arr => arr.map(s => mod(BigInt(s))));
const N_ROUNDS_P = [56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65, 70, 60, 64, 68];
const N_ROUNDS_F = 8;

// Poseidon permutation, single-output form (matches circomlib Poseidon(nInputs)).
function poseidon(inputs, initialState = 0n) {
    const t = inputs.length + 1;
    const idx = t - 2;
    if (idx < 0 || idx >= N_ROUNDS_P.length) throw new Error(`Poseidon t=${t} out of range`);
    const c = C[idx];
    const s = S_[idx];
    const m = M_[idx];
    const p = P_[idx];
    const nRoundsP = N_ROUNDS_P[idx];

    let state = [mod(initialState), ...inputs.map(x => mod(x))];
    state = state.map((a, i) => fadd(a, c[i]));

    const mixWith = (mat) => {
        const out = new Array(t);
        for (let i = 0; i < t; i++) {
            let acc = 0n;
            for (let j = 0; j < t; j++) acc = fadd(acc, fmul(mat[j][i], state[j]));
            out[i] = acc;
        }
        return out;
    };

    // First half full rounds (nRoundsF/2 - 1 = 3)
    for (let r = 0; r < N_ROUNDS_F / 2 - 1; r++) {
        for (let i = 0; i < t; i++) state[i] = fpow5(state[i]);
        for (let i = 0; i < t; i++) state[i] = fadd(state[i], c[(r + 1) * t + i]);
        state = mixWith(m);
    }

    // Transition full round → mix with P
    for (let i = 0; i < t; i++) state[i] = fpow5(state[i]);
    const transitionRound = N_ROUNDS_F / 2 - 1 + 1;
    for (let i = 0; i < t; i++) state[i] = fadd(state[i], c[transitionRound * t + i]);
    state = mixWith(p);

    // Partial rounds
    for (let r = 0; r < nRoundsP; r++) {
        state[0] = fpow5(state[0]);
        state[0] = fadd(state[0], c[(N_ROUNDS_F / 2 + 1) * t + r]);
        let s0 = 0n;
        for (let j = 0; j < t; j++) s0 = fadd(s0, fmul(s[(t * 2 - 1) * r + j], state[j]));
        for (let k = 1; k < t; k++) {
            state[k] = fadd(state[k], fmul(state[0], s[(t * 2 - 1) * r + t + k - 1]));
        }
        state[0] = s0;
    }

    // Second half full rounds (3)
    for (let r = 0; r < N_ROUNDS_F / 2 - 1; r++) {
        for (let i = 0; i < t; i++) state[i] = fpow5(state[i]);
        for (let i = 0; i < t; i++) state[i] = fadd(state[i], c[(N_ROUNDS_F / 2 + 1) * t + nRoundsP + r * t + i]);
        state = mixWith(m);
    }

    // Final S-box and mix with M
    for (let i = 0; i < t; i++) state[i] = fpow5(state[i]);
    let out0 = 0n;
    for (let j = 0; j < t; j++) out0 = fadd(out0, fmul(m[j][0], state[j]));
    return out0;
}

// Pack 16 bytes (LE) into one secq256r1 field element.
function packBytes16ToFe(bytes) {
    let acc = 0n;
    for (let i = 0; i < 16; i++) acc += BigInt(bytes[i]) * (1n << BigInt(8 * i));
    return mod(acc);
}

// Take the low 128 bits of fe as 16 bytes (LE).
function unpackFeToBytes16(fe) {
    const bytes = new Array(16);
    let v = fe;
    for (let i = 0; i < 16; i++) { bytes[i] = Number(v & 0xffn); v >>= 8n; }
    return bytes;
}

// PoseidonHash16(nInputs) — Poseidon → low 128 bits as 16 bytes.
function poseidonHash16(inputs) {
    return unpackFeToBytes16(poseidon(inputs));
}

// PoseidonHash30(nInputs) — two Poseidon(nInputs+1) calls with tags 0/1,
// concatenate 16 + 14 bytes = 30 bytes.
function poseidonHash30(inputs) {
    const p0 = poseidon([0n, ...inputs]);
    const p1 = poseidon([1n, ...inputs]);
    return [...unpackFeToBytes16(p0), ...unpackFeToBytes16(p1).slice(0, 14)];
}

// PoseidonReduce(N) — binary Merkle reduce of N field elements via Poseidon(2).
function poseidonReduce(elts) {
    let cur = elts.slice();
    while (cur.length > 1) {
        const next = [];
        for (let i = 0; i < cur.length; i += 2) {
            const left = cur[i];
            const right = (i + 1 < cur.length) ? cur[i + 1] : 0n;
            next.push(poseidon([left, right]));
        }
        cur = next;
    }
    return cur[0];
}

// SlhF: tag=0; F primitive.
function slhF(pk_seed, layer, tree_high, tree_low, type_, keypair, chain, hash, m) {
    return poseidonHash16([
        0n,
        packBytes16ToFe(pk_seed),
        BigInt(layer), BigInt(tree_high), BigInt(tree_low), BigInt(type_),
        BigInt(keypair), BigInt(chain), BigInt(hash),
        packBytes16ToFe(m),
    ]);
}

// SlhH: tag=1; H primitive (input is 32 bytes m1||m2).
function slhH(pk_seed, layer, tree_high, tree_low, type_, keypair, chain, hash, m1, m2) {
    return poseidonHash16([
        1n,
        packBytes16ToFe(pk_seed),
        BigInt(layer), BigInt(tree_high), BigInt(tree_low), BigInt(type_),
        BigInt(keypair), BigInt(chain), BigInt(hash),
        packBytes16ToFe(m1), packBytes16ToFe(m2),
    ]);
}

// SlhTk: tag=2; T_k primitive over 14 16-byte roots.
function slhTk(pk_seed, layer, tree_high, tree_low, type_, keypair, chain, hash, roots14) {
    const packed = roots14.map(packBytes16ToFe);
    const reduced = poseidonReduce(packed);
    return poseidonHash16([
        2n,
        packBytes16ToFe(pk_seed),
        BigInt(layer), BigInt(tree_high), BigInt(tree_low), BigInt(type_),
        BigInt(keypair), BigInt(chain), BigInt(hash),
        reduced,
    ]);
}

// SlhTlen: tag=3; T_len primitive over 35 16-byte chain ends.
function slhTlen(pk_seed, layer, tree_high, tree_low, type_, keypair, chain, hash, ends35) {
    const packed = ends35.map(packBytes16ToFe);
    const reduced = poseidonReduce(packed);
    return poseidonHash16([
        3n,
        packBytes16ToFe(pk_seed),
        BigInt(layer), BigInt(tree_high), BigInt(tree_low), BigInt(type_),
        BigInt(keypair), BigInt(chain), BigInt(hash),
        reduced,
    ]);
}

// SlhHMsg: 4-input PoseidonHash30 over (R, pk_seed, pk_root, msg_digest).
function slhHMsg(r, pk_seed, pk_root, msg1024) {
    const msg_packed = [];
    for (let i = 0; i < 64; i++) msg_packed.push(packBytes16ToFe(msg1024.slice(i*16, i*16+16)));
    const msg_digest = poseidonReduce(msg_packed);
    return poseidonHash30([
        packBytes16ToFe(r), packBytes16ToFe(pk_seed), packBytes16ToFe(pk_root), msg_digest,
    ]);
}

// =================================================================
// SLH-DSA-128s parameters
// =================================================================
const N = 16, H_TOTAL = 63, D = 7, HPRIME = 9, A_FORS = 12, K_FORS = 14, LG_W = 4, W = 16, LEN = 35;

// PRF: deterministically derive a 16-byte secret from sk_seed and ADRS-style identifier.
// Uses Poseidon with a signer-private tag (we pick 99n; verifier never sees this).
function prfSk(sk_seed, layer, tree_high, tree_low, type_, keypair, chain, hash) {
    return unpackFeToBytes16(poseidon([
        99n,
        packBytes16ToFe(sk_seed),
        BigInt(layer), BigInt(tree_high), BigInt(tree_low), BigInt(type_),
        BigInt(keypair), BigInt(chain), BigInt(hash),
    ]));
}

// Compute a WOTS chain end from sk_wots[chain] by iterating SlhF 15 times.
function wotsChainEnd(pk_seed, layer, tree_high, tree_low, keypair, chain, startBytes) {
    let cur = startBytes;
    for (let k = 0; k < 15; k++) {
        const fe = slhF(pk_seed, layer, tree_high, tree_low, 0 /* WOTS_HASH */, keypair, chain, k, cur);
        cur = fe;
    }
    return cur;
}

// Compute a WOTS pubkey: full chain ends for all 35 chains, then SlhTlen.
function wotsPk(pk_seed, sk_seed, layer, tree_high, tree_low, keypair) {
    const ends = new Array(LEN);
    for (let i = 0; i < LEN; i++) {
        const sk = prfSk(sk_seed, layer, tree_high, tree_low, 5 /* WOTS_PRF */, keypair, i, 0);
        ends[i] = wotsChainEnd(pk_seed, layer, tree_high, tree_low, keypair, i, sk);
    }
    return slhTlen(pk_seed, layer, tree_high, tree_low, 1 /* WOTS_PK */, keypair, 0, 0, ends);
}

// Build the XMSS tree at (layer, tree_high, tree_low) and return its root.
// Optionally returns the full level-0 leaves array (the 512 WOTS pks) for sibling extraction.
function xmssTreeRoot(pk_seed, sk_seed, layer, tree_high, tree_low) {
    const numLeaves = 1 << HPRIME;
    let leaves = new Array(numLeaves);
    for (let kp = 0; kp < numLeaves; kp++) {
        leaves[kp] = wotsPk(pk_seed, sk_seed, layer, tree_high, tree_low, kp);
    }
    // Build Merkle tree: store all levels in case sibling extraction needed.
    const levels = [leaves];
    for (let z = 1; z <= HPRIME; z++) {
        const prev = levels[z - 1];
        const cur = new Array(prev.length / 2);
        for (let i = 0; i < prev.length; i += 2) {
            cur[i / 2] = slhH(pk_seed, layer, tree_high, tree_low, 2 /* TREE */, 0, z, i / 2, prev[i], prev[i + 1]);
        }
        levels.push(cur);
    }
    return { root: levels[HPRIME][0], levels };
}

// Extract XMSS auth path of length HPRIME=9 for leaf idx_leaf within a tree
// whose level structure is `levels` (output of xmssTreeRoot).
function xmssAuthPath(levels, idx_leaf) {
    const auth = new Array(HPRIME);
    let idx = idx_leaf;
    for (let k = 0; k < HPRIME; k++) {
        const sibIdx = idx ^ 1;
        auth[k] = levels[k][sibIdx];
        idx >>= 1;
    }
    return auth;
}

// Build a FORS tree of height A_FORS=12 (4096 leaves) for FORS subtree i,
// returning the levels structure so we can extract the auth path and root.
function forsTree(pk_seed, sk_seed, layer, tree_high, tree_low, keypair, forsIdx) {
    const numLeaves = 1 << A_FORS;
    const leaves = new Array(numLeaves);
    for (let j = 0; j < numLeaves; j++) {
        const treeIndex = forsIdx * numLeaves + j;
        const sk = prfSk(sk_seed, layer, tree_high, tree_low, 6 /* FORS_PRF */, keypair, forsIdx, j);
        leaves[j] = slhF(pk_seed, layer, tree_high, tree_low, 3 /* FORS_TREE */, keypair, 0 /* height */, treeIndex, sk);
    }
    const levels = [leaves];
    for (let z = 1; z <= A_FORS; z++) {
        const prev = levels[z - 1];
        const cur = new Array(prev.length / 2);
        for (let i = 0; i < prev.length; i += 2) {
            // Global tree_index at level z = forsIdx * 2^(A_FORS - z) + (i / 2).
            // Matches the verifier's `tree_index_shifted = i * 2^(12-z) + (md_indices[i] >> z)`
            // for the auth-path node at level z above leaf p, where (i/2) is the local
            // node index = (p >> z) for the walked path, or any other local index here.
            const treeIndex = forsIdx * (numLeaves >> z) + (i / 2);
            cur[i / 2] = slhH(pk_seed, layer, tree_high, tree_low, 3 /* FORS_TREE */, keypair, z, treeIndex, prev[i], prev[i + 1]);
        }
        levels.push(cur);
    }
    return { root: levels[A_FORS][0], levels, leaves };
}

// Base2bWithCsum: matches circuits/common/digest.circom — 32 nibbles from
// 16 bytes (MSB-first) + 3 checksum nibbles.
function base2bWithCsum(digest16) {
    const chunks = new Array(35);
    for (let i = 0; i < 16; i++) {
        chunks[2 * i]     = (digest16[i] >> 4) & 0xf;
        chunks[2 * i + 1] = digest16[i] & 0xf;
    }
    let csum = 0;
    for (let i = 0; i < 32; i++) csum += 15 - chunks[i];
    // csum < 2^9; shift left 4 then split into 3 nibbles MSB-first (i.e., (csum<<4) as 2 BE bytes → 3 nibbles).
    // chunks[32] = csum>>8 ; chunks[33] = (csum>>4)&0xf ; chunks[34] = csum & 0xf
    chunks[32] = (csum >> 8) & 0x1;
    chunks[33] = (csum >> 4) & 0xf;
    chunks[34] = csum & 0xf;
    return chunks;
}

// Parse 30-byte H_msg digest into (md_indices[14], idx_tree, idx_leaf).
// idx_tree is returned as BigInt because it can exceed 2^53 (JS safe integer).
function parseDigest(digest30) {
    const md_indices = new Array(14);
    for (let c = 0; c < 14; c++) {
        let val = 0;
        for (let j = 0; j < 12; j++) {
            const bePos = 12 * c + j;
            const byteIdx = bePos >> 3;
            const bitInByteBe = bePos & 7;
            const bitInByteLe = 7 - bitInByteBe;
            const bit = (digest30[byteIdx] >> bitInByteLe) & 1;
            val += bit * (1 << (11 - j));
        }
        md_indices[c] = val;
    }
    let idx_tree_56 = 0n;
    for (let i = 0; i < 7; i++) idx_tree_56 = (idx_tree_56 << 8n) | BigInt(digest30[21 + i]);
    const idx_tree = idx_tree_56 & ((1n << 54n) - 1n);   // BigInt
    const idx_leaf_16 = (digest30[28] << 8) | digest30[29];
    const idx_leaf = idx_leaf_16 & 0x1ff;                 // < 2^9, fits in Number
    return { md_indices, idx_tree, idx_leaf };
}

// =================================================================
// Keygen + Sign
// =================================================================
function randomBytes16(label) {
    // Deterministic for reproducibility: hash label into 16 bytes.
    const crypto = require('node:crypto');
    return Array.from(crypto.createHash('sha256').update(String(label)).digest().slice(0, 16));
}

async function main() {
    const t0 = Date.now();
    console.log('[poseidon_sign] starting');

    // Deterministic seeds for reproducibility.
    const sk_seed = (await import('node:crypto')).createHash('sha256').update('slh-dsa-bench-sk-seed-v1').digest().slice(0, 16);
    const pk_seed = (await import('node:crypto')).createHash('sha256').update('slh-dsa-bench-pk-seed-v1').digest().slice(0, 16);
    const sk_seed_arr = Array.from(sk_seed);
    const pk_seed_arr = Array.from(pk_seed);
    console.log(`[keygen] sk_seed=${Buffer.from(sk_seed).toString('hex')}`);
    console.log(`[keygen] pk_seed=${Buffer.from(pk_seed).toString('hex')}`);

    // --- KEYGEN: build top XMSS tree at layer d-1 = 6, get pk_root ---
    console.log(`[keygen] building top XMSS (layer ${D-1}, ${1 << HPRIME} leaves)…`);
    const topTree = xmssTreeRoot(pk_seed_arr, sk_seed_arr, D - 1, 0, 0);
    const pk_root_arr = topTree.root;
    console.log(`[keygen] pk_root=${Buffer.from(pk_root_arr).toString('hex')}  (${(Date.now()-t0)/1000}s)`);

    // --- MESSAGE + RANDOMIZER ---
    const msg = Array.from((await import('node:crypto')).createHash('sha512').update('slh-dsa-bench-msg-v1').digest());
    while (msg.length < 1024) msg.push(...msg.slice(0, Math.min(msg.length, 1024 - msg.length)));
    const msg1024 = msg.slice(0, 1024);
    const r = Array.from((await import('node:crypto')).createHash('sha256').update('slh-dsa-bench-r-v1').digest().slice(0, 16));

    // --- COMPUTE H_msg → indices ---
    console.log('[sign] H_msg…');
    const digest30 = slhHMsg(r, pk_seed_arr, pk_root_arr, msg1024);
    const { md_indices, idx_tree, idx_leaf } = parseDigest(digest30);
    console.log(`[sign] idx_tree=${idx_tree}  idx_leaf=${idx_leaf}  md_indices=[${md_indices.join(',')}]`);

    // --- FORS SIGN ---
    // FORS lives at HT layer 0 (the bottom XMSS tree).
    // Its keypair address = idx_leaf. ADRS.tree_low = idx_tree.
    console.log('[sign] FORS trees…');
    const sig_fors = new Array(K_FORS);
    const fors_roots = new Array(K_FORS);
    for (let i = 0; i < K_FORS; i++) {
        const t1 = Date.now();
        const leafIdx = md_indices[i];
        const tree = forsTree(pk_seed_arr, sk_seed_arr, 0, 0, idx_tree, idx_leaf, i);
        fors_roots[i] = tree.root;
        // sig_fors[i][0] = leaf sk
        const sig_i = [];
        sig_i.push(Array.from(prfSk(sk_seed_arr, 0, 0, idx_tree, 6 /* FORS_PRF */, idx_leaf, i, leafIdx)));
        // sig_fors[i][1..12] = auth path siblings
        let idx = leafIdx;
        for (let z = 0; z < A_FORS; z++) {
            const sibIdx = idx ^ 1;
            sig_i.push(tree.levels[z][sibIdx]);
            idx >>= 1;
        }
        sig_fors[i] = sig_i;
        console.log(`[sign]   FORS tree ${i}/${K_FORS}  (${(Date.now()-t1)/1000}s, total ${(Date.now()-t0)/1000}s)`);
    }

    // pk_fors = SlhTk(fors_roots)
    const pk_fors = slhTk(pk_seed_arr, 0, 0, idx_tree, 4 /* FORS_ROOTS */, idx_leaf, 0, 0, fors_roots);

    // --- HT SIGN ---
    console.log('[sign] HT layers…');
    const sig_ht = new Array(D);
    let layer_msg = pk_fors;
    let cur_idx_tree = idx_tree;
    let cur_idx_leaf = idx_leaf;
    for (let j = 0; j < D; j++) {
        const t1 = Date.now();
        // Build the layer-j XMSS tree at (cur_idx_tree).
        const xmss = xmssTreeRoot(pk_seed_arr, sk_seed_arr, j, 0, cur_idx_tree);

        // Compute WOTS signature: chain start values from PRF, chain msg_chunks[i] times.
        const wots_msg = base2bWithCsum(layer_msg);
        const wots_sig = new Array(LEN);
        for (let i = 0; i < LEN; i++) {
            const sk_i = prfSk(sk_seed_arr, j, 0, cur_idx_tree, 5 /* WOTS_PRF */, cur_idx_leaf, i, 0);
            let cur = sk_i;
            for (let k = 0; k < wots_msg[i]; k++) {
                cur = slhF(pk_seed_arr, j, 0, cur_idx_tree, 0 /* WOTS_HASH */, cur_idx_leaf, i, k, cur);
            }
            wots_sig[i] = cur;
        }

        // Sanity check: continuing the chain to position 15 should yield this leaf's WOTS pk,
        // and that should be xmss.levels[0][cur_idx_leaf].
        const auth = xmssAuthPath(xmss.levels, cur_idx_leaf);
        const sig_j = wots_sig.concat(auth);
        sig_ht[j] = sig_j;

        // Next layer: layer_msg = xmss root, idx_tree >>= 9, idx_leaf = old idx_tree & 0x1ff.
        if (j < D - 1) {
            layer_msg = xmss.root;
            cur_idx_leaf = Number(cur_idx_tree & 0x1ffn);
            cur_idx_tree = cur_idx_tree >> 9n;
        } else {
            // Verify top layer's xmss root equals pk_root (sanity).
            const matches = xmss.root.every((b, k) => b === pk_root_arr[k]);
            if (!matches) {
                console.error('[sign] WARNING: top XMSS root mismatch with pk_root');
            } else {
                console.log('[sign] top XMSS root matches pk_root ✓');
            }
        }
        console.log(`[sign]   HT layer ${j}/${D}  (${(Date.now()-t1)/1000}s, total ${(Date.now()-t0)/1000}s)`);
    }

    // --- EMIT JSON ---
    const pk = pk_seed_arr.concat(pk_root_arr);
    const out = {
        pk:       pk.map(String),
        msg:      msg1024.map(String),
        r:        r.map(String),
        sig_fors: sig_fors.map(row => row.map(node => node.map(String))),
        sig_ht:   sig_ht.map(row => row.map(node => node.map(String))),
    };
    const outPath = process.argv[2] || path.resolve(__dirname, '../inputs/main_poseidon/1k/default.json');
    fs.mkdirSync(path.dirname(outPath), { recursive: true });
    fs.writeFileSync(outPath, JSON.stringify(out));
    console.log(`[done] wrote ${outPath}  (${(Date.now()-t0)/1000}s total)`);
}

main().catch(e => { console.error(e); process.exit(1); });

// JS replica of the SlhDsaVerify circuit. Reads the witness JSON and
// computes the verifier output (the recovered pk_root), comparing against
// the witness's pk_root. Used to localize bugs in poseidon_sign.mjs.
//
// Usage: node poseidon_verify.mjs [path/to/default.json]

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CONSTANTS_PATH = path.resolve(
    __dirname,
    '../../slh-dsa-128s-poseidon-bench/wallet-unit-poc/circom/node_modules/circomlibjs/src/poseidon_constants_opt.json'
);

const P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
const mod = (x) => { const r = x % P; return r < 0n ? r + P : r; };
const fadd = (a, b) => mod(a + b);
const fmul = (a, b) => mod(a * b);
const fpow5 = (a) => { const a2 = fmul(a, a); const a4 = fmul(a2, a2); return fmul(a4, a); };

const rawConsts = JSON.parse(fs.readFileSync(CONSTANTS_PATH, 'utf8'));
const C   = rawConsts.C.map(arr => arr.map(s => mod(BigInt(s))));
const M_  = rawConsts.M.map(mat => mat.map(row => row.map(s => mod(BigInt(s)))));
const P_  = rawConsts.P.map(mat => mat.map(row => row.map(s => mod(BigInt(s)))));
const S_  = rawConsts.S.map(arr => arr.map(s => mod(BigInt(s))));
const N_ROUNDS_P = [56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65, 70, 60, 64, 68];
const N_ROUNDS_F = 8;

function poseidon(inputs, initialState = 0n) {
    const t = inputs.length + 1;
    const idx = t - 2;
    const c = C[idx]; const s = S_[idx]; const m = M_[idx]; const p = P_[idx];
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
    for (let r = 0; r < N_ROUNDS_F / 2 - 1; r++) {
        for (let i = 0; i < t; i++) state[i] = fpow5(state[i]);
        for (let i = 0; i < t; i++) state[i] = fadd(state[i], c[(r + 1) * t + i]);
        state = mixWith(m);
    }
    for (let i = 0; i < t; i++) state[i] = fpow5(state[i]);
    for (let i = 0; i < t; i++) state[i] = fadd(state[i], c[(N_ROUNDS_F / 2) * t + i]);
    state = mixWith(p);
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
    for (let r = 0; r < N_ROUNDS_F / 2 - 1; r++) {
        for (let i = 0; i < t; i++) state[i] = fpow5(state[i]);
        for (let i = 0; i < t; i++) state[i] = fadd(state[i], c[(N_ROUNDS_F / 2 + 1) * t + nRoundsP + r * t + i]);
        state = mixWith(m);
    }
    for (let i = 0; i < t; i++) state[i] = fpow5(state[i]);
    let out0 = 0n;
    for (let j = 0; j < t; j++) out0 = fadd(out0, fmul(m[j][0], state[j]));
    return out0;
}

function packBytes16ToFe(bytes) {
    let acc = 0n;
    for (let i = 0; i < 16; i++) acc += BigInt(bytes[i]) * (1n << BigInt(8 * i));
    return mod(acc);
}
function unpackFeToBytes16(fe) {
    const bytes = new Array(16);
    let v = fe;
    for (let i = 0; i < 16; i++) { bytes[i] = Number(v & 0xffn); v >>= 8n; }
    return bytes;
}
function poseidonHash16(inputs) { return unpackFeToBytes16(poseidon(inputs)); }
function poseidonHash30(inputs) {
    const p0 = poseidon([0n, ...inputs]);
    const p1 = poseidon([1n, ...inputs]);
    return [...unpackFeToBytes16(p0), ...unpackFeToBytes16(p1).slice(0, 14)];
}
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

function slhF(pk_seed, layer, th, tl, type_, kp, chain, hash, m) {
    return poseidonHash16([0n, packBytes16ToFe(pk_seed),
        BigInt(layer), BigInt(th), BigInt(tl), BigInt(type_),
        BigInt(kp), BigInt(chain), BigInt(hash), packBytes16ToFe(m)]);
}
function slhH(pk_seed, layer, th, tl, type_, kp, chain, hash, m1, m2) {
    return poseidonHash16([1n, packBytes16ToFe(pk_seed),
        BigInt(layer), BigInt(th), BigInt(tl), BigInt(type_),
        BigInt(kp), BigInt(chain), BigInt(hash),
        packBytes16ToFe(m1), packBytes16ToFe(m2)]);
}
function slhTk(pk_seed, layer, th, tl, type_, kp, chain, hash, roots14) {
    const packed = roots14.map(packBytes16ToFe);
    const reduced = poseidonReduce(packed);
    return poseidonHash16([2n, packBytes16ToFe(pk_seed),
        BigInt(layer), BigInt(th), BigInt(tl), BigInt(type_),
        BigInt(kp), BigInt(chain), BigInt(hash), reduced]);
}
function slhTlen(pk_seed, layer, th, tl, type_, kp, chain, hash, ends35) {
    const packed = ends35.map(packBytes16ToFe);
    const reduced = poseidonReduce(packed);
    return poseidonHash16([3n, packBytes16ToFe(pk_seed),
        BigInt(layer), BigInt(th), BigInt(tl), BigInt(type_),
        BigInt(kp), BigInt(chain), BigInt(hash), reduced]);
}
function slhHMsg(r, pk_seed, pk_root, msg1024) {
    const msg_packed = [];
    for (let i = 0; i < 64; i++) msg_packed.push(packBytes16ToFe(msg1024.slice(i*16, i*16+16)));
    const msg_digest = poseidonReduce(msg_packed);
    return poseidonHash30([
        packBytes16ToFe(r), packBytes16ToFe(pk_seed), packBytes16ToFe(pk_root), msg_digest,
    ]);
}

function base2bWithCsum(digest16) {
    const chunks = new Array(35);
    for (let i = 0; i < 16; i++) {
        chunks[2*i]     = (digest16[i] >> 4) & 0xf;
        chunks[2*i + 1] = digest16[i] & 0xf;
    }
    let csum = 0;
    for (let i = 0; i < 32; i++) csum += 15 - chunks[i];
    chunks[32] = (csum >> 8) & 0x1;
    chunks[33] = (csum >> 4) & 0xf;
    chunks[34] = csum & 0xf;
    return chunks;
}

function parseDigest(digest30) {
    const md_indices = new Array(14);
    for (let c = 0; c < 14; c++) {
        let val = 0;
        for (let j = 0; j < 12; j++) {
            const bePos = 12 * c + j;
            const byteIdx = bePos >> 3;
            const bitInByteLe = 7 - (bePos & 7);
            const bit = (digest30[byteIdx] >> bitInByteLe) & 1;
            val += bit * (1 << (11 - j));
        }
        md_indices[c] = val;
    }
    let idx_tree_56 = 0n;
    for (let i = 0; i < 7; i++) idx_tree_56 = (idx_tree_56 << 8n) | BigInt(digest30[21 + i]);
    const idx_tree = idx_tree_56 & ((1n << 54n) - 1n);  // BigInt
    const idx_leaf_16 = (digest30[28] << 8) | digest30[29];
    const idx_leaf = idx_leaf_16 & 0x1ff;
    return { md_indices, idx_tree, idx_leaf };
}

// Verifier-side WOTS pubkey computation from a WOTS sig.
function wotsPkFromSig(pk_seed, layer, th, tl, keypair, wots_msg, wots_sig) {
    const chain_pk = new Array(35);
    for (let i = 0; i < 35; i++) {
        const cand = new Array(16);
        cand[0] = wots_sig[i];
        for (let k = 0; k < 15; k++) {
            cand[k + 1] = slhF(pk_seed, layer, th, tl, 0, keypair, i, wots_msg[i] + k, cand[k]);
        }
        chain_pk[i] = cand[15 - wots_msg[i]];
    }
    return slhTlen(pk_seed, layer, th, tl, 1, keypair, 0, 0, chain_pk);
}

// Verifier-side FORS pk from sig.
function forsPkFromSig(pk_seed, layer, th, tl, keypair, md_indices, sig_fors) {
    const tree_roots = new Array(14);
    for (let i = 0; i < 14; i++) {
        const md_i = md_indices[i];
        // Leaf hash
        let node = slhF(pk_seed, layer, th, tl, 3, keypair, 0, i * 4096 + md_i, sig_fors[i][0]);
        // Walk up 12 levels
        let idx = md_i;
        for (let z = 1; z <= 12; z++) {
            const bit = (idx >> (z - 1)) & 1;
            const sibling = sig_fors[i][z];
            const left  = (bit === 0) ? node : sibling;
            const right = (bit === 0) ? sibling : node;
            const treeIndex = i * (1 << (12 - z)) + (md_i >> z);
            node = slhH(pk_seed, layer, th, tl, 3, keypair, z, treeIndex, left, right);
        }
        tree_roots[i] = node;
    }
    return slhTk(pk_seed, layer, th, tl, 4, keypair, 0, 0, tree_roots);
}

// Verifier-side XMSS pk from sig.
function xmssPkFromSig(pk_seed, layer, th, tl, idx_leaf, wots_msg, wots_sig, xmss_auth) {
    let node = wotsPkFromSig(pk_seed, layer, th, tl, idx_leaf, wots_msg, wots_sig);
    for (let k = 0; k < 9; k++) {
        const bit = (idx_leaf >> k) & 1;
        const sibling = xmss_auth[k];
        const left  = (bit === 0) ? node : sibling;
        const right = (bit === 0) ? sibling : node;
        const tree_index_at_k1 = idx_leaf >> (k + 1);
        node = slhH(pk_seed, layer, th, tl, 2, 0, k + 1, tree_index_at_k1, left, right);
    }
    return node;
}

// Full verifier.
function verify(witness) {
    const pk = witness.pk.map(Number);
    const msg = witness.msg.map(Number);
    const r = witness.r.map(Number);
    const sig_fors = witness.sig_fors.map(row => row.map(node => node.map(Number)));
    const sig_ht = witness.sig_ht.map(row => row.map(node => node.map(Number)));

    const pk_seed = pk.slice(0, 16);
    const pk_root = pk.slice(16, 32);

    // Step 1: H_msg digest
    const digest = slhHMsg(r, pk_seed, pk_root, msg);
    const { md_indices, idx_tree, idx_leaf } = parseDigest(digest);
    console.log(`[verify] idx_tree=${idx_tree}  idx_leaf=${idx_leaf}`);
    console.log(`[verify] md_indices=[${md_indices.join(',')}]`);

    // Step 2: FORS pk
    const pk_fors = forsPkFromSig(pk_seed, 0, 0, idx_tree, idx_leaf, md_indices, sig_fors);
    console.log(`[verify] pk_fors=${Buffer.from(pk_fors).toString('hex')}`);

    // Step 3: HT verification
    let layer_msg = pk_fors;
    let cur_idx_tree = idx_tree;
    let cur_idx_leaf = idx_leaf;
    for (let j = 0; j < 7; j++) {
        const wots_msg = base2bWithCsum(layer_msg);
        const wots_sig = sig_ht[j].slice(0, 35);
        const auth = sig_ht[j].slice(35, 44);
        const xmss_root = xmssPkFromSig(pk_seed, j, 0, cur_idx_tree, cur_idx_leaf, wots_msg, wots_sig, auth);
        console.log(`[verify] layer ${j}  cur_idx_tree=${cur_idx_tree}  cur_idx_leaf=${cur_idx_leaf}  xmss_root=${Buffer.from(xmss_root).toString('hex')}`);
        layer_msg = xmss_root;
        if (j < 6) {
            cur_idx_leaf = Number(cur_idx_tree & 0x1ffn);
            cur_idx_tree = cur_idx_tree >> 9n;
        }
    }

    const matches = layer_msg.every((b, k) => b === pk_root[k]);
    console.log(`[verify] final_root=${Buffer.from(layer_msg).toString('hex')}`);
    console.log(`[verify] pk_root=  ${Buffer.from(pk_root).toString('hex')}`);
    console.log(`[verify] ${matches ? '✓ VALID' : '✗ INVALID (mismatch)'}`);
    return matches;
}

const witnessPath = process.argv[2] || '/tmp/slh_dsa_witness.json';
const witness = JSON.parse(fs.readFileSync(witnessPath, 'utf8'));
verify(witness);

pragma circom 2.2.3;

include "../poseidon/poseidon_wrap.circom";

// Measures the R1CS cost of PoseidonReduce(N) — the binary-tree
// reduction used inside SlhTk (N=14), SlhTlen (N=35), and SlhHMsg
// (N=64). Per `circuits/poseidon/poseidon_wrap.circom:91-117` this is
// a binary tree with `ceil(N/2)` pairs at each level (odd inputs paired
// with zero).
//
// Validates the symbolic perm-count formula in
// research/folding/step_function_slh_dsa_128s.md §2.1, §3.3:
//   PoseidonReduce(14) = 7+4+2+1 = 14 Poseidon(2) perms
//   PoseidonReduce(35) = 18+9+5+3+2+1 = 38 perms
//   PoseidonReduce(64) = 32+16+8+4+2+1 = 63 perms
//
// Combined with the bench_poseidon_reduce2 measurement, this lets us
// cross-check: PoseidonReduce(N) constraints ≈ (tree-perm-count) × P(2).
template BenchPoseidonReduceChain(n) {
    signal input in[n];
    signal output out;

    component r = PoseidonReduce(n);
    for (var i = 0; i < n; i++) r.inputs[i] <== in[i];
    out <== r.out;
}

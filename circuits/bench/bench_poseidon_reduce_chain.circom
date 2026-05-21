pragma circom 2.2.3;

include "../poseidon/poseidon_wrap.circom";

// Measures the R1CS cost of PoseidonReduce(N) — the binary-tree
// reduction used inside SlhTk (N=14), SlhTlen (N=35), and SlhHMsg
// (N=64). Combined with bench_poseidon_reduce2, lets us cross-check
// `PoseidonReduce(N).R1CS ≈ poseidon_reduce_perm_count(N) × P(2)`.
// See `poseidon_reduce_perm_count()` in scripts/folding_lib.py.
template BenchPoseidonReduceChain(n) {
    signal input in[n];
    signal output out;

    component r = PoseidonReduce(n);
    for (var i = 0; i < n; i++) r.inputs[i] <== in[i];
    out <== r.out;
}

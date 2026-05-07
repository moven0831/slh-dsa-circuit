# SLH-DSA-128s R1CS Per-Component Bench Summary

Auto-generated from `results/raw_bench.txt` by `scripts/parse_r1cs_stats.py`.

## Per-component constraint counts

| Component | invocations | sha2 (constraints/call) | shake (constraints/call) | poseidon (constraints/call) |
|-----------|-------------|-----------|-----------|-----------|
| F | 3689 | 30,290 | 145,568 | 968 |
| H | 231 | 30,662 | 145,824 | 1,102 |
| Tk | 1 | 123,182 | 440,736 | 5,989 |
| Tlen | 7 | 307,106 | 737,952 | 14,428 |
| HMsg | 1 | 583,273 | 1,182,912 | 24,844 |
| **Sum-of-parts** | — | 121,678,929 | 577,475,008 | 3,957,343 |

## Integrated full-main constraint counts

| Family | Status | nConstraints | nWires | nPubIn | nPrvIn | .r1cs size |
|--------|--------|-------------:|-------:|-------:|-------:|-----------:|
| sha2 | compile_error | — | — | — | — | — |
| shake | compile_error | — | — | — | — | — |
| poseidon | OK | 3,992,159 | 3,861,768 | 1056 | 7856 | 2,276,653,228 B |

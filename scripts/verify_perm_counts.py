#!/usr/bin/env python3
"""Validate the symbolic Poseidon-permutation and R1CS counts claimed in
`research/folding/step_function_slh_dsa_128s.md` against the actual code
in this repo.

Verifies:
  1. SLH-DSA-128s parameters declared in `circuits/common/params.circom`
     match the values cited in §3.1 of the design doc.
  2. The PoseidonReduce(N) binary-tree perm-count formula
     (ceil(N/2) + ceil(N/4) + ... + 1) matches the measured R1CS counts
     from `bench_poseidon_reduce_{14,35,64}` (allowing small wire-routing
     overhead, <1 %).
  3. The per-verify Poseidon-perm grand total of 4,273 is correctly
     derived from the parameter set.
  4. Σ(per-primitive R1CS × call count from FIPS 205) reconciles to the
     measured main_poseidon total within 2 %.
  5. The D2-c flat-IVC primary claim (uniform arity-2 Poseidon step) uses
     the measured Poseidon(2) R1CS, not the design-doc's earlier estimate.

Run after `yarn bench` (so raw_bench.txt has fresh numbers including the
new `bench_poseidon_reduce*` entries). Exits non-zero on any reconciliation
failure so this can be a CI check.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass

from folding_lib import (
    compute_invocation_counts,
    poseidon_reduce_perm_count,
    read_bench_constraints,
    read_params,
)

# Tolerance bands for the five reconciliation checks.
TOL_REDUCE_PCT = 1.0   # PoseidonReduce R1CS ≈ perms × P(2), modulo wire-routing overhead
TOL_EXACT = 0.0        # symbolic perm count: must match exactly
TOL_SUM_PCT = 2.0      # sum-of-parts vs measured main: byte-packing glue at the boundaries
TOL_DOC_DRIFT = 1.0    # design-doc canonical numbers vs measured (regression detector)

# Design-doc claims (research/folding/step_function_slh_dsa_128s.md §3.1).
EXPECTED_PARAMS = {
    "SLH_N": 16,
    "SLH_H": 63,
    "SLH_D": 7,
    "SLH_HPRIME": 9,
    "SLH_A": 12,
    "SLH_K": 14,
    "SLH_LG_W": 4,
    "SLH_W": 16,
    "SLH_M_BYTES": 30,
    "SLH_LEN1": 32,
    "SLH_LEN2": 3,
    "SLH_LEN": 35,
}


@dataclass
class Check:
    name: str
    expected: float
    actual: float
    tolerance_pct: float
    units: str = ""

    @property
    def passed(self) -> bool:
        # When expected==0, tolerance_pct is treated as an absolute threshold.
        if self.expected == 0:
            return abs(self.actual) <= self.tolerance_pct
        return abs(self.actual - self.expected) / abs(self.expected) * 100 <= self.tolerance_pct

    def report(self) -> str:
        delta = self.actual - self.expected
        delta_pct = (delta / self.expected * 100) if self.expected else 0.0
        status = "PASS" if self.passed else "FAIL"
        return (
            f"  [{status}] {self.name}: expected={self.expected:,.0f}{self.units}, "
            f"actual={self.actual:,.0f}{self.units}, delta={delta:+,.0f} ({delta_pct:+.2f}%)"
        )


def main() -> int:
    params = read_params()
    bench = read_bench_constraints()

    print("=" * 72)
    print("Validating research/folding/step_function_slh_dsa_128s.md numbers")
    print("=" * 72)

    failures = 0

    # --- Check 1: SLH-DSA-128s parameters ---
    print("\n[1] SLH-DSA-128s parameters from circuits/common/params.circom")
    for k, expected in EXPECTED_PARAMS.items():
        actual = params.get(k)
        if actual is None:
            print(f"  [FAIL] {k}: not found in params.circom")
            failures += 1
        elif actual != expected:
            print(f"  [FAIL] {k}: expected={expected}, got={actual}")
            failures += 1
        else:
            print(f"  [PASS] {k} = {actual}")

    # --- Check 2: PoseidonReduce(N) binary-tree perm count ---
    print("\n[2] PoseidonReduce(N) binary-tree perm counts (vs measured R1CS)")
    p2_r1cs = bench.get("bench_poseidon_reduce2")
    if p2_r1cs is None:
        print("  [SKIP] bench_poseidon_reduce2 not in raw_bench.txt — run `yarn bench`")
        failures += 1
    else:
        print(f"  Poseidon(2) baseline R1CS = {p2_r1cs}")
        for n in (14, 35, 64):
            expected_perms = poseidon_reduce_perm_count(n)
            actual_r1cs = bench.get(f"bench_poseidon_reduce_{n}")
            if actual_r1cs is None:
                print(f"  [SKIP] bench_poseidon_reduce_{n} not measured")
                failures += 1
                continue
            chk = Check(
                name=f"PoseidonReduce({n}) = {expected_perms} × P(2)",
                expected=expected_perms * p2_r1cs,
                actual=actual_r1cs,
                tolerance_pct=TOL_REDUCE_PCT,
                units=" R1CS",
            )
            print(chk.report())
            if not chk.passed:
                failures += 1

    # --- Check 3: Per-verify Poseidon-permutation grand total ---
    print("\n[3] Per-verify Poseidon-perm derivation (design doc §3.3 claim: 4,273)")
    calls = compute_invocation_counts(params)
    # Per-primitive Poseidon-perm count: 1 for F/H; 1 mix + reduce(arity) for
    # T_k/T_len; 2 mix + reduce(64) for H_msg (M=1024 B = 64 FE).
    perm_per_call = {
        "F": 1,
        "H": 1,
        "Tk": 1 + poseidon_reduce_perm_count(params["SLH_K"]),
        "Tlen": 1 + poseidon_reduce_perm_count(params["SLH_LEN"]),
        "HMsg": 2 + poseidon_reduce_perm_count(64),
    }
    print(f"  Per-primitive call counts: {calls}")
    print(f"  Perms per call: {perm_per_call}")
    grand_total_perms = sum(calls[p] * perm_per_call[p] for p in calls)
    print(f"  Grand total Poseidon perms per verify = {grand_total_perms}")
    chk = Check(
        name="grand-total perms = 4,273",
        expected=4273,
        actual=grand_total_perms,
        tolerance_pct=TOL_EXACT,
        units=" perms",
    )
    print(chk.report())
    if not chk.passed:
        failures += 1

    # --- Check 4: Σ(per-prim R1CS × call count) vs measured main_poseidon ---
    print("\n[4] Per-primitive R1CS × call counts vs measured main_poseidon")
    measured_per_prim = {p: bench.get(f"bench_poseidon_{p}") for p in calls}
    main_r1cs = bench.get("main_poseidon")
    if any(v is None for v in measured_per_prim.values()) or main_r1cs is None:
        print("  [SKIP] missing per-primitive or main_poseidon measurement")
        failures += 1
    else:
        sum_of_parts = sum(measured_per_prim[p] * calls[p] for p in calls)
        delta = main_r1cs - sum_of_parts
        delta_pct = delta / main_r1cs * 100
        print(f"  Sum-of-parts = {sum_of_parts:,} R1CS")
        print(f"  Measured main_poseidon = {main_r1cs:,} R1CS")
        print(f"  Glue overhead = {delta:+,} R1CS ({delta_pct:+.2f}%)")
        chk = Check(
            name="sum-of-parts reconciles to ≤2% of main_poseidon",
            expected=main_r1cs,
            actual=sum_of_parts,
            tolerance_pct=TOL_SUM_PCT,
            units=" R1CS",
        )
        print(chk.report())
        if not chk.passed:
            failures += 1

    # --- Check 5: D2-c flat-IVC step cost (canonical for Week 2) ---
    print("\n[5] D2-c flat-IVC step cost (canonical for scheme_selection.md)")
    if p2_r1cs is None or main_r1cs is None:
        print("  [SKIP] missing Poseidon(2) or main_poseidon measurement")
    else:
        d2c_total = p2_r1cs * grand_total_perms
        reduction_pct = (1 - d2c_total / main_r1cs) * 100
        print(f"  D2-c step circuit: 1× Poseidon(2) = {p2_r1cs} R1CS")
        print(f"  D2-c fold count: {grand_total_perms}")
        print(f"  D2-c total step work: {d2c_total:,} R1CS")
        print(f"  Reduction vs monolithic {main_r1cs:,}: {reduction_pct:.1f}%")
        # Design-doc canonical numbers — must match the values cited in the
        # doc itself. Update both this dict and the doc together. The drift
        # check makes the verifier a one-way ratchet against silent rot.
        doc_canonical = {
            "step R1CS": (240, p2_r1cs),
            "total D2-c R1CS": (1_025_520, d2c_total),
            "reduction vs monolithic (%)": (74.3, reduction_pct),
        }
        for label, (claimed, measured) in doc_canonical.items():
            drift = (measured - claimed) / claimed * 100 if claimed else 0
            tag = "OK" if abs(drift) < TOL_DOC_DRIFT else "STALE"
            print(
                f"  [{tag}] doc claim {label} = {claimed:,} vs measured {measured:,.1f} "
                f"({drift:+.2f}%)"
            )
            if tag == "STALE":
                failures += 1

    # --- Summary ---
    print("\n" + "=" * 72)
    if failures:
        print(f"RESULT: {failures} check(s) failed.")
        return 1
    print("RESULT: all checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

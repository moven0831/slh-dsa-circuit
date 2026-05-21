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

import math
import re
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PARAMS_FILE = ROOT / "circuits" / "common" / "params.circom"
RAW_BENCH = ROOT / "results" / "raw_bench.txt"

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


def read_params() -> dict[str, int]:
    """Parse `function SLH_*() { return N; }` entries from params.circom."""
    text = PARAMS_FILE.read_text()
    params: dict[str, int] = {}
    for m in re.finditer(r"function\s+(SLH_\w+)\(\)\s*\{\s*return\s+(\d+)\s*;\s*\}", text):
        params[m.group(1)] = int(m.group(2))
    return params


def read_bench() -> dict[str, int]:
    """Parse circuit-name → nConstraints from raw_bench.txt."""
    if not RAW_BENCH.exists():
        sys.stderr.write(f"ERROR: {RAW_BENCH} missing — run `yarn bench` first.\n")
        sys.exit(1)
    out: dict[str, int] = {}
    for line in RAW_BENCH.read_text().splitlines():
        m = re.match(r"^(\S+)\s+OK\s+.*nConstraints=(\d+)", line)
        if m:
            out[m.group(1)] = int(m.group(2))
    return out


def poseidon_reduce_perm_count(n: int) -> int:
    """Number of Poseidon(2) permutations PoseidonReduce(n) instantiates.

    Matches `circuits/poseidon/poseidon_wrap.circom:91-117`: at each level
    pair `ceil(n/2)` inputs (odd-out paired with zero), recurse until 1.
    """
    total = 0
    while n > 1:
        pairs = (n + 1) // 2
        total += pairs
        n = pairs
    return total


@dataclass
class Check:
    name: str
    expected: float
    actual: float
    tolerance_pct: float
    units: str = ""

    @property
    def passed(self) -> bool:
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
    bench = read_bench()

    print("=" * 72)
    print("Validating research/folding/step_function_slh_dsa_128s.md numbers")
    print("=" * 72)

    # --- Check 1: SLH-DSA-128s parameters ---
    print("\n[1] SLH-DSA-128s parameters from circuits/common/params.circom")
    failures = 0
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
        reduce_checks = []
        for n in (14, 35, 64):
            expected_perms = poseidon_reduce_perm_count(n)
            expected_r1cs = expected_perms * p2_r1cs
            actual_r1cs = bench.get(f"bench_poseidon_reduce_{n}")
            if actual_r1cs is None:
                print(f"  [SKIP] bench_poseidon_reduce_{n} not measured")
                failures += 1
                continue
            chk = Check(
                name=f"PoseidonReduce({n}) = {expected_perms} × P(2)",
                expected=expected_r1cs,
                actual=actual_r1cs,
                tolerance_pct=1.0,
                units=" R1CS",
            )
            reduce_checks.append(chk)
            print(chk.report())
            if not chk.passed:
                failures += 1

    # --- Check 3: Per-verify Poseidon-permutation grand total ---
    print("\n[3] Per-verify Poseidon-perm derivation (design doc §3.3 claim: 4,273)")
    k_param, a_param = params["SLH_K"], params["SLH_A"]
    d_param, hp_param = params["SLH_D"], params["SLH_HPRIME"]
    len_param, w_param = params["SLH_LEN"], params["SLH_W"]

    # Per-primitive Poseidon-perm cost: 1 + PoseidonReduce(arity) for compress
    # primitives; 1 for F/H; 2 + reduce for HMsg.
    perms_per_F = 1
    perms_per_H = 1
    perms_per_Tk = 1 + poseidon_reduce_perm_count(k_param)              # 1 mix + reduce(k)
    perms_per_Tlen = 1 + poseidon_reduce_perm_count(len_param)          # 1 mix + reduce(len)
    perms_per_HMsg = 2 + poseidon_reduce_perm_count(64)                 # 2 mix + reduce(64) [M=1024B=64 FE]

    calls = {
        "F": k_param + d_param * len_param * (w_param - 1),     # FORS leaves + WOTS chain steps
        "H": k_param * a_param + d_param * hp_param,            # FORS auth + XMSS path
        "Tk": 1,
        "Tlen": d_param,
        "HMsg": 1,
    }
    perm_per_call = {
        "F": perms_per_F,
        "H": perms_per_H,
        "Tk": perms_per_Tk,
        "Tlen": perms_per_Tlen,
        "HMsg": perms_per_HMsg,
    }
    print(f"  Per-primitive call counts: {calls}")
    print(f"  Perms per call: {perm_per_call}")

    grand_total_perms = sum(calls[p] * perm_per_call[p] for p in calls)
    print(f"  Grand total Poseidon perms per verify = {grand_total_perms}")

    chk = Check(
        name="grand-total perms = 4,273",
        expected=4273,
        actual=grand_total_perms,
        tolerance_pct=0.0,
        units=" perms",
    )
    print(chk.report())
    if not chk.passed:
        failures += 1

    # --- Check 4: Σ(per-prim R1CS × call count) vs measured main_poseidon ---
    print("\n[4] Per-primitive R1CS × call counts vs measured main_poseidon")
    measured_per_prim = {
        "F": bench.get("bench_poseidon_F"),
        "H": bench.get("bench_poseidon_H"),
        "Tk": bench.get("bench_poseidon_Tk"),
        "Tlen": bench.get("bench_poseidon_Tlen"),
        "HMsg": bench.get("bench_poseidon_HMsg"),
    }
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
            tolerance_pct=2.0,
            units=" R1CS",
        )
        print(chk.report())
        if not chk.passed:
            failures += 1

    # --- Check 5: D2-c flat-IVC step cost (canonical for Week 2) ---
    print("\n[5] D2-c flat-IVC step cost (canonical for scheme_selection.md)")
    if p2_r1cs is None:
        print("  [SKIP] bench_poseidon_reduce2 missing")
    else:
        step_r1cs = p2_r1cs
        d2c_fold_count = grand_total_perms
        d2c_total = step_r1cs * d2c_fold_count
        reduction_pct = (1 - d2c_total / main_r1cs) * 100 if main_r1cs else 0
        print(f"  D2-c step circuit: 1× Poseidon(2) = {step_r1cs} R1CS")
        print(f"  D2-c fold count: {d2c_fold_count}")
        print(f"  D2-c total step work: {d2c_total:,} R1CS")
        if main_r1cs:
            print(f"  Reduction vs monolithic {main_r1cs:,}: {reduction_pct:.1f}%")
        # Sanity vs design-doc canonical numbers (post-validation).
        # Update these when the doc claims change; mismatch fires [STALE]
        # so the verifier doubles as a regression detector.
        DOC_CANONICAL = {
            "step R1CS": (240, step_r1cs),
            "total D2-c R1CS": (1_025_520, d2c_total),
            "reduction vs monolithic (%)": (74.3, reduction_pct),
        }
        for label, (claimed, measured) in DOC_CANONICAL.items():
            drift = (measured - claimed) / claimed * 100 if claimed else 0
            tag = "OK" if abs(drift) < 1 else "STALE"
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

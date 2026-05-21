"""Shared helpers for the SLH-DSA-128s R1CS tooling.

Both `parse_r1cs_stats.py` (generates `results/results_summary.md`) and
`verify_perm_counts.py` (validates the folding-research design doc against
measured benches) depend on:

  - parsing `results/raw_bench.txt`
  - reading SLH-DSA-128s parameters from `circuits/common/params.circom`
  - deriving per-primitive invocation counts from those parameters

Centralising these here keeps the two scripts in lockstep — if params change
(e.g. swap to 128f) both consumers update from the single source of truth.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PARAMS_FILE = ROOT / "circuits" / "common" / "params.circom"
RAW_BENCH = ROOT / "results" / "raw_bench.txt"


def parse_line(line: str) -> dict | None:
    """Parse one row of `raw_bench.txt`.

    Format: `<circuit> <OK|FAILED> key=value key=value …`
    Returns None for comments, blanks, and unmatched rows.
    """
    if line.startswith("#") or not line.strip():
        return None
    m = re.match(r"^(\S+)\s+(OK|FAILED)\s+(.*)$", line)
    if not m:
        return None
    name, status, rest = m.groups()
    fields = {"circuit": name, "status": status}
    for kv in rest.split():
        if "=" in kv:
            k, v = kv.split("=", 1)
            fields[k] = v
    return fields


def read_params() -> dict[str, int]:
    """Parse `function SLH_*() { return N; }` entries from params.circom."""
    text = PARAMS_FILE.read_text()
    return {
        m.group(1): int(m.group(2))
        for m in re.finditer(
            r"function\s+(SLH_\w+)\(\)\s*\{\s*return\s+(\d+)\s*;\s*\}", text
        )
    }


def read_bench_constraints() -> dict[str, int]:
    """Parse `raw_bench.txt` → {circuit: nConstraints} for OK rows only.

    Exits with a clear error if the bench file is missing — callers run
    after `yarn bench`, so an empty file means the user forgot that step.
    """
    if not RAW_BENCH.exists():
        sys.stderr.write(f"ERROR: {RAW_BENCH} missing — run `yarn bench` first.\n")
        sys.exit(1)
    out: dict[str, int] = {}
    for line in RAW_BENCH.read_text().splitlines():
        d = parse_line(line)
        if d and d["status"] == "OK" and "nConstraints" in d:
            out[d["circuit"]] = int(d["nConstraints"])
    return out


def compute_invocation_counts(params: dict[str, int]) -> dict[str, int]:
    """Per-verify call counts for the five SLH-DSA-128s primitives.

    Derived from FIPS 205 §11.2.2:
      - F: k FORS leaves + d·len·(w−1) WOTS chain steps
      - H: k·a FORS auth + d·h' XMSS Merkle
      - T_k: 1 FORS-root compress
      - T_len: d WOTS-pubkey compresses (one per HT layer)
      - H_msg: 1 per verify
    """
    k, a = params["SLH_K"], params["SLH_A"]
    d, hp = params["SLH_D"], params["SLH_HPRIME"]
    length, w = params["SLH_LEN"], params["SLH_W"]
    return {
        "F": k + d * length * (w - 1),
        "H": k * a + d * hp,
        "Tk": 1,
        "Tlen": d,
        "HMsg": 1,
    }


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

#!/usr/bin/env python3
"""Parse results/raw_bench.txt into a Markdown summary table at results/results.md."""

import sys
from pathlib import Path

from folding_lib import (
    RAW_BENCH,
    compute_invocation_counts,
    parse_line,
    read_params,
)

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "results" / "results_summary.md"


def main():
    if not RAW_BENCH.exists():
        print(f"raw_bench.txt not found at {RAW_BENCH}; run scripts/bench.sh first", file=sys.stderr)
        sys.exit(1)

    rows = []
    for line in RAW_BENCH.read_text().splitlines():
        d = parse_line(line)
        if d:
            rows.append(d)

    # Per-component table by family.
    primitives = ["F", "H", "Tk", "Tlen", "HMsg"]
    families = ["sha2", "shake", "poseidon"]
    table_lines = ["| Component | invocations |"]
    sub = ""
    for fam in families:
        table_lines[0] += f" {fam} (constraints/call) |"
        sub += "|" + "-" * 11
    table_lines.append("|" + "-" * 11 + "|" + "-" * 13 + sub + "|")

    # Derive invocation counts from params.circom (single source of truth shared
    # with scripts/verify_perm_counts.py). Avoids drift if params ever change.
    invocation_counts = compute_invocation_counts(read_params())

    rows_by_name = {r["circuit"]: r for r in rows}
    for prim in primitives:
        line = f"| {prim} | {invocation_counts[prim]} |"
        for fam in families:
            key = f"bench_{fam}_{prim}"
            r = rows_by_name.get(key)
            if r and r["status"] == "OK":
                line += f" {int(r['nConstraints']):,} |"
            else:
                line += f" — |"
        table_lines.append(line)

    # Totals (sum-of-parts).
    total_line = "| **Sum-of-parts** | — |"
    for fam in families:
        total = 0
        ok = True
        for prim in primitives:
            key = f"bench_{fam}_{prim}"
            r = rows_by_name.get(key)
            if r and r["status"] == "OK":
                total += int(r["nConstraints"]) * invocation_counts[prim]
            else:
                ok = False
                break
        total_line += f" {total:,} |" if ok else " — |"
    table_lines.append(total_line)

    # Integrated mains.
    integrated_lines = ["", "## Integrated full-main constraint counts", "", "| Family | Status | nConstraints | nWires | nPubIn | nPrvIn | .r1cs size |", "|--------|--------|-------------:|-------:|-------:|-------:|-----------:|"]
    for fam in families:
        key = f"main_{fam}"
        r = rows_by_name.get(key)
        if r and r["status"] == "OK":
            integrated_lines.append(
                f"| {fam} | OK | {int(r['nConstraints']):,} | {int(r['nWires']):,} | {r.get('nPubIn', '?')} | {r.get('nPrvIn', '?')} | {int(r.get('r1cs_size', 0)):,} B |"
            )
        else:
            status = r["status"] if r else "not_run"
            integrated_lines.append(f"| {fam} | {status} | — | — | — | — | — |")

    OUT.write_text(
        "# SLH-DSA-128s R1CS Per-Component Bench Summary\n\n"
        "Auto-generated from `results/raw_bench.txt` by `scripts/parse_r1cs_stats.py`.\n\n"
        "## Per-component constraint counts\n\n"
        + "\n".join(table_lines)
        + "\n"
        + "\n".join(integrated_lines)
        + "\n"
    )
    print(f"Wrote {OUT}")


if __name__ == "__main__":
    main()

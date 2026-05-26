//! Smoke test — Day 3 Gate-3 deliverable.
//!
//! Parses a Circom `.r1cs` + `.wtns` for `bench_poseidon_gl_reduce2`, lifts
//! into LatticeFold's `R1CS<GoldilocksRingNTT>`, builds a `CCS<GoldilocksRingNTT>`
//! via `CCS::from_r1cs`, and asserts that `ccs.check_relation(&z)` returns Ok
//! on a witness produced by `npx circomkit witness` (or direct `node generate_witness.js`).
//!
//! Run:
//!   cargo run --release --bin smoke -- \
//!     --r1cs $REPO/build/poseidon_gl_bench/bench_poseidon_gl_reduce2/bench_poseidon_gl_reduce2.r1cs \
//!     --wtns $REPO/build/poseidon_gl_bench/bench_poseidon_gl_reduce2/all_zeros.wtns
//!
//! Exit 0 on PASS.

use anyhow::{Context, Result};
use clap::Parser;
use latticefold::arith::{Arith, CCS};
use r1cs_latticefold::{
    circom_r1cs_to_latticefold, circom_witness_to_latticefold, parse_circom_r1cs,
    parse_circom_wtns,
};
use std::path::PathBuf;
use std::time::Instant;

#[derive(Debug, Parser)]
#[command(name = "smoke", about = "Circom R1CS+wtns → LatticeFold CCS smoke test.")]
struct Args {
    #[arg(long)]
    r1cs: PathBuf,
    #[arg(long)]
    wtns: PathBuf,
}

fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();

    println!("=== Parse phase ===");
    let t0 = Instant::now();
    let circom_r1cs = parse_circom_r1cs(&args.r1cs)
        .with_context(|| format!("parsing {}", args.r1cs.display()))?;
    let circom_wtns = parse_circom_wtns(&args.wtns)
        .with_context(|| format!("parsing {}", args.wtns.display()))?;
    println!("  parsed .r1cs + .wtns in {:?}", t0.elapsed());
    println!("  n_constraints: {}", circom_r1cs.n_constraints);
    println!("  n_wires:       {} (r1cs) / {} (wtns)", circom_r1cs.n_wires, circom_wtns.n_wires);
    println!("  n_pub_out:     {}", circom_r1cs.n_pub_out);
    println!("  n_pub_in:      {}", circom_r1cs.n_pub_in);
    if circom_r1cs.n_wires != circom_wtns.n_wires {
        anyhow::bail!(
            "wire-count mismatch: r1cs={}, wtns={}",
            circom_r1cs.n_wires,
            circom_wtns.n_wires
        );
    }

    println!("=== Lift phase (Goldilocks → RqNTT) ===");
    let t1 = Instant::now();
    let lf_r1cs = circom_r1cs_to_latticefold(&circom_r1cs)?;
    let z = circom_witness_to_latticefold(&circom_wtns)?;
    println!("  lifted in {:?}", t1.elapsed());
    println!("  lf_r1cs.l (public surface): {}", lf_r1cs.l);
    println!(
        "  lf_r1cs.A: {} × {} ({} nnz)",
        lf_r1cs.A.nrows,
        lf_r1cs.A.ncols,
        lf_r1cs.A.coeffs.iter().map(|r| r.len()).sum::<usize>()
    );
    println!("  z.len(): {}", z.len());

    println!("=== check_relation on R1CS ===");
    let t2 = Instant::now();
    let r1cs_check = lf_r1cs.check_relation(&z);
    println!("  R1CS::check_relation -> {:?} (in {:?})", r1cs_check, t2.elapsed());
    if r1cs_check.is_err() {
        anyhow::bail!("FAIL: R1CS::check_relation returned Err — Circom witness is not satisfying the LatticeFold-form R1CS");
    }

    println!("=== Build CCS from R1CS ===");
    let t3 = Instant::now();
    // CCS::from_r1cs takes W = matrix row count (i.e., m). For our circuit m = n_constraints.
    let w_param = circom_r1cs.n_constraints as usize;
    let ccs: CCS<_> = CCS::from_r1cs(lf_r1cs, w_param);
    println!("  CCS built in {:?}", t3.elapsed());
    println!("  ccs.m: {}", ccs.m);
    println!("  ccs.n: {}", ccs.n);
    println!("  ccs.l: {}", ccs.l);
    println!("  ccs.t: {}, q: {}, d: {}", ccs.t, ccs.q, ccs.d);

    println!("=== check_relation on CCS ===");
    let t4 = Instant::now();
    let ccs_check = ccs.check_relation(&z);
    println!("  CCS::check_relation -> {:?} (in {:?})", ccs_check, t4.elapsed());
    if ccs_check.is_err() {
        anyhow::bail!("FAIL: CCS::check_relation returned Err");
    }

    println!();
    println!(
        "RESULT: PASS — Circom R1CS + witness lift cleanly into LatticeFold and \
         satisfy both R1CS::check_relation and CCS::check_relation."
    );
    Ok(())
}

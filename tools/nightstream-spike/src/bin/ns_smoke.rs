//! Day-5 Phase B smoke: feed a Circom-derived R1CS + witness into Nightstream's
//! r1cs_to_ccs and run the row-wise CCS relation check.

use anyhow::{Context, Result};
use clap::Parser;
use neo_ccs::relations::check_ccs_rowwise_zero;
use nightstream_spike::{build_ccs, build_ccs_sparse, circom_witness_to_f, parser};
use std::path::PathBuf;
use std::time::Instant;

#[derive(Debug, Parser)]
#[command(name = "ns_smoke", about = "Circom R1CS → Nightstream CCS smoke test.")]
struct Args {
    #[arg(long)]
    r1cs: PathBuf,
    #[arg(long)]
    wtns: PathBuf,
    /// Use the sparse CSC path. Required for circuits beyond ~10K wires;
    /// dense Mat<F> would OOM at HtLayerStep scale.
    #[arg(long)]
    sparse: bool,
}

fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();

    println!("=== 1/4 Parse Circom .r1cs + .wtns ===");
    let t = Instant::now();
    let circom_r1cs = parser::parse_circom_r1cs(&args.r1cs)
        .with_context(|| format!("parsing {}", args.r1cs.display()))?;
    let circom_wtns = parser::parse_circom_wtns(&args.wtns)
        .with_context(|| format!("parsing {}", args.wtns.display()))?;
    println!(
        "  parsed in {:?}: n_constraints={}, n_wires={}/{}, n_pub_out={}, n_pub_in={}",
        t.elapsed(),
        circom_r1cs.n_constraints,
        circom_r1cs.n_wires,
        circom_wtns.n_wires,
        circom_r1cs.n_pub_out,
        circom_r1cs.n_pub_in,
    );
    if circom_r1cs.n_wires != circom_wtns.n_wires {
        anyhow::bail!(
            "wire count mismatch: r1cs={}, wtns={}",
            circom_r1cs.n_wires,
            circom_wtns.n_wires
        );
    }

    println!(
        "=== 2/4 Lift to neo_ccs::{} + build CcsStructure ===",
        if args.sparse { "CcsMatrix (sparse CSC)" } else { "Mat<F> (dense)" }
    );
    let t = Instant::now();
    let (ccs, l, n_cols) = if args.sparse {
        build_ccs_sparse(&circom_r1cs)?
    } else {
        build_ccs(&circom_r1cs)?
    };
    let z = circom_witness_to_f(&circom_wtns)?;
    println!(
        "  built CCS in {:?}: t={}, max_degree={}, l(public surface)={}, n={}",
        t.elapsed(),
        ccs.t(),
        ccs.max_degree(),
        l,
        n_cols,
    );

    println!("=== 3/4 Split z into (x, w) ===");
    let x: Vec<_> = z[..l + 1].to_vec();
    let w: Vec<_> = z[l + 1..].to_vec();
    println!("  x.len()={} (incl. constant 1 at index 0), w.len()={}", x.len(), w.len());

    println!("=== 4/4 check_ccs_rowwise_zero ===");
    let t = Instant::now();
    let result = check_ccs_rowwise_zero(&ccs, &x, &w);
    println!("  result: {:?} (in {:?})", result, t.elapsed());

    match result {
        Ok(()) => {
            println!();
            println!("RESULT: PASS — Circom R1CS lifts cleanly into Nightstream's CCS form; row-wise relation check holds.");
        }
        Err(e) => {
            println!();
            println!("RESULT: FAIL — {:?}", e);
            std::process::exit(1);
        }
    }
    Ok(())
}

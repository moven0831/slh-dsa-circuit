//! Negative-test smoke — runs both R1CS::check_relation and CCS::check_relation
//! on a (possibly corrupt) witness without bailing early. Reports outcomes for
//! both; exits 0 on success (i.e., on independent verification that the lift
//! detected the corruption). Used by the Day-3 importer review to confirm that
//! the parser+lift actually catches mismatches, not silently passes.

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
#[command(name = "smoke_neg", about = "Negative-test variant of smoke: never bails on Err.")]
struct Args {
    #[arg(long)]
    r1cs: PathBuf,
    #[arg(long)]
    wtns: PathBuf,
}

fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();

    let t0 = Instant::now();
    let circom_r1cs = parse_circom_r1cs(&args.r1cs)
        .with_context(|| format!("parsing {}", args.r1cs.display()))?;
    let circom_wtns = parse_circom_wtns(&args.wtns)
        .with_context(|| format!("parsing {}", args.wtns.display()))?;
    println!("parsed .r1cs + .wtns in {:?}", t0.elapsed());
    println!("n_constraints: {}", circom_r1cs.n_constraints);
    println!("n_wires:       {} (r1cs) / {} (wtns)", circom_r1cs.n_wires, circom_wtns.n_wires);

    let lf_r1cs = circom_r1cs_to_latticefold(&circom_r1cs)?;
    let z = circom_witness_to_latticefold(&circom_wtns)?;

    let t1 = Instant::now();
    let r1cs_check = lf_r1cs.check_relation(&z);
    println!("R1CS::check_relation -> {:?} (in {:?})", r1cs_check, t1.elapsed());

    let w_param = circom_r1cs.n_constraints as usize;
    let ccs: CCS<_> = CCS::from_r1cs(lf_r1cs, w_param);
    let t2 = Instant::now();
    let ccs_check = ccs.check_relation(&z);
    println!("CCS::check_relation  -> {:?} (in {:?})", ccs_check, t2.elapsed());

    Ok(())
}

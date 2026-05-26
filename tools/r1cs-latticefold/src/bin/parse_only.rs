//! Standalone CLI that loads a Circom .r1cs (+ optionally .wtns) and prints
//! header info, sanity-checking the binary parsers. Stage-1 build target —
//! does NOT depend on LatticeFold.

use anyhow::Result;
use clap::Parser;
use r1cs_latticefold::{parse_circom_r1cs, parse_circom_wtns};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "parse_only", about = "Parse a Circom .r1cs + .wtns and print header summary.")]
struct Args {
    /// Path to the .r1cs file.
    #[arg(long)]
    r1cs: PathBuf,
    /// Optional path to the .wtns file (for sanity-checking the witness shape).
    #[arg(long)]
    wtns: Option<PathBuf>,
}

fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();

    let r1cs = parse_circom_r1cs(&args.r1cs)?;
    println!("R1CS file: {}", args.r1cs.display());
    println!("  field_size_bytes: {}", r1cs.field_size_bytes);
    println!("  prime (first 8 LE bytes): {:02x?}", &r1cs.prime_le_bytes[..r1cs.prime_le_bytes.len().min(8)]);
    println!("  n_wires:         {}", r1cs.n_wires);
    println!("  n_pub_out:       {}", r1cs.n_pub_out);
    println!("  n_pub_in:        {}", r1cs.n_pub_in);
    println!("  n_priv_in:       {}", r1cs.n_priv_in);
    println!("  n_labels:        {}", r1cs.n_labels);
    println!("  n_constraints:   {}", r1cs.n_constraints);
    println!(
        "  A nnz total:     {}",
        r1cs.a.iter().map(|row| row.len()).sum::<usize>()
    );
    println!(
        "  B nnz total:     {}",
        r1cs.b.iter().map(|row| row.len()).sum::<usize>()
    );
    println!(
        "  C nnz total:     {}",
        r1cs.c.iter().map(|row| row.len()).sum::<usize>()
    );

    if let Some(path) = args.wtns.as_ref() {
        let wtns = parse_circom_wtns(path)?;
        println!("WTNS file: {}", path.display());
        println!("  field_size_bytes: {}", wtns.field_size_bytes);
        println!("  n_wires:         {}", wtns.n_wires);
        if wtns.n_wires > 0 {
            // First wire is always the constant 1.
            let w0 = wtns.wire_u64(0).unwrap_or(u64::MAX);
            println!("  wire[0]:         {} (expected 1)", w0);
        }
        if wtns.n_wires >= 3 && wtns.field_size_bytes <= 8 {
            // For the reduce2 smoke: wire[1] = out_lo, wire[2] = out_hi.
            let lo = wtns.wire_u64(1)?;
            let hi = wtns.wire_u64(2)?;
            println!("  wire[1] (out_lo): 0x{:016x}", lo);
            println!("  wire[2] (out_hi): 0x{:016x}", hi);
        }
    }

    Ok(())
}

//! Day-4 Phase-B: full NIFSProver::prove invocation on a real Circom-derived
//! R1CS + witness, using LatticeFold's example default decomposition parameters
//! (Goldilocks: B=2^15, L=5, B_SMALL=2, K=15, KAPPA=4).
//!
//! Day-4 finding (commit b985c08+):
//!   Prove SUCCEEDS — generates a 133 KB proof in ~219 ms on bench_poseidon_gl_reduce2
//!   (440 constraints, post-pad m=4096, ajtai_n=2210). Ajtai + Witness::from_w_ccs +
//!   LFLinearizationProver + NIFSProver::prove all complete cleanly.
//!
//!   Verify FAILS — `linearization sum-check sum mismatch`. Root cause: `CCS::from_r1cs`
//!   produces a degree-2 CCS (`t=3, q=2, d=2`, S=[[0,1],[2]]), but LatticeFold's NIFS
//!   protocol expects the degree-3 form (`d=3, q=3`) used by
//!   `get_test_dummy_degree_three_ccs_non_scalar`. Upstream `examples/e2e.rs`
//!   verifies in 39 ms with its degree-3 CCS; the verifier's reconstruction of the
//!   linearization sum is well-defined only for d=3+. The R1CS-derived d=2 CCS is
//!   structurally correct for `check_relation` (matrix relation holds) but the NIFS
//!   sumcheck protocol's expected-sum formula doesn't reduce correctly through it.
//!
//! Resolution paths (Week-3+):
//!   1. Wrap our degree-2 CCS in a degree-3 form by lifting (A·z) * (B·z) = (C·z)
//!      as ((A·z) * (B·z)) * 1 = (C·z) * 1 — adds redundant degree, may or may not
//!      satisfy NIFS's structural assumptions.
//!   2. Use LatticeFold+ (NethermindEth/latticefold WIP) — may natively handle d=2.
//!   3. Switch to a folding scheme that supports R1CS directly (Neo/SuperNeo via
//!      Nightstream — the Day-5 measurement-spike target).

use anyhow::{Context, Result};
use ark_serialize::{CanonicalSerialize, Compress};
use clap::Parser;
use cyclotomic_rings::{
    challenge_set::LatticefoldChallengeSet,
    rings::{GoldilocksChallengeSet, GoldilocksRingNTT, SuitableRing},
};
use latticefold::{
    arith::{Arith, Witness, CCCS, CCS},
    commitment::AjtaiCommitmentScheme,
    decomposition_parameters::DecompositionParams,
    nifs::{
        linearization::{LFLinearizationProver, LinearizationProver},
        NIFSProver, NIFSVerifier,
    },
    transcript::poseidon::PoseidonTranscript,
};
use r1cs_latticefold::load_circom_for_latticefold;
use std::path::PathBuf;
use std::time::Instant;

/// LatticeFold example defaults for Goldilocks (build.rs PARAM_* env vars).
#[derive(Clone)]
struct GoldilocksDP;

impl DecompositionParams for GoldilocksDP {
    const B: u128 = 1 << 15;
    const L: usize = 5;
    const B_SMALL: usize = 2;
    const K: usize = 15;
}

const KAPPA: usize = 4;

#[derive(Debug, Parser)]
#[command(name = "fold_step", about = "Attempt one NIFSProver::prove fold step on a Circom R1CS + witness.")]
struct Args {
    #[arg(long)]
    r1cs: PathBuf,
    #[arg(long)]
    wtns: PathBuf,
}

type RqNTT = GoldilocksRingNTT;
type CS = GoldilocksChallengeSet;
type T = PoseidonTranscript<RqNTT, CS>;

fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();

    let total = Instant::now();

    println!("=== 1/6 Parse Circom .r1cs + .wtns + lift ===");
    let t = Instant::now();
    let (lf_r1cs, z) = load_circom_for_latticefold(&args.r1cs, &args.wtns)
        .context("load_circom_for_latticefold")?;
    println!(
        "  done in {:?}: l={}, n={}, m={}, z.len()={}",
        t.elapsed(),
        lf_r1cs.l,
        lf_r1cs.A.ncols(),
        lf_r1cs.A.nrows(),
        z.len()
    );

    println!("=== 2/6 Build CCS ===");
    let t = Instant::now();
    let w_param = lf_r1cs.A.nrows();
    let ccs: CCS<RqNTT> = CCS::from_r1cs_padded(lf_r1cs, w_param, GoldilocksDP::L);
    println!(
        "  done in {:?}: m={} (padded), n={}, l={}",
        t.elapsed(),
        ccs.m,
        ccs.n,
        ccs.l
    );

    println!("=== 3/6 Pre-flight: ccs.check_relation(&z) ===");
    let t = Instant::now();
    let pre_check = ccs.check_relation(&z);
    println!("  result: {:?} (in {:?})", pre_check, t.elapsed());
    if let Err(e) = pre_check {
        anyhow::bail!(
            "CCS::check_relation failed BEFORE prove — witness is not satisfying after padding: {:?}",
            e
        );
    }

    println!("=== 4/6 Split z → (one, x_ccs, w_ccs) per LatticeFold convention ===");
    // z layout: z[0]=1, z[1..=l]=public surface, z[l+1..]=private witness.
    let one = z[0];
    let x_ccs: Vec<RqNTT> = z[1..1 + ccs.l].to_vec();
    let w_ccs: Vec<RqNTT> = z[1 + ccs.l..].to_vec();
    println!(
        "  one (z[0]) is_one: {}; x_ccs.len()={}, w_ccs.len()={}",
        one == RqNTT::from(1u64),
        x_ccs.len(),
        w_ccs.len()
    );

    println!("=== 5/6 Setup commitment scheme + initial accumulator ===");
    let t = Instant::now();
    let mut rng = ark_std::test_rng();
    // Ajtai scheme `n` must equal the gadget-decomposed witness length =
    // w_ccs.len() * L (each ring element is split into L base-B digits before
    // committing). Sizing it as ccs.n (the un-decomposed wire count) fails
    // with "Wrong length of the witness: 2210, expected: 445" because
    // Witness::from_w_ccs has already expanded by L.
    let ajtai_n = w_ccs.len() * GoldilocksDP::L;
    let scheme: AjtaiCommitmentScheme<RqNTT> = AjtaiCommitmentScheme::rand(KAPPA, ajtai_n, &mut rng);
    let wit: Witness<RqNTT> = Witness::from_w_ccs::<GoldilocksDP>(w_ccs.clone());
    println!("  scheme + witness built in {:?} (ajtai_n = w_ccs.len() * L = {})", t.elapsed(), ajtai_n);

    let t = Instant::now();
    let cm_i: CCCS<RqNTT> = CCCS {
        cm: wit
            .commit::<GoldilocksDP>(&scheme)
            .context("wit.commit (Ajtai)")?,
        x_ccs: x_ccs.clone(),
    };
    println!("  CCCS (commitment + x_ccs) built in {:?}", t.elapsed());

    // Initial accumulator: linearize cm_i against ITS OWN witness.
    // (Day-4 review caught this: upstream e2e.rs uses a random rand_w_ccs because
    // its `cm_i` was already committed with `wit`, and the linearization just
    // produces an LCCCS *structure* using cm_i.cm + wit_acc's MLE evaluations.
    // But that pattern produces inconsistent LCCCS in our setup — acc.cm attests
    // to `wit` while acc.u encodes wit_acc's evaluations, breaking the verifier's
    // recomputation. Fix: use the real witness as wit_acc so acc.cm and acc.u
    // both correspond to the same w_ccs.)
    let t = Instant::now();
    let wit_acc = Witness::from_w_ccs::<GoldilocksDP>(w_ccs.clone());
    let mut setup_transcript = PoseidonTranscript::<RqNTT, CS>::default();
    let (acc, _) = LFLinearizationProver::<_, T>::prove(&cm_i, &wit_acc, &mut setup_transcript, &ccs)
        .context("LFLinearizationProver::prove (setup)")?;
    println!("  initial accumulator (linearization) in {:?}", t.elapsed());

    println!("=== 6/6 NIFSProver::prove (the fold step) ===");
    let t = Instant::now();
    let mut prover_transcript = PoseidonTranscript::<RqNTT, CS>::default();
    let (_, _, proof) = NIFSProver::<RqNTT, GoldilocksDP, T>::prove(
        &acc,
        &wit_acc,
        &cm_i,
        &wit,
        &mut prover_transcript,
        &ccs,
        &scheme,
    )
    .context("NIFSProver::prove")?;
    println!("  proof generated in {:?}", t.elapsed());

    // Proof size (compressed + uncompressed).
    let mut buf_c = Vec::new();
    proof.serialize_with_mode(&mut buf_c, Compress::Yes)?;
    let mut buf_u = Vec::new();
    proof.serialize_with_mode(&mut buf_u, Compress::No)?;
    println!(
        "  proof size: {} B compressed / {} B uncompressed",
        buf_c.len(),
        buf_u.len()
    );

    println!("=== Verify ===");
    let t = Instant::now();
    let mut verifier_transcript = PoseidonTranscript::<RqNTT, CS>::default();
    NIFSVerifier::<RqNTT, GoldilocksDP, T>::verify(&acc, &cm_i, &proof, &mut verifier_transcript, &ccs)
        .context("NIFSVerifier::verify")?;
    println!("  verified in {:?}", t.elapsed());

    println!();
    println!("RESULT: PASS — full NIFS fold step completed end-to-end in {:?}", total.elapsed());
    Ok(())
}

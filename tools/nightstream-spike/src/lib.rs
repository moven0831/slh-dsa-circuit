//! Day-5 measurement-spike for LFDT-Nightstream / Neo folding. Parses Circom
//! Goldilocks .r1cs + .wtns, lifts coefficients into `neo_math::F`, builds
//! `neo_ccs::Mat<F>` triplet, and feeds them to `neo_ccs::r1cs::r1cs_to_ccs`.
//!
//! Side-by-side counterpart to `tools/r1cs-latticefold` (Day 3-4). LatticeFold's
//! pipeline reached the relation-check level cleanly but ran into a verify-side
//! blocker at NIFSProver::prove + NIFSVerifier::verify (see
//! research/folding/poseidon_gl_audit.md §6b). Nightstream uses a different
//! folding scheme (Neo).

#![forbid(unsafe_code)]

pub mod parser;

use anyhow::{bail, Result};
use neo_ccs::matrix::Mat;
use neo_ccs::relations::CcsStructure;
use neo_math::F;
use p3_field::PrimeCharacteristicRing;

/// Convert a Circom-parsed R1CS (Goldilocks, 8-byte LE coefficients) into a
/// `neo_ccs::Mat<F>` triplet plus the public-input length `l`.
pub fn circom_to_nightstream_mats(
    circom: &parser::CircomR1cs,
) -> Result<(Mat<F>, Mat<F>, Mat<F>, usize, usize)> {
    if circom.field_size_bytes != 8 {
        bail!(
            "expected Goldilocks-sized field (8 bytes), got {}",
            circom.field_size_bytes
        );
    }
    let n_cols = circom.n_wires as usize;
    let m_rows = circom.n_constraints as usize;
    let l = (circom.n_pub_in + circom.n_pub_out) as usize;

    let mat_from = |rows: &[Vec<(u32, Vec<u8>)>]| -> Result<Mat<F>> {
        let mut data: Vec<F> = vec![F::ZERO; m_rows * n_cols];
        for (i, row) in rows.iter().enumerate() {
            for (wire_idx, coeff_bytes) in row {
                let v = coeff_to_f(coeff_bytes)?;
                data[i * n_cols + (*wire_idx as usize)] = v;
            }
        }
        Ok(Mat::<F>::from_row_major(m_rows, n_cols, data))
    };

    let a = mat_from(&circom.a)?;
    let b = mat_from(&circom.b)?;
    let c = mat_from(&circom.c)?;
    Ok((a, b, c, l, n_cols))
}

pub fn circom_witness_to_f(wtns: &parser::CircomWitness) -> Result<Vec<F>> {
    if wtns.field_size_bytes != 8 {
        bail!("expected Goldilocks-sized witness, got {}", wtns.field_size_bytes);
    }
    wtns.wires_le_bytes.iter().map(|w| coeff_to_f(w)).collect()
}

fn coeff_to_f(bytes: &[u8]) -> Result<F> {
    if bytes.len() != 8 {
        bail!("expected 8-byte coefficient, got {}", bytes.len());
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(bytes);
    let v = u64::from_le_bytes(buf);
    Ok(F::from_u64(v))
}

/// Build a Nightstream CcsStructure from a parsed Circom R1CS (dense path).
/// Memory: O(rows × cols) — only viable for circuits up to ~10K wires.
pub fn build_ccs(circom: &parser::CircomR1cs) -> Result<(CcsStructure<F>, usize, usize)> {
    let (a, b, c, l, n_cols) = circom_to_nightstream_mats(circom)?;
    let ccs = neo_ccs::r1cs::r1cs_to_ccs::<F>(a, b, c);
    Ok((ccs, l, n_cols))
}

/// Build a Nightstream CcsStructure from a parsed Circom R1CS using the sparse
/// CSC path. Required for circuits beyond ~10K wires; HtLayerStep (486K
/// constraints × 467K wires × 1.8M nnz) needs this.
pub fn build_ccs_sparse(circom: &parser::CircomR1cs) -> Result<(CcsStructure<F>, usize, usize)> {
    use neo_ccs::sparse::CcsMatrix;
    if circom.field_size_bytes != 8 {
        bail!(
            "expected Goldilocks-sized field (8 bytes), got {}",
            circom.field_size_bytes
        );
    }
    let n_cols = circom.n_wires as usize;
    let m_rows = circom.n_constraints as usize;
    let l = (circom.n_pub_in + circom.n_pub_out) as usize;

    let mat_from = |rows: &[Vec<(u32, Vec<u8>)>]| -> Result<CcsMatrix<F>> {
        let mut triplets: Vec<(usize, usize, F)> = Vec::new();
        for (i, row) in rows.iter().enumerate() {
            for (wire_idx, coeff_bytes) in row {
                let v = coeff_to_f(coeff_bytes)?;
                triplets.push((i, *wire_idx as usize, v));
            }
        }
        // CcsMatrix is an enum: Identity | Csc(CscMat). For arbitrary R1CS use Csc.
        Ok(CcsMatrix::Csc(neo_ccs::sparse::CscMat::from_triplets(
            triplets, m_rows, n_cols,
        )))
    };

    let a = mat_from(&circom.a)?;
    let b = mat_from(&circom.b)?;
    let c = mat_from(&circom.c)?;
    let ccs = neo_ccs::r1cs::sparse_r1cs_to_ccs::<F>(a, b, c)
        .map_err(|e| anyhow::anyhow!("sparse_r1cs_to_ccs: {:?}", e))?;
    Ok((ccs, l, n_cols))
}

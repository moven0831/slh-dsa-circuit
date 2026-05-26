//! Circom `.r1cs` + `.wtns` binary parsers + LatticeFold CCS importer.
//!
//! # Format references
//! - R1CS binary: <https://github.com/iden3/r1csfile/blob/master/doc/r1cs_bin_format.md>
//! - Witness binary: <https://github.com/iden3/snarkjs/blob/master/src/wtns_format.md>
//!
//! # Public surface
//! - [`parse_circom_r1cs`]: read a Circom binary R1CS into a field-agnostic triplet
//!   of sparse matrices + headers.
//! - [`parse_circom_wtns`]: read a Circom binary witness vector.
//! - [`circom_r1cs_to_latticefold`]: wrap a Goldilocks-parsed Circom R1CS into
//!   `latticefold::arith::R1CS<GoldilocksRingNTT>` — each scalar lifted to a
//!   degree-0 cyclotomic ring element via `GoldilocksRingNTT::from(u64)`.
//! - [`circom_witness_to_latticefold`]: same lift for the witness vector.

#![deny(unsafe_code)]
#![warn(rust_2018_idioms)]

use anyhow::{anyhow, bail, Context, Result};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use cyclotomic_rings::rings::GoldilocksRingNTT;
use latticefold::arith::r1cs::R1CS;
use num_traits::Zero;
use stark_rings_linalg::SparseMatrix;

// ----- Constants from the binary R1CS spec -----

const R1CS_MAGIC: [u8; 4] = *b"r1cs";
const WTNS_MAGIC: [u8; 4] = *b"wtns";

const R1CS_SECTION_HEADER: u32 = 1;
const R1CS_SECTION_CONSTRAINTS: u32 = 2;
// Wire-to-label mapping is section 3; we ignore it for this prototype.

const WTNS_SECTION_HEADER: u32 = 1;
const WTNS_SECTION_DATA: u32 = 2;

// ----- Public types -----

/// A parsed Circom binary `.r1cs` file.
///
/// Matrices are stored as **sparse row-major triplets**: each constraint i is
/// the equation `A[i] · z * B[i] · z = C[i] · z` where `·` denotes the dot
/// product over the field, and each `A[i]`/`B[i]`/`C[i]` is a list of
/// `(wire_index, coefficient_bytes)` pairs. Coefficients are kept as
/// little-endian byte vectors of length `field_size` — the caller picks a
/// field type to interpret them as (Goldilocks = 8 bytes, secq256r1 = 32).
#[derive(Debug, Clone)]
pub struct CircomR1cs {
    pub field_size_bytes: u32,
    pub prime_le_bytes: Vec<u8>,
    pub n_wires: u32,
    pub n_pub_out: u32,
    pub n_pub_in: u32,
    pub n_priv_in: u32,
    pub n_labels: u64,
    pub n_constraints: u32,
    /// A[i], B[i], C[i] are each `Vec<(wire_idx, coeff_bytes)>` of length `field_size_bytes`.
    pub a: Vec<Vec<(u32, Vec<u8>)>>,
    pub b: Vec<Vec<(u32, Vec<u8>)>>,
    pub c: Vec<Vec<(u32, Vec<u8>)>>,
}

/// A parsed Circom binary `.wtns` file. Wires are stored as full field
/// elements of length `field_size_bytes` (little-endian).
#[derive(Debug, Clone)]
pub struct CircomWitness {
    pub field_size_bytes: u32,
    pub prime_le_bytes: Vec<u8>,
    pub n_wires: u32,
    pub wires_le_bytes: Vec<Vec<u8>>,
}

impl CircomWitness {
    /// Convenience: read wire `i` as a little-endian `u64`. Only valid for
    /// `field_size_bytes ≤ 8` (i.e., Goldilocks-class fields).
    pub fn wire_u64(&self, i: usize) -> Result<u64> {
        let w = self
            .wires_le_bytes
            .get(i)
            .ok_or_else(|| anyhow!("wire index {} out of range ({} wires)", i, self.n_wires))?;
        if w.len() > 8 {
            bail!("wire_u64 called on a wider-than-8-byte field ({} bytes)", w.len());
        }
        let mut buf = [0u8; 8];
        buf[..w.len()].copy_from_slice(w);
        Ok(u64::from_le_bytes(buf))
    }
}

// ----- R1CS parser -----

/// Read a Circom binary `.r1cs` file at `path`.
pub fn parse_circom_r1cs(path: &Path) -> Result<CircomR1cs> {
    let mut f = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mut magic = [0u8; 4];
    f.read_exact(&mut magic)?;
    if magic != R1CS_MAGIC {
        bail!("not a Circom r1cs file: magic {:?} != {:?}", magic, R1CS_MAGIC);
    }
    let version = read_u32_le(&mut f)?;
    if version != 1 {
        bail!("unsupported r1cs version {}", version);
    }
    let n_sections = read_u32_le(&mut f)?;

    let mut header: Option<R1csHeader> = None;
    let mut constraints_offset: Option<u64> = None;
    let mut constraints_size: Option<u64> = None;

    // First pass: scan section table, capture header + remember constraints offset.
    for _ in 0..n_sections {
        let section_type = read_u32_le(&mut f)?;
        let section_size = read_u64_le(&mut f)?;
        let section_start = f.stream_position()?;
        match section_type {
            R1CS_SECTION_HEADER => {
                header = Some(parse_r1cs_header(&mut f)?);
                // Skip the rest of the header section if any (shouldn't be any).
                f.seek(SeekFrom::Start(section_start + section_size))?;
            }
            R1CS_SECTION_CONSTRAINTS => {
                constraints_offset = Some(section_start);
                constraints_size = Some(section_size);
                f.seek(SeekFrom::Start(section_start + section_size))?;
            }
            _ => {
                // Skip unknown sections (e.g., wire-to-label map).
                f.seek(SeekFrom::Start(section_start + section_size))?;
            }
        }
    }

    let header = header.ok_or_else(|| anyhow!("r1cs file is missing the header section"))?;
    let constraints_offset = constraints_offset
        .ok_or_else(|| anyhow!("r1cs file is missing the constraints section"))?;
    let _constraints_size = constraints_size.unwrap();

    // Second pass: read constraints.
    f.seek(SeekFrom::Start(constraints_offset))?;
    let mut a = Vec::with_capacity(header.n_constraints as usize);
    let mut b = Vec::with_capacity(header.n_constraints as usize);
    let mut c = Vec::with_capacity(header.n_constraints as usize);
    for _ in 0..header.n_constraints {
        let av = read_linear_combo(&mut f, header.field_size_bytes)?;
        let bv = read_linear_combo(&mut f, header.field_size_bytes)?;
        let cv = read_linear_combo(&mut f, header.field_size_bytes)?;
        a.push(av);
        b.push(bv);
        c.push(cv);
    }

    Ok(CircomR1cs {
        field_size_bytes: header.field_size_bytes,
        prime_le_bytes: header.prime_le_bytes,
        n_wires: header.n_wires,
        n_pub_out: header.n_pub_out,
        n_pub_in: header.n_pub_in,
        n_priv_in: header.n_priv_in,
        n_labels: header.n_labels,
        n_constraints: header.n_constraints,
        a,
        b,
        c,
    })
}

struct R1csHeader {
    field_size_bytes: u32,
    prime_le_bytes: Vec<u8>,
    n_wires: u32,
    n_pub_out: u32,
    n_pub_in: u32,
    n_priv_in: u32,
    n_labels: u64,
    n_constraints: u32,
}

fn parse_r1cs_header(f: &mut File) -> Result<R1csHeader> {
    let field_size_bytes = read_u32_le(f)?;
    let mut prime_le_bytes = vec![0u8; field_size_bytes as usize];
    f.read_exact(&mut prime_le_bytes)?;
    let n_wires = read_u32_le(f)?;
    let n_pub_out = read_u32_le(f)?;
    let n_pub_in = read_u32_le(f)?;
    let n_priv_in = read_u32_le(f)?;
    let n_labels = read_u64_le(f)?;
    let n_constraints = read_u32_le(f)?;
    Ok(R1csHeader {
        field_size_bytes,
        prime_le_bytes,
        n_wires,
        n_pub_out,
        n_pub_in,
        n_priv_in,
        n_labels,
        n_constraints,
    })
}

fn read_linear_combo(f: &mut File, field_size_bytes: u32) -> Result<Vec<(u32, Vec<u8>)>> {
    let n_terms = read_u32_le(f)?;
    let mut out = Vec::with_capacity(n_terms as usize);
    for _ in 0..n_terms {
        let wire_idx = read_u32_le(f)?;
        let mut coeff = vec![0u8; field_size_bytes as usize];
        f.read_exact(&mut coeff)?;
        out.push((wire_idx, coeff));
    }
    Ok(out)
}

// ----- Witness parser -----

/// Read a Circom binary `.wtns` file at `path`.
pub fn parse_circom_wtns(path: &Path) -> Result<CircomWitness> {
    let mut f = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mut magic = [0u8; 4];
    f.read_exact(&mut magic)?;
    if magic != WTNS_MAGIC {
        bail!("not a Circom wtns file: magic {:?} != {:?}", magic, WTNS_MAGIC);
    }
    let version = read_u32_le(&mut f)?;
    if version != 2 {
        bail!("unsupported wtns version {}", version);
    }
    let n_sections = read_u32_le(&mut f)?;

    let mut field_size_bytes: Option<u32> = None;
    let mut prime_le_bytes: Option<Vec<u8>> = None;
    let mut n_wires: Option<u32> = None;
    let mut data_offset: Option<u64> = None;
    let mut data_size: Option<u64> = None;

    for _ in 0..n_sections {
        let section_type = read_u32_le(&mut f)?;
        let section_size = read_u64_le(&mut f)?;
        let section_start = f.stream_position()?;
        match section_type {
            WTNS_SECTION_HEADER => {
                let fsb = read_u32_le(&mut f)?;
                let mut prime = vec![0u8; fsb as usize];
                f.read_exact(&mut prime)?;
                let nw = read_u32_le(&mut f)?;
                field_size_bytes = Some(fsb);
                prime_le_bytes = Some(prime);
                n_wires = Some(nw);
                f.seek(SeekFrom::Start(section_start + section_size))?;
            }
            WTNS_SECTION_DATA => {
                data_offset = Some(section_start);
                data_size = Some(section_size);
                f.seek(SeekFrom::Start(section_start + section_size))?;
            }
            _ => {
                f.seek(SeekFrom::Start(section_start + section_size))?;
            }
        }
    }

    let field_size_bytes =
        field_size_bytes.ok_or_else(|| anyhow!("wtns file is missing the header section"))?;
    let prime_le_bytes = prime_le_bytes.unwrap();
    let n_wires = n_wires.ok_or_else(|| anyhow!("wtns file has no n_wires"))?;
    let data_offset =
        data_offset.ok_or_else(|| anyhow!("wtns file is missing the data section"))?;
    let _data_size = data_size.unwrap();

    f.seek(SeekFrom::Start(data_offset))?;
    let mut wires_le_bytes = Vec::with_capacity(n_wires as usize);
    for _ in 0..n_wires {
        let mut w = vec![0u8; field_size_bytes as usize];
        f.read_exact(&mut w)?;
        wires_le_bytes.push(w);
    }
    Ok(CircomWitness {
        field_size_bytes,
        prime_le_bytes,
        n_wires,
        wires_le_bytes,
    })
}

// ----- Low-level helpers -----

fn read_u32_le(f: &mut File) -> Result<u32> {
    let mut buf = [0u8; 4];
    f.read_exact(&mut buf)?;
    Ok(u32::from_le_bytes(buf))
}

fn read_u64_le(f: &mut File) -> Result<u64> {
    let mut buf = [0u8; 8];
    f.read_exact(&mut buf)?;
    Ok(u64::from_le_bytes(buf))
}

// ----- LatticeFold lift -----

/// Convert an 8-byte little-endian coefficient slice into a `GoldilocksRingNTT`
/// degree-0 element (scalar lifted into the cyclotomic ring). Panics if `bytes`
/// is wider than 8 bytes; that would indicate the .r1cs file was generated
/// against a non-Goldilocks prime.
fn coeff_to_goldilocks_ring(bytes: &[u8]) -> Result<GoldilocksRingNTT> {
    if bytes.len() != 8 {
        bail!(
            "expected 8-byte coefficient (Goldilocks field_size), got {} bytes",
            bytes.len()
        );
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(bytes);
    let v = u64::from_le_bytes(buf);
    Ok(GoldilocksRingNTT::from(v))
}

/// Convert a parsed Circom R1CS (Goldilocks field) into LatticeFold's
/// `R1CS<GoldilocksRingNTT>` form. The conversion lifts each scalar coefficient
/// into a degree-0 cyclotomic ring element via `GoldilocksRingNTT::from(u64)`.
///
/// `l` (public-input length per LatticeFold convention) is set to
/// `n_pub_in + n_pub_out` — Circom's public surface, excluding the constant-1
/// wire which lives at wire index 0.
pub fn circom_r1cs_to_latticefold(circom: &CircomR1cs) -> Result<R1CS<GoldilocksRingNTT>> {
    if circom.field_size_bytes != 8 {
        bail!(
            "expected Goldilocks-sized field (8 bytes), got {} bytes; \
             this .r1cs was probably compiled against a different prime",
            circom.field_size_bytes,
        );
    }

    let n_cols = circom.n_wires as usize;
    let m_rows = circom.n_constraints as usize;
    let l = (circom.n_pub_in + circom.n_pub_out) as usize;

    let mat_from = |rows: &[Vec<(u32, Vec<u8>)>]| -> Result<SparseMatrix<GoldilocksRingNTT>> {
        let mut coeffs: Vec<Vec<(GoldilocksRingNTT, usize)>> = Vec::with_capacity(m_rows);
        for row in rows {
            let mut row_out = Vec::with_capacity(row.len());
            for (wire_idx, coeff_bytes) in row {
                let v = coeff_to_goldilocks_ring(coeff_bytes)?;
                // Drop zero coefficients (LatticeFold's check_relation treats absent and
                // explicit-zero coefficients identically; explicit zeros just bloat the
                // sparse representation).
                if !v.is_zero() {
                    row_out.push((v, *wire_idx as usize));
                }
            }
            coeffs.push(row_out);
        }
        Ok(SparseMatrix {
            nrows: m_rows,
            ncols: n_cols,
            coeffs,
        })
    };

    Ok(R1CS {
        l,
        A: mat_from(&circom.a)?,
        B: mat_from(&circom.b)?,
        C: mat_from(&circom.c)?,
    })
}

/// Convert a parsed Circom witness vector (Goldilocks) into the LatticeFold
/// `z`-vector form: `Vec<GoldilocksRingNTT>`. Order is unchanged — wire i in
/// Circom maps to z[i].
pub fn circom_witness_to_latticefold(wtns: &CircomWitness) -> Result<Vec<GoldilocksRingNTT>> {
    if wtns.field_size_bytes != 8 {
        bail!(
            "expected Goldilocks-sized witness (8 bytes/wire), got {} bytes",
            wtns.field_size_bytes
        );
    }
    let mut out = Vec::with_capacity(wtns.n_wires as usize);
    for wire in &wtns.wires_le_bytes {
        out.push(coeff_to_goldilocks_ring(wire)?);
    }
    Ok(out)
}

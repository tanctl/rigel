use starknet_crypto::Felt;

use crate::advanced::one_out_of_many::{PedersenOneOutOfManyProof, PedersenOneOutOfManyStatement};
use crate::advanced::ring::{RingProof, RingStatement};
use crate::core::constants::{
    TAG_CHAUM_PED, TAG_DLOG, TAG_OKAMOTO, TAG_PEDERSEN, TAG_PEDERSEN_EQ, TAG_PEDERSEN_RERAND,
    TAG_SCHNORR,
};
use crate::core::curve::{Point, ensure_non_identity, point_coordinates};
use crate::core::errors::{ProverError, Result};
use crate::core::limits::{
    MAX_OKAMOTO_BASES, MAX_ONE_OUT_OF_MANY, MAX_RING_SIZE,
};
use crate::core::scalar::Scalar;
use crate::protocols::types::*;

pub fn encode_point(p: &Point) -> Result<Vec<Felt>> {
    ensure_non_identity(p)?;
    let (x, y) = point_coordinates(p);
    Ok(vec![x, y])
}

pub fn encode_scalar(s: &Scalar) -> Result<Felt> {
    s.ensure_canonical()?;
    Ok(s.to_felt())
}

pub fn encode_schnorr_statement(stmt: &SchnorrStatement) -> Result<Vec<Felt>> {
    encode_point(&stmt.public_key)
}

pub fn encode_dlog_statement(stmt: &DLogStatement) -> Result<Vec<Felt>> {
    let mut out = Vec::with_capacity(4);
    out.extend_from_slice(&encode_point(&stmt.base)?);
    out.extend_from_slice(&encode_point(&stmt.public_key)?);
    Ok(out)
}

pub fn encode_chaum_ped_statement(stmt: &ChaumPedStatement) -> Result<Vec<Felt>> {
    let mut out = Vec::with_capacity(6);
    out.extend_from_slice(&encode_point(&stmt.y1)?);
    out.extend_from_slice(&encode_point(&stmt.y2)?);
    out.extend_from_slice(&encode_point(&stmt.h)?);
    Ok(out)
}

pub fn encode_okamoto_statement(stmt: &OkamotoStatement) -> Result<Vec<Felt>> {
    if stmt.bases.is_empty() || stmt.bases.len() > MAX_OKAMOTO_BASES {
        return Err(ProverError::InvalidStatement);
    }
    let mut out = Vec::with_capacity(1 + stmt.bases.len() * 2 + 2);
    out.push(Felt::from(stmt.bases.len() as u64));
    for base in &stmt.bases {
        out.extend_from_slice(&encode_point(base)?);
    }
    out.extend_from_slice(&encode_point(&stmt.y)?);
    Ok(out)
}

pub fn encode_pedersen_statement(stmt: &PedersenStatement) -> Result<Vec<Felt>> {
    let mut out = Vec::with_capacity(6);
    out.extend_from_slice(&encode_point(&stmt.value_base)?);
    out.extend_from_slice(&encode_point(&stmt.blinding_base)?);
    out.extend_from_slice(&encode_point(&stmt.commitment)?);
    Ok(out)
}

pub fn encode_pedersen_eq_statement(stmt: &PedersenEqStatement) -> Result<Vec<Felt>> {
    let mut out = Vec::with_capacity(12);
    out.extend_from_slice(&encode_point(&stmt.value_base1)?);
    out.extend_from_slice(&encode_point(&stmt.blinding_base1)?);
    out.extend_from_slice(&encode_point(&stmt.commitment1)?);
    out.extend_from_slice(&encode_point(&stmt.value_base2)?);
    out.extend_from_slice(&encode_point(&stmt.blinding_base2)?);
    out.extend_from_slice(&encode_point(&stmt.commitment2)?);
    Ok(out)
}

pub fn encode_pedersen_rerand_statement(stmt: &PedersenRerandStatement) -> Result<Vec<Felt>> {
    let mut out = Vec::with_capacity(6);
    out.extend_from_slice(&encode_point(&stmt.rerand_base)?);
    out.extend_from_slice(&encode_point(&stmt.commitment_from)?);
    out.extend_from_slice(&encode_point(&stmt.commitment_to)?);
    Ok(out)
}

pub fn encode_sigma_statement(stmt: &SigmaStatement) -> Result<Vec<Felt>> {
    let mut out = Vec::new();
    match stmt {
        SigmaStatement::Schnorr(s) => {
            out.push(Felt::from(TAG_SCHNORR));
            out.extend_from_slice(&encode_schnorr_statement(s)?);
        }
        SigmaStatement::DLog(s) => {
            out.push(Felt::from(TAG_DLOG));
            out.extend_from_slice(&encode_dlog_statement(s)?);
        }
        SigmaStatement::ChaumPed(s) => {
            out.push(Felt::from(TAG_CHAUM_PED));
            out.extend_from_slice(&encode_chaum_ped_statement(s)?);
        }
        SigmaStatement::Okamoto(s) => {
            out.push(Felt::from(TAG_OKAMOTO));
            out.extend_from_slice(&encode_okamoto_statement(s)?);
        }
        SigmaStatement::Pedersen(s) => {
            out.push(Felt::from(TAG_PEDERSEN));
            out.extend_from_slice(&encode_pedersen_statement(s)?);
        }
        SigmaStatement::PedersenEq(s) => {
            out.push(Felt::from(TAG_PEDERSEN_EQ));
            out.extend_from_slice(&encode_pedersen_eq_statement(s)?);
        }
        SigmaStatement::PedersenRerand(s) => {
            out.push(Felt::from(TAG_PEDERSEN_RERAND));
            out.extend_from_slice(&encode_pedersen_rerand_statement(s)?);
        }
    }
    Ok(out)
}

pub fn encode_schnorr_commitment(commitment: &Point) -> Result<Vec<Felt>> {
    encode_point(commitment)
}

pub fn encode_dlog_commitment(commitment: &Point) -> Result<Vec<Felt>> {
    encode_point(commitment)
}

pub fn encode_chaum_ped_commitment(r1: &Point, r2: &Point) -> Result<Vec<Felt>> {
    let mut out = Vec::with_capacity(4);
    out.extend_from_slice(&encode_point(r1)?);
    out.extend_from_slice(&encode_point(r2)?);
    Ok(out)
}

pub fn encode_okamoto_commitment(commitment: &Point) -> Result<Vec<Felt>> {
    encode_point(commitment)
}

pub fn encode_pedersen_commitment(commitment: &Point) -> Result<Vec<Felt>> {
    encode_point(commitment)
}

pub fn encode_pedersen_eq_commitment(c1: &Point, c2: &Point) -> Result<Vec<Felt>> {
    let mut out = Vec::with_capacity(4);
    out.extend_from_slice(&encode_point(c1)?);
    out.extend_from_slice(&encode_point(c2)?);
    Ok(out)
}

pub fn encode_pedersen_rerand_commitment(commitment: &Point) -> Result<Vec<Felt>> {
    encode_point(commitment)
}

pub fn encode_schnorr_proof(proof: &SchnorrProof) -> Result<Vec<Felt>> {
    let mut out = Vec::with_capacity(3);
    out.extend_from_slice(&encode_point(&proof.commitment)?);
    out.push(encode_scalar(&proof.response)?);
    Ok(out)
}

pub fn encode_dlog_proof(proof: &DLogProof) -> Result<Vec<Felt>> {
    let mut out = Vec::with_capacity(3);
    out.extend_from_slice(&encode_point(&proof.commitment)?);
    out.push(encode_scalar(&proof.response)?);
    Ok(out)
}

pub fn encode_chaum_ped_proof(proof: &ChaumPedProof) -> Result<Vec<Felt>> {
    let mut out = Vec::with_capacity(5);
    out.extend_from_slice(&encode_point(&proof.r1)?);
    out.extend_from_slice(&encode_point(&proof.r2)?);
    out.push(encode_scalar(&proof.response)?);
    Ok(out)
}

pub fn encode_okamoto_proof(proof: &OkamotoProof) -> Result<Vec<Felt>> {
    if proof.responses.is_empty() || proof.responses.len() > MAX_OKAMOTO_BASES {
        return Err(ProverError::InvalidStatement);
    }
    let mut out = Vec::with_capacity(3 + proof.responses.len());
    out.extend_from_slice(&encode_point(&proof.commitment)?);
    out.push(Felt::from(proof.responses.len() as u64));
    for s in &proof.responses {
        out.push(encode_scalar(s)?);
    }
    Ok(out)
}

pub fn encode_pedersen_proof(proof: &PedersenProof) -> Result<Vec<Felt>> {
    let mut out = Vec::with_capacity(4);
    out.extend_from_slice(&encode_point(&proof.nonce_commitment)?);
    out.push(encode_scalar(&proof.response_value)?);
    out.push(encode_scalar(&proof.response_blinding)?);
    Ok(out)
}

pub fn encode_pedersen_eq_proof(proof: &PedersenEqProof) -> Result<Vec<Felt>> {
    let mut out = Vec::with_capacity(7);
    out.extend_from_slice(&encode_point(&proof.nonce_commitment1)?);
    out.extend_from_slice(&encode_point(&proof.nonce_commitment2)?);
    out.push(encode_scalar(&proof.response_value)?);
    out.push(encode_scalar(&proof.response_blinding1)?);
    out.push(encode_scalar(&proof.response_blinding2)?);
    Ok(out)
}

pub fn encode_pedersen_rerand_proof(proof: &PedersenRerandProof) -> Result<Vec<Felt>> {
    let mut out = Vec::with_capacity(3);
    out.extend_from_slice(&encode_point(&proof.nonce_commitment)?);
    out.push(encode_scalar(&proof.response)?);
    Ok(out)
}

pub fn encode_sigma_proof(proof: &SigmaProof) -> Result<Vec<Felt>> {
    let mut out = Vec::new();
    match proof {
        SigmaProof::Schnorr(p) => {
            out.push(Felt::from(TAG_SCHNORR));
            out.extend_from_slice(&encode_schnorr_proof(p)?);
        }
        SigmaProof::DLog(p) => {
            out.push(Felt::from(TAG_DLOG));
            out.extend_from_slice(&encode_dlog_proof(p)?);
        }
        SigmaProof::ChaumPed(p) => {
            out.push(Felt::from(TAG_CHAUM_PED));
            out.extend_from_slice(&encode_chaum_ped_proof(p)?);
        }
        SigmaProof::Okamoto(p) => {
            out.push(Felt::from(TAG_OKAMOTO));
            out.extend_from_slice(&encode_okamoto_proof(p)?);
        }
        SigmaProof::Pedersen(p) => {
            out.push(Felt::from(TAG_PEDERSEN));
            out.extend_from_slice(&encode_pedersen_proof(p)?);
        }
        SigmaProof::PedersenEq(p) => {
            out.push(Felt::from(TAG_PEDERSEN_EQ));
            out.extend_from_slice(&encode_pedersen_eq_proof(p)?);
        }
        SigmaProof::PedersenRerand(p) => {
            out.push(Felt::from(TAG_PEDERSEN_RERAND));
            out.extend_from_slice(&encode_pedersen_rerand_proof(p)?);
        }
    }
    Ok(out)
}

pub fn encode_ring_statement(stmt: &RingStatement) -> Result<Vec<Felt>> {
    let n = stmt.public_keys.len();
    if n == 0 || n > MAX_RING_SIZE {
        return Err(ProverError::InvalidStatement);
    }
    let mut out = Vec::with_capacity(1 + n * 2);
    out.push(Felt::from(n as u64));
    for pk in &stmt.public_keys {
        out.extend_from_slice(&encode_point(pk)?);
    }
    Ok(out)
}

pub fn encode_ring_commitment(commitments: &[Point]) -> Result<Vec<Felt>> {
    let n = commitments.len();
    if n == 0 || n > MAX_RING_SIZE {
        return Err(ProverError::InvalidStatement);
    }
    let mut out = Vec::with_capacity(1 + n * 2);
    out.push(Felt::from(n as u64));
    for c in commitments {
        out.extend_from_slice(&encode_point(c)?);
    }
    Ok(out)
}

pub fn encode_ring_proof(proof: &RingProof) -> Result<Vec<Felt>> {
    let n = proof.commitments.len();
    if n == 0 || n > MAX_RING_SIZE {
        return Err(ProverError::InvalidStatement);
    }
    if proof.challenges.len() != n || proof.responses.len() != n {
        return Err(ProverError::MismatchedLength);
    }
    let mut out = Vec::with_capacity(1 + n * 2 + n + n);
    out.push(Felt::from(n as u64));
    for c in &proof.commitments {
        out.extend_from_slice(&encode_point(c)?);
    }
    for c in &proof.challenges {
        out.push(encode_scalar(c)?);
    }
    for s in &proof.responses {
        out.push(encode_scalar(s)?);
    }
    Ok(out)
}

pub fn encode_one_out_of_many_statement(stmt: &PedersenOneOutOfManyStatement) -> Result<Vec<Felt>> {
    let n = stmt.candidates.len();
    if n == 0 || n > MAX_ONE_OUT_OF_MANY {
        return Err(ProverError::InvalidStatement);
    }
    if !n.is_power_of_two() {
        return Err(ProverError::RingSizeMustBePowerOfTwo);
    }
    let mut out = Vec::with_capacity(1 + 2 + n * 2);
    out.push(Felt::from(n as u64));
    out.extend_from_slice(&encode_point(&stmt.commitment)?);
    for c in &stmt.candidates {
        out.extend_from_slice(&encode_point(c)?);
    }
    Ok(out)
}

#[inline]
fn max_one_out_of_many_log2() -> Result<usize> {
    if MAX_ONE_OUT_OF_MANY == 0 || !MAX_ONE_OUT_OF_MANY.is_power_of_two() {
        return Err(ProverError::InvalidStatement);
    }
    Ok(MAX_ONE_OUT_OF_MANY.trailing_zeros() as usize)
}

pub fn encode_one_out_of_many_proof(proof: &PedersenOneOutOfManyProof) -> Result<Vec<Felt>> {
    let n = proof.f.len();
    if n > max_one_out_of_many_log2()? {
        return Err(ProverError::InvalidStatement);
    }
    if proof.cl.len() != n
        || proof.ca.len() != n
        || proof.cb.len() != n
        || proof.cd.len() != n
        || proof.za.len() != n
        || proof.zb.len() != n
    {
        return Err(ProverError::MismatchedLength);
    }
    let mut out = Vec::with_capacity(1 + n * (2 * 4 + 3) + 1);
    out.push(Felt::from(n as u64));
    for p in &proof.cl {
        out.extend_from_slice(&encode_point(p)?);
    }
    for p in &proof.ca {
        out.extend_from_slice(&encode_point(p)?);
    }
    for p in &proof.cb {
        out.extend_from_slice(&encode_point(p)?);
    }
    for p in &proof.cd {
        out.extend_from_slice(&encode_point(p)?);
    }
    for s in &proof.f {
        out.push(encode_scalar(s)?);
    }
    for s in &proof.za {
        out.push(encode_scalar(s)?);
    }
    for s in &proof.zb {
        out.push(encode_scalar(s)?);
    }
    out.push(encode_scalar(&proof.zd)?);
    Ok(out)
}

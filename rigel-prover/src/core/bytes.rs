use crate::advanced::one_out_of_many::PedersenOneOutOfManyProof;
use crate::core::constants::{FIELD_PRIME, ORDER};
use crate::core::curve::{Point, ensure_non_identity, point_coordinates, validate_point};
use crate::core::errors::{ProverError, Result};
use crate::core::scalar::Scalar;
use crate::protocols::types::{
    ChaumPedProof, DLogProof, PedersenEqProof, PedersenProof, PedersenRerandProof, SchnorrProof,
};
use num_bigint::BigUint;

pub const SCALAR_BYTES: usize = 32;
pub const POINT_BYTES: usize = 64;

pub fn encode_scalar_be32(s: &Scalar) -> Result<[u8; SCALAR_BYTES]> {
    s.ensure_canonical()?;
    Ok(s.to_bytes_be())
}

pub fn encode_point_be64(p: &Point) -> Result<[u8; POINT_BYTES]> {
    ensure_non_identity(p)?;
    let (x, y) = point_coordinates(p);
    let mut out = [0u8; POINT_BYTES];
    let xb = x.to_bytes_be();
    let yb = y.to_bytes_be();
    out[..SCALAR_BYTES].copy_from_slice(&xb);
    out[SCALAR_BYTES..].copy_from_slice(&yb);
    Ok(out)
}

pub fn encode_scalars_be32(values: &[Scalar]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(values.len() * SCALAR_BYTES);
    for s in values {
        out.extend_from_slice(&encode_scalar_be32(s)?);
    }
    Ok(out)
}

pub fn encode_points_be64(points: &[Point]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(points.len() * POINT_BYTES);
    for p in points {
        out.extend_from_slice(&encode_point_be64(p)?);
    }
    Ok(out)
}

pub fn encode_schnorr_proof_bytes(proof: &SchnorrProof) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(POINT_BYTES + SCALAR_BYTES);
    out.extend_from_slice(&encode_point_be64(&proof.commitment)?);
    out.extend_from_slice(&encode_scalar_be32(&proof.response)?);
    Ok(out)
}

pub fn encode_dlog_proof_bytes(proof: &DLogProof) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(POINT_BYTES + SCALAR_BYTES);
    out.extend_from_slice(&encode_point_be64(&proof.commitment)?);
    out.extend_from_slice(&encode_scalar_be32(&proof.response)?);
    Ok(out)
}

pub fn encode_chaum_ped_proof_bytes(proof: &ChaumPedProof) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(POINT_BYTES * 2 + SCALAR_BYTES);
    out.extend_from_slice(&encode_point_be64(&proof.r1)?);
    out.extend_from_slice(&encode_point_be64(&proof.r2)?);
    out.extend_from_slice(&encode_scalar_be32(&proof.response)?);
    Ok(out)
}

pub fn encode_okamoto_responses_bytes(responses: &[Scalar]) -> Result<Vec<u8>> {
    encode_scalars_be32(responses)
}

pub fn encode_pedersen_proof_bytes(proof: &PedersenProof) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(POINT_BYTES + SCALAR_BYTES * 2);
    out.extend_from_slice(&encode_point_be64(&proof.nonce_commitment)?);
    out.extend_from_slice(&encode_scalar_be32(&proof.response_value)?);
    out.extend_from_slice(&encode_scalar_be32(&proof.response_blinding)?);
    Ok(out)
}

pub fn encode_pedersen_eq_proof_bytes(proof: &PedersenEqProof) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(POINT_BYTES * 2 + SCALAR_BYTES * 3);
    out.extend_from_slice(&encode_point_be64(&proof.nonce_commitment1)?);
    out.extend_from_slice(&encode_point_be64(&proof.nonce_commitment2)?);
    out.extend_from_slice(&encode_scalar_be32(&proof.response_value)?);
    out.extend_from_slice(&encode_scalar_be32(&proof.response_blinding1)?);
    out.extend_from_slice(&encode_scalar_be32(&proof.response_blinding2)?);
    Ok(out)
}

pub fn encode_pedersen_rerand_proof_bytes(proof: &PedersenRerandProof) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(POINT_BYTES + SCALAR_BYTES);
    out.extend_from_slice(&encode_point_be64(&proof.nonce_commitment)?);
    out.extend_from_slice(&encode_scalar_be32(&proof.response)?);
    Ok(out)
}

pub fn encode_one_out_of_many_proof_bytes(
    proof: &PedersenOneOutOfManyProof,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let n = proof.f.len();
    if proof.cl.len() != n
        || proof.ca.len() != n
        || proof.cb.len() != n
        || proof.cd.len() != n
        || proof.za.len() != n
        || proof.zb.len() != n
    {
        return Err(ProverError::MismatchedLength);
    }

    let mut commitments = Vec::with_capacity(n * POINT_BYTES * 4);
    for p in &proof.cl {
        commitments.extend_from_slice(&encode_point_be64(p)?);
    }
    for p in &proof.ca {
        commitments.extend_from_slice(&encode_point_be64(p)?);
    }
    for p in &proof.cb {
        commitments.extend_from_slice(&encode_point_be64(p)?);
    }
    for p in &proof.cd {
        commitments.extend_from_slice(&encode_point_be64(p)?);
    }

    let mut scalars = Vec::with_capacity((n * 3 + 1) * SCALAR_BYTES);
    for s in &proof.f {
        scalars.extend_from_slice(&encode_scalar_be32(s)?);
    }
    for s in &proof.za {
        scalars.extend_from_slice(&encode_scalar_be32(s)?);
    }
    for s in &proof.zb {
        scalars.extend_from_slice(&encode_scalar_be32(s)?);
    }
    scalars.extend_from_slice(&encode_scalar_be32(&proof.zd)?);

    Ok((commitments, scalars))
}

pub fn decode_scalar_be32(bytes: &[u8]) -> Result<Scalar> {
    if bytes.len() != SCALAR_BYTES {
        return Err(ProverError::InvalidEncoding);
    }
    let value = BigUint::from_bytes_be(bytes);
    if value >= *ORDER {
        return Err(ProverError::NonCanonicalScalar);
    }
    Scalar::from_biguint(value)
}

pub fn decode_point_be64(bytes: &[u8]) -> Result<Point> {
    if bytes.len() != POINT_BYTES {
        return Err(ProverError::InvalidEncoding);
    }
    let x = BigUint::from_bytes_be(&bytes[..SCALAR_BYTES]);
    let y = BigUint::from_bytes_be(&bytes[SCALAR_BYTES..]);
    if x >= *FIELD_PRIME || y >= *FIELD_PRIME {
        return Err(ProverError::InvalidPoint);
    }
    let mut xb = [0u8; SCALAR_BYTES];
    let mut yb = [0u8; SCALAR_BYTES];
    xb.copy_from_slice(&bytes[..SCALAR_BYTES]);
    yb.copy_from_slice(&bytes[SCALAR_BYTES..]);
    let x_felt = starknet_crypto::Felt::from_bytes_be(&xb);
    let y_felt = starknet_crypto::Felt::from_bytes_be(&yb);
    validate_point(x_felt, y_felt)
}

pub fn decode_scalars_be32(bytes: &[u8]) -> Result<Vec<Scalar>> {
    if !bytes.len().is_multiple_of(SCALAR_BYTES) {
        return Err(ProverError::InvalidEncoding);
    }
    let mut out = Vec::with_capacity(bytes.len() / SCALAR_BYTES);
    for chunk in bytes.chunks_exact(SCALAR_BYTES) {
        out.push(decode_scalar_be32(chunk)?);
    }
    Ok(out)
}

pub fn decode_points_be64(bytes: &[u8]) -> Result<Vec<Point>> {
    if !bytes.len().is_multiple_of(POINT_BYTES) {
        return Err(ProverError::InvalidEncoding);
    }
    let mut out = Vec::with_capacity(bytes.len() / POINT_BYTES);
    for chunk in bytes.chunks_exact(POINT_BYTES) {
        out.push(decode_point_be64(chunk)?);
    }
    Ok(out)
}

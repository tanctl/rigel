use starknet_crypto::Felt;

use crate::advanced::one_out_of_many::{PedersenOneOutOfManyProof, PedersenOneOutOfManyStatement};
use crate::advanced::ring::{RingProof, RingStatement};
use crate::core::constants::{
    TAG_CHAUM_PED, TAG_DLOG, TAG_OKAMOTO, TAG_PEDERSEN, TAG_PEDERSEN_EQ, TAG_PEDERSEN_RERAND,
    TAG_SCHNORR,
};
use crate::core::curve::validate_point;
use crate::core::errors::{ProverError, Result};
use crate::core::limits::{
    MAX_OKAMOTO_BASES, MAX_ONE_OUT_OF_MANY, MAX_RING_SIZE,
};
use crate::core::scalar::Scalar;
use crate::protocols::types::*;

struct Decoder<'a> {
    data: &'a [Felt],
    pos: usize,
}

impl<'a> Decoder<'a> {
    fn new(data: &'a [Felt]) -> Self {
        Self { data, pos: 0 }
    }

    fn pop(&mut self) -> Result<Felt> {
        if self.pos >= self.data.len() {
            return Err(ProverError::InvalidEncoding);
        }
        let v = self.data[self.pos];
        self.pos += 1;
        Ok(v)
    }

    fn rest(&self) -> &'a [Felt] {
        &self.data[self.pos..]
    }
}

fn pop_scalar(dec: &mut Decoder<'_>) -> Result<Scalar> {
    let f = dec.pop()?;
    Scalar::from_biguint(f.to_biguint())
}

fn pop_point(dec: &mut Decoder<'_>) -> Result<crate::core::curve::Point> {
    let x = dec.pop()?;
    let y = dec.pop()?;
    validate_point(x, y)
}

fn pop_pedersen_eq_proof(dec: &mut Decoder<'_>) -> Result<PedersenEqProof> {
    let nonce_commitment1 = pop_point(dec)?;
    let nonce_commitment2 = pop_point(dec)?;
    let response_value = pop_scalar(dec)?;
    let response_blinding1 = pop_scalar(dec)?;
    let response_blinding2 = pop_scalar(dec)?;
    Ok(PedersenEqProof {
        nonce_commitment1,
        nonce_commitment2,
        response_value,
        response_blinding1,
        response_blinding2,
    })
}

fn felt_to_usize(f: Felt) -> Result<usize> {
    let n = f.to_biguint();
    let n_u64: u64 = n.try_into().map_err(|_| ProverError::InvalidStatement)?;
    Ok(n_u64 as usize)
}

#[inline]
fn max_one_out_of_many_log2() -> Result<usize> {
    if MAX_ONE_OUT_OF_MANY == 0 || !MAX_ONE_OUT_OF_MANY.is_power_of_two() {
        return Err(ProverError::InvalidStatement);
    }
    Ok(MAX_ONE_OUT_OF_MANY.trailing_zeros() as usize)
}

pub fn decode_schnorr_statement(data: &[Felt]) -> Result<(SchnorrStatement, &[Felt])> {
    let mut dec = Decoder::new(data);
    let stmt = SchnorrStatement {
        public_key: pop_point(&mut dec)?,
    };
    Ok((stmt, dec.rest()))
}

pub fn decode_schnorr_statement_strict(data: &[Felt]) -> Result<SchnorrStatement> {
    let (stmt, rest) = decode_schnorr_statement(data)?;
    if !rest.is_empty() {
        return Err(ProverError::InvalidEncoding);
    }
    Ok(stmt)
}

pub fn decode_dlog_statement(data: &[Felt]) -> Result<(DLogStatement, &[Felt])> {
    let mut dec = Decoder::new(data);
    let base = pop_point(&mut dec)?;
    let public_key = pop_point(&mut dec)?;
    Ok((DLogStatement { base, public_key }, dec.rest()))
}

pub fn decode_dlog_statement_strict(data: &[Felt]) -> Result<DLogStatement> {
    let (stmt, rest) = decode_dlog_statement(data)?;
    if !rest.is_empty() {
        return Err(ProverError::InvalidEncoding);
    }
    Ok(stmt)
}

pub fn decode_chaum_ped_statement(data: &[Felt]) -> Result<(ChaumPedStatement, &[Felt])> {
    let mut dec = Decoder::new(data);
    let y1 = pop_point(&mut dec)?;
    let y2 = pop_point(&mut dec)?;
    let h = pop_point(&mut dec)?;
    Ok((ChaumPedStatement { y1, y2, h }, dec.rest()))
}

pub fn decode_chaum_ped_statement_strict(data: &[Felt]) -> Result<ChaumPedStatement> {
    let (stmt, rest) = decode_chaum_ped_statement(data)?;
    if !rest.is_empty() {
        return Err(ProverError::InvalidEncoding);
    }
    Ok(stmt)
}

pub fn decode_okamoto_statement(data: &[Felt]) -> Result<(OkamotoStatement, &[Felt])> {
    let mut dec = Decoder::new(data);
    let n_felt = dec.pop()?;
    let n = felt_to_usize(n_felt)?;
    if n == 0 || n > MAX_OKAMOTO_BASES {
        return Err(ProverError::InvalidStatement);
    }
    let mut bases = Vec::with_capacity(n);
    for _ in 0..n {
        bases.push(pop_point(&mut dec)?);
    }
    let y = pop_point(&mut dec)?;
    Ok((OkamotoStatement { bases, y }, dec.rest()))
}

pub fn decode_okamoto_statement_strict(data: &[Felt]) -> Result<OkamotoStatement> {
    let (stmt, rest) = decode_okamoto_statement(data)?;
    if !rest.is_empty() {
        return Err(ProverError::InvalidEncoding);
    }
    Ok(stmt)
}

pub fn decode_pedersen_statement(data: &[Felt]) -> Result<(PedersenStatement, &[Felt])> {
    let mut dec = Decoder::new(data);
    let value_base = pop_point(&mut dec)?;
    let blinding_base = pop_point(&mut dec)?;
    let commitment = pop_point(&mut dec)?;
    Ok((
        PedersenStatement {
            value_base,
            blinding_base,
            commitment,
        },
        dec.rest(),
    ))
}

pub fn decode_pedersen_statement_strict(data: &[Felt]) -> Result<PedersenStatement> {
    let (stmt, rest) = decode_pedersen_statement(data)?;
    if !rest.is_empty() {
        return Err(ProverError::InvalidEncoding);
    }
    Ok(stmt)
}

pub fn decode_pedersen_eq_statement(data: &[Felt]) -> Result<(PedersenEqStatement, &[Felt])> {
    let mut dec = Decoder::new(data);
    let value_base1 = pop_point(&mut dec)?;
    let blinding_base1 = pop_point(&mut dec)?;
    let commitment1 = pop_point(&mut dec)?;
    let value_base2 = pop_point(&mut dec)?;
    let blinding_base2 = pop_point(&mut dec)?;
    let commitment2 = pop_point(&mut dec)?;
    Ok((
        PedersenEqStatement {
            commitment1,
            commitment2,
            value_base1,
            blinding_base1,
            value_base2,
            blinding_base2,
        },
        dec.rest(),
    ))
}

pub fn decode_pedersen_eq_statement_strict(data: &[Felt]) -> Result<PedersenEqStatement> {
    let (stmt, rest) = decode_pedersen_eq_statement(data)?;
    if !rest.is_empty() {
        return Err(ProverError::InvalidEncoding);
    }
    Ok(stmt)
}

pub fn decode_pedersen_rerand_statement(
    data: &[Felt],
) -> Result<(PedersenRerandStatement, &[Felt])> {
    let mut dec = Decoder::new(data);
    let rerand_base = pop_point(&mut dec)?;
    let commitment_from = pop_point(&mut dec)?;
    let commitment_to = pop_point(&mut dec)?;
    Ok((
        PedersenRerandStatement {
            rerand_base,
            commitment_from,
            commitment_to,
        },
        dec.rest(),
    ))
}

pub fn decode_pedersen_rerand_statement_strict(data: &[Felt]) -> Result<PedersenRerandStatement> {
    let (stmt, rest) = decode_pedersen_rerand_statement(data)?;
    if !rest.is_empty() {
        return Err(ProverError::InvalidEncoding);
    }
    Ok(stmt)
}

pub fn decode_sigma_statement(data: &[Felt]) -> Result<(SigmaStatement, &[Felt])> {
    let mut dec = Decoder::new(data);
    let tag = dec.pop()?;
    let stmt = if tag == Felt::from(TAG_SCHNORR) {
        SigmaStatement::Schnorr(SchnorrStatement {
            public_key: pop_point(&mut dec)?,
        })
    } else if tag == Felt::from(TAG_DLOG) {
        SigmaStatement::DLog(DLogStatement {
            base: pop_point(&mut dec)?,
            public_key: pop_point(&mut dec)?,
        })
    } else if tag == Felt::from(TAG_CHAUM_PED) {
        let y1 = pop_point(&mut dec)?;
        let y2 = pop_point(&mut dec)?;
        let h = pop_point(&mut dec)?;
        SigmaStatement::ChaumPed(ChaumPedStatement { y1, y2, h })
    } else if tag == Felt::from(TAG_OKAMOTO) {
        let n_felt = dec.pop()?;
        let n = felt_to_usize(n_felt)?;
        if n == 0 || n > MAX_OKAMOTO_BASES {
            return Err(ProverError::InvalidStatement);
        }
        let mut bases = Vec::with_capacity(n);
        for _ in 0..n {
            bases.push(pop_point(&mut dec)?);
        }
        let y = pop_point(&mut dec)?;
        SigmaStatement::Okamoto(OkamotoStatement { bases, y })
    } else if tag == Felt::from(TAG_PEDERSEN) {
        SigmaStatement::Pedersen(PedersenStatement {
            value_base: pop_point(&mut dec)?,
            blinding_base: pop_point(&mut dec)?,
            commitment: pop_point(&mut dec)?,
        })
    } else if tag == Felt::from(TAG_PEDERSEN_EQ) {
        SigmaStatement::PedersenEq(PedersenEqStatement {
            value_base1: pop_point(&mut dec)?,
            blinding_base1: pop_point(&mut dec)?,
            commitment1: pop_point(&mut dec)?,
            value_base2: pop_point(&mut dec)?,
            blinding_base2: pop_point(&mut dec)?,
            commitment2: pop_point(&mut dec)?,
        })
    } else if tag == Felt::from(TAG_PEDERSEN_RERAND) {
        SigmaStatement::PedersenRerand(PedersenRerandStatement {
            rerand_base: pop_point(&mut dec)?,
            commitment_from: pop_point(&mut dec)?,
            commitment_to: pop_point(&mut dec)?,
        })
    } else {
        return Err(ProverError::InvalidEncoding);
    };
    Ok((stmt, dec.rest()))
}

pub fn decode_sigma_statement_strict(data: &[Felt]) -> Result<SigmaStatement> {
    let (stmt, rest) = decode_sigma_statement(data)?;
    if !rest.is_empty() {
        return Err(ProverError::InvalidEncoding);
    }
    Ok(stmt)
}

pub fn decode_schnorr_proof(data: &[Felt]) -> Result<(SchnorrProof, &[Felt])> {
    let mut dec = Decoder::new(data);
    let commitment = pop_point(&mut dec)?;
    let response = pop_scalar(&mut dec)?;
    Ok((
        SchnorrProof {
            commitment,
            response,
        },
        dec.rest(),
    ))
}

pub fn decode_schnorr_proof_strict(data: &[Felt]) -> Result<SchnorrProof> {
    let (proof, rest) = decode_schnorr_proof(data)?;
    if !rest.is_empty() {
        return Err(ProverError::InvalidEncoding);
    }
    Ok(proof)
}

pub fn decode_dlog_proof(data: &[Felt]) -> Result<(DLogProof, &[Felt])> {
    let mut dec = Decoder::new(data);
    let commitment = pop_point(&mut dec)?;
    let response = pop_scalar(&mut dec)?;
    Ok((
        DLogProof {
            commitment,
            response,
        },
        dec.rest(),
    ))
}

pub fn decode_dlog_proof_strict(data: &[Felt]) -> Result<DLogProof> {
    let (proof, rest) = decode_dlog_proof(data)?;
    if !rest.is_empty() {
        return Err(ProverError::InvalidEncoding);
    }
    Ok(proof)
}

pub fn decode_chaum_ped_proof(data: &[Felt]) -> Result<(ChaumPedProof, &[Felt])> {
    let mut dec = Decoder::new(data);
    let r1 = pop_point(&mut dec)?;
    let r2 = pop_point(&mut dec)?;
    let response = pop_scalar(&mut dec)?;
    Ok((ChaumPedProof { r1, r2, response }, dec.rest()))
}

pub fn decode_chaum_ped_proof_strict(data: &[Felt]) -> Result<ChaumPedProof> {
    let (proof, rest) = decode_chaum_ped_proof(data)?;
    if !rest.is_empty() {
        return Err(ProverError::InvalidEncoding);
    }
    Ok(proof)
}

pub fn decode_okamoto_proof(data: &[Felt]) -> Result<(OkamotoProof, &[Felt])> {
    let mut dec = Decoder::new(data);
    let commitment = pop_point(&mut dec)?;
    let n_felt = dec.pop()?;
    let n = felt_to_usize(n_felt)?;
    if n == 0 || n > MAX_OKAMOTO_BASES {
        return Err(ProverError::InvalidStatement);
    }
    let mut responses = Vec::with_capacity(n);
    for _ in 0..n {
        responses.push(pop_scalar(&mut dec)?);
    }
    Ok((
        OkamotoProof {
            commitment,
            responses,
        },
        dec.rest(),
    ))
}

pub fn decode_okamoto_proof_strict(data: &[Felt]) -> Result<OkamotoProof> {
    let (proof, rest) = decode_okamoto_proof(data)?;
    if !rest.is_empty() {
        return Err(ProverError::InvalidEncoding);
    }
    Ok(proof)
}

pub fn decode_pedersen_proof(data: &[Felt]) -> Result<(PedersenProof, &[Felt])> {
    let mut dec = Decoder::new(data);
    let nonce_commitment = pop_point(&mut dec)?;
    let response_value = pop_scalar(&mut dec)?;
    let response_blinding = pop_scalar(&mut dec)?;
    Ok((
        PedersenProof {
            nonce_commitment,
            response_value,
            response_blinding,
        },
        dec.rest(),
    ))
}

pub fn decode_pedersen_proof_strict(data: &[Felt]) -> Result<PedersenProof> {
    let (proof, rest) = decode_pedersen_proof(data)?;
    if !rest.is_empty() {
        return Err(ProverError::InvalidEncoding);
    }
    Ok(proof)
}

pub fn decode_pedersen_eq_proof(data: &[Felt]) -> Result<(PedersenEqProof, &[Felt])> {
    let mut dec = Decoder::new(data);
    let proof = pop_pedersen_eq_proof(&mut dec)?;
    Ok((proof, dec.rest()))
}

pub fn decode_pedersen_eq_proof_strict(data: &[Felt]) -> Result<PedersenEqProof> {
    let (proof, rest) = decode_pedersen_eq_proof(data)?;
    if !rest.is_empty() {
        return Err(ProverError::InvalidEncoding);
    }
    Ok(proof)
}

pub fn decode_pedersen_rerand_proof(data: &[Felt]) -> Result<(PedersenRerandProof, &[Felt])> {
    let mut dec = Decoder::new(data);
    let nonce_commitment = pop_point(&mut dec)?;
    let response = pop_scalar(&mut dec)?;
    Ok((
        PedersenRerandProof {
            nonce_commitment,
            response,
        },
        dec.rest(),
    ))
}

pub fn decode_pedersen_rerand_proof_strict(data: &[Felt]) -> Result<PedersenRerandProof> {
    let (proof, rest) = decode_pedersen_rerand_proof(data)?;
    if !rest.is_empty() {
        return Err(ProverError::InvalidEncoding);
    }
    Ok(proof)
}

pub fn decode_sigma_proof(data: &[Felt]) -> Result<(SigmaProof, &[Felt])> {
    let mut dec = Decoder::new(data);
    let tag = dec.pop()?;
    let proof = if tag == Felt::from(TAG_SCHNORR) {
        let commitment = pop_point(&mut dec)?;
        let response = pop_scalar(&mut dec)?;
        SigmaProof::Schnorr(SchnorrProof {
            commitment,
            response,
        })
    } else if tag == Felt::from(TAG_DLOG) {
        let commitment = pop_point(&mut dec)?;
        let response = pop_scalar(&mut dec)?;
        SigmaProof::DLog(DLogProof {
            commitment,
            response,
        })
    } else if tag == Felt::from(TAG_CHAUM_PED) {
        let r1 = pop_point(&mut dec)?;
        let r2 = pop_point(&mut dec)?;
        let response = pop_scalar(&mut dec)?;
        SigmaProof::ChaumPed(ChaumPedProof { r1, r2, response })
    } else if tag == Felt::from(TAG_OKAMOTO) {
        let commitment = pop_point(&mut dec)?;
        let n_felt = dec.pop()?;
        let n = felt_to_usize(n_felt)?;
        if n == 0 || n > MAX_OKAMOTO_BASES {
            return Err(ProverError::InvalidStatement);
        }
        let mut responses = Vec::with_capacity(n);
        for _ in 0..n {
            responses.push(pop_scalar(&mut dec)?);
        }
        SigmaProof::Okamoto(OkamotoProof {
            commitment,
            responses,
        })
    } else if tag == Felt::from(TAG_PEDERSEN) {
        let nonce_commitment = pop_point(&mut dec)?;
        let response_value = pop_scalar(&mut dec)?;
        let response_blinding = pop_scalar(&mut dec)?;
        SigmaProof::Pedersen(PedersenProof {
            nonce_commitment,
            response_value,
            response_blinding,
        })
    } else if tag == Felt::from(TAG_PEDERSEN_EQ) {
        SigmaProof::PedersenEq(pop_pedersen_eq_proof(&mut dec)?)
    } else if tag == Felt::from(TAG_PEDERSEN_RERAND) {
        let nonce_commitment = pop_point(&mut dec)?;
        let response = pop_scalar(&mut dec)?;
        SigmaProof::PedersenRerand(PedersenRerandProof {
            nonce_commitment,
            response,
        })
    } else {
        return Err(ProverError::InvalidEncoding);
    };
    Ok((proof, dec.rest()))
}

pub fn decode_sigma_proof_strict(data: &[Felt]) -> Result<SigmaProof> {
    let (proof, rest) = decode_sigma_proof(data)?;
    if !rest.is_empty() {
        return Err(ProverError::InvalidEncoding);
    }
    Ok(proof)
}

pub fn decode_ring_statement(data: &[Felt]) -> Result<(RingStatement, &[Felt])> {
    let mut dec = Decoder::new(data);
    let n_felt = dec.pop()?;
    let n = felt_to_usize(n_felt)?;
    if n == 0 || n > MAX_RING_SIZE {
        return Err(ProverError::InvalidStatement);
    }
    let mut public_keys = Vec::with_capacity(n);
    for _ in 0..n {
        public_keys.push(pop_point(&mut dec)?);
    }
    Ok((RingStatement { public_keys }, dec.rest()))
}

pub fn decode_ring_statement_strict(data: &[Felt]) -> Result<RingStatement> {
    let (stmt, rest) = decode_ring_statement(data)?;
    if !rest.is_empty() {
        return Err(ProverError::InvalidEncoding);
    }
    Ok(stmt)
}

pub fn decode_ring_commitment(data: &[Felt]) -> Result<(Vec<crate::core::curve::Point>, &[Felt])> {
    let mut dec = Decoder::new(data);
    let n_felt = dec.pop()?;
    let n = felt_to_usize(n_felt)?;
    if n == 0 || n > MAX_RING_SIZE {
        return Err(ProverError::InvalidStatement);
    }
    let mut commitments = Vec::with_capacity(n);
    for _ in 0..n {
        commitments.push(pop_point(&mut dec)?);
    }
    Ok((commitments, dec.rest()))
}

pub fn decode_ring_commitment_strict(data: &[Felt]) -> Result<Vec<crate::core::curve::Point>> {
    let (commitments, rest) = decode_ring_commitment(data)?;
    if !rest.is_empty() {
        return Err(ProverError::InvalidEncoding);
    }
    Ok(commitments)
}

pub fn decode_ring_proof(data: &[Felt]) -> Result<(RingProof, &[Felt])> {
    let mut dec = Decoder::new(data);
    let n_felt = dec.pop()?;
    let n = felt_to_usize(n_felt)?;
    if n == 0 || n > MAX_RING_SIZE {
        return Err(ProverError::InvalidStatement);
    }
    let mut commitments = Vec::with_capacity(n);
    for _ in 0..n {
        commitments.push(pop_point(&mut dec)?);
    }
    let mut challenges = Vec::with_capacity(n);
    for _ in 0..n {
        challenges.push(pop_scalar(&mut dec)?);
    }
    let mut responses = Vec::with_capacity(n);
    for _ in 0..n {
        responses.push(pop_scalar(&mut dec)?);
    }
    Ok((
        RingProof {
            commitments,
            challenges,
            responses,
        },
        dec.rest(),
    ))
}

pub fn decode_ring_proof_strict(data: &[Felt]) -> Result<RingProof> {
    let (proof, rest) = decode_ring_proof(data)?;
    if !rest.is_empty() {
        return Err(ProverError::InvalidEncoding);
    }
    Ok(proof)
}

pub fn decode_one_out_of_many_statement(
    data: &[Felt],
) -> Result<(PedersenOneOutOfManyStatement, &[Felt])> {
    let mut dec = Decoder::new(data);
    let n_felt = dec.pop()?;
    let n = felt_to_usize(n_felt)?;
    if n == 0 || n > MAX_ONE_OUT_OF_MANY {
        return Err(ProverError::InvalidStatement);
    }
    if !n.is_power_of_two() {
        return Err(ProverError::RingSizeMustBePowerOfTwo);
    }
    let commitment = pop_point(&mut dec)?;
    let mut candidates = Vec::with_capacity(n);
    for _ in 0..n {
        candidates.push(pop_point(&mut dec)?);
    }
    Ok((
        PedersenOneOutOfManyStatement {
            commitment,
            candidates,
        },
        dec.rest(),
    ))
}

pub fn decode_one_out_of_many_statement_strict(
    data: &[Felt],
) -> Result<PedersenOneOutOfManyStatement> {
    let (stmt, rest) = decode_one_out_of_many_statement(data)?;
    if !rest.is_empty() {
        return Err(ProverError::InvalidEncoding);
    }
    Ok(stmt)
}

pub fn decode_one_out_of_many_proof(data: &[Felt]) -> Result<(PedersenOneOutOfManyProof, &[Felt])> {
    let mut dec = Decoder::new(data);
    let n_felt = dec.pop()?;
    let n = felt_to_usize(n_felt)?;
    if n > max_one_out_of_many_log2()? {
        return Err(ProverError::InvalidStatement);
    }
    let mut cl = Vec::with_capacity(n);
    for _ in 0..n {
        cl.push(pop_point(&mut dec)?);
    }
    let mut ca = Vec::with_capacity(n);
    for _ in 0..n {
        ca.push(pop_point(&mut dec)?);
    }
    let mut cb = Vec::with_capacity(n);
    for _ in 0..n {
        cb.push(pop_point(&mut dec)?);
    }
    let mut cd = Vec::with_capacity(n);
    for _ in 0..n {
        cd.push(pop_point(&mut dec)?);
    }
    let mut f = Vec::with_capacity(n);
    for _ in 0..n {
        f.push(pop_scalar(&mut dec)?);
    }
    let mut za = Vec::with_capacity(n);
    for _ in 0..n {
        za.push(pop_scalar(&mut dec)?);
    }
    let mut zb = Vec::with_capacity(n);
    for _ in 0..n {
        zb.push(pop_scalar(&mut dec)?);
    }
    let zd = pop_scalar(&mut dec)?;
    Ok((
        PedersenOneOutOfManyProof {
            cl,
            ca,
            cb,
            cd,
            f,
            za,
            zb,
            zd,
        },
        dec.rest(),
    ))
}

pub fn decode_one_out_of_many_proof_strict(data: &[Felt]) -> Result<PedersenOneOutOfManyProof> {
    let (proof, rest) = decode_one_out_of_many_proof(data)?;
    if !rest.is_empty() {
        return Err(ProverError::InvalidEncoding);
    }
    Ok(proof)
}

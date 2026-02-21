use core::array::{Array, ArrayTrait, Span};
use core::integer::u256;
use core::traits::TryInto;

use crate::core::canonical::{
    TAG_SCHNORR,
    TAG_DLOG,
    TAG_CHAUM_PED,
    TAG_OKAMOTO,
    TAG_PEDERSEN,
    TAG_PEDERSEN_EQ,
    TAG_PEDERSEN_RERAND,
};
use crate::core::errors::VerifyError;
use crate::core::limits::MAX_OKAMOTO_BASES_U256;
use crate::protocols::types::{
    SchnorrStatement,
    SchnorrProof,
    DLogStatement,
    DLogProof,
    ChaumPedStatement,
    ChaumPedProof,
    OkamotoStatement,
    OkamotoProof,
    PedersenStatement,
    PedersenProof,
    PedersenEqStatement,
    PedersenEqProof,
    PedersenRerandStatement,
    PedersenRerandProof,
    SigmaStatement,
    SigmaProof,
};
use crate::utils::bytes::{pop_point_be64, pop_scalar_be32};

#[inline]
fn pop_okamoto_statement(ref data: Span<u8>) -> Result<(OkamotoStatement, u32), VerifyError> {
    let n_felt = pop_scalar_be32(ref data)?;
    let n_u256: u256 = n_felt.into();
    let zero: u256 = 0;
    if n_u256 == zero || n_u256 > MAX_OKAMOTO_BASES_U256 {
        return Err(VerifyError::InvalidStatement);
    }
    let n: u32 = n_felt.try_into().ok_or(VerifyError::InvalidStatement)?;
    let mut bases: Array<core::ec::NonZeroEcPoint> = ArrayTrait::new();
    let mut i: u32 = 0;
    loop {
        if i >= n {
            break;
        }
        let p = pop_point_be64(ref data)?;
        bases.append(p);
        i += 1;
    }
    let y = pop_point_be64(ref data)?;
    Ok((OkamotoStatement { bases: bases.span(), y }, n))
}

#[inline]
fn pop_okamoto_proof(ref data: Span<u8>, n: u32) -> Result<OkamotoProof, VerifyError> {
    let commitment = pop_point_be64(ref data)?;
    let mut responses: Array<felt252> = ArrayTrait::new();
    let mut i: u32 = 0;
    loop {
        if i >= n {
            break;
        }
        let s = pop_scalar_be32(ref data)?;
        responses.append(s);
        i += 1;
    }
    Ok(OkamotoProof { commitment, responses: responses.span() })
}

pub(crate) fn pop_instance(ref data: Span<u8>) -> Result<(SigmaStatement, SigmaProof), VerifyError> {
    let tag = pop_scalar_be32(ref data)?;
    if tag == TAG_SCHNORR {
        let pk = pop_point_be64(ref data)?;
        let commitment = pop_point_be64(ref data)?;
        let response = pop_scalar_be32(ref data)?;
        return Ok((
            SigmaStatement::Schnorr(SchnorrStatement { public_key: pk }),
            SigmaProof::Schnorr(SchnorrProof { commitment, response }),
        ));
    }
    if tag == TAG_DLOG {
        let base = pop_point_be64(ref data)?;
        let pk = pop_point_be64(ref data)?;
        let commitment = pop_point_be64(ref data)?;
        let response = pop_scalar_be32(ref data)?;
        return Ok((
            SigmaStatement::DLog(DLogStatement { base, public_key: pk }),
            SigmaProof::DLog(DLogProof { commitment, response }),
        ));
    }
    if tag == TAG_CHAUM_PED {
        let y1 = pop_point_be64(ref data)?;
        let y2 = pop_point_be64(ref data)?;
        let h = pop_point_be64(ref data)?;
        let r1 = pop_point_be64(ref data)?;
        let r2 = pop_point_be64(ref data)?;
        let response = pop_scalar_be32(ref data)?;
        return Ok((
            SigmaStatement::ChaumPed(ChaumPedStatement { y1, y2, h }),
            SigmaProof::ChaumPed(ChaumPedProof { r1, r2, response }),
        ));
    }
    if tag == TAG_OKAMOTO {
        let (stmt, n) = pop_okamoto_statement(ref data)?;
        let proof = pop_okamoto_proof(ref data, n)?;
        return Ok((
            SigmaStatement::Okamoto(stmt),
            SigmaProof::Okamoto(proof),
        ));
    }
    if tag == TAG_PEDERSEN {
        let value_base = pop_point_be64(ref data)?;
        let blinding_base = pop_point_be64(ref data)?;
        let commitment = pop_point_be64(ref data)?;
        let nonce_commitment = pop_point_be64(ref data)?;
        let response_value = pop_scalar_be32(ref data)?;
        let response_blinding = pop_scalar_be32(ref data)?;
        return Ok((
            SigmaStatement::Pedersen(PedersenStatement { value_base, blinding_base, commitment }),
            SigmaProof::Pedersen(PedersenProof { nonce_commitment, response_value, response_blinding }),
        ));
    }
    if tag == TAG_PEDERSEN_EQ {
        let value_base1 = pop_point_be64(ref data)?;
        let blinding_base1 = pop_point_be64(ref data)?;
        let commitment1 = pop_point_be64(ref data)?;
        let value_base2 = pop_point_be64(ref data)?;
        let blinding_base2 = pop_point_be64(ref data)?;
        let commitment2 = pop_point_be64(ref data)?;
        let nonce_commitment1 = pop_point_be64(ref data)?;
        let nonce_commitment2 = pop_point_be64(ref data)?;
        let response_value = pop_scalar_be32(ref data)?;
        let response_blinding1 = pop_scalar_be32(ref data)?;
        let response_blinding2 = pop_scalar_be32(ref data)?;
        return Ok((
            SigmaStatement::PedersenEq(PedersenEqStatement {
                commitment1,
                commitment2,
                value_base1,
                blinding_base1,
                value_base2,
                blinding_base2,
            }),
            SigmaProof::PedersenEq(PedersenEqProof {
                nonce_commitment1,
                nonce_commitment2,
                response_value,
                response_blinding1,
                response_blinding2,
            }),
        ));
    }
    if tag == TAG_PEDERSEN_RERAND {
        let rerand_base = pop_point_be64(ref data)?;
        let commitment_from = pop_point_be64(ref data)?;
        let commitment_to = pop_point_be64(ref data)?;
        let nonce_commitment = pop_point_be64(ref data)?;
        let response = pop_scalar_be32(ref data)?;
        return Ok((
            SigmaStatement::PedersenRerand(PedersenRerandStatement {
                rerand_base,
                commitment_from,
                commitment_to,
            }),
            SigmaProof::PedersenRerand(PedersenRerandProof { nonce_commitment, response }),
        ));
    }

    Err(VerifyError::InvalidEncoding)
}

pub(crate) fn pop_instance_with_challenge(
    ref data: Span<u8>,
) -> Result<(SigmaStatement, SigmaProof, felt252), VerifyError> {
    let (stmt, proof) = pop_instance(ref data)?;
    let challenge = pop_scalar_be32(ref data)?;
    Ok((stmt, proof, challenge))
}

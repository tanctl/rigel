use core::array::{Array, ArrayTrait, Span, SpanTrait};
use core::ec::NonZeroEcPoint;
use core::integer::u256;
use core::option::OptionTrait;
use core::traits::{Into, TryInto};

use crate::core::curve::validate_point;
use crate::core::encoding::{append_point, append_scalar};
use crate::core::scalar::is_canonical_scalar;
use crate::core::errors::VerifyError;
use crate::core::limits::{
    MAX_ONE_OUT_OF_MANY,
    MAX_OKAMOTO_BASES_U256,
    MAX_RING_SIZE_U256,
    MAX_ONE_OUT_OF_MANY_U256,
};
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
use crate::advanced::ring::{RingStatement, RingProof};
use crate::advanced::one_out_of_many::{
    PedersenOneOutOfManyStatement,
    PedersenOneOutOfManyProof,
};

/// variant tags for canonical statement/proof encodings
pub const TAG_SCHNORR: felt252 = 1;
pub const TAG_CHAUM_PED: felt252 = 2;
pub const TAG_OKAMOTO: felt252 = 3;
pub const TAG_PEDERSEN: felt252 = 4;
pub const TAG_PEDERSEN_EQ: felt252 = 5;
pub const TAG_PEDERSEN_RERAND: felt252 = 6;
pub const TAG_DLOG: felt252 = 7;

#[derive(Drop)]
pub struct OkamotoStatementDecoded {
    pub bases: Array<NonZeroEcPoint>,
    pub y: NonZeroEcPoint,
}

#[derive(Drop)]
pub struct OkamotoProofDecoded {
    pub commitment: NonZeroEcPoint,
    pub responses: Array<felt252>,
}

#[derive(Drop)]
pub struct RingStatementDecoded {
    pub public_keys: Array<NonZeroEcPoint>,
}

#[derive(Drop)]
pub struct RingProofDecoded {
    pub commitments: Array<NonZeroEcPoint>,
    pub challenges: Array<felt252>,
    pub responses: Array<felt252>,
}

#[derive(Drop)]
pub struct OneOutOfManyStatementDecoded {
    pub commitment: NonZeroEcPoint,
    pub candidates: Array<NonZeroEcPoint>,
}

#[derive(Drop)]
pub struct OneOutOfManyProofDecoded {
    pub cl: Array<NonZeroEcPoint>,
    pub ca: Array<NonZeroEcPoint>,
    pub cb: Array<NonZeroEcPoint>,
    pub cd: Array<NonZeroEcPoint>,
    pub f: Array<felt252>,
    pub za: Array<felt252>,
    pub zb: Array<felt252>,
    pub zd: felt252,
}

#[derive(Drop)]
pub enum DecodedSigmaStatement {
    Schnorr: SchnorrStatement,
    DLog: DLogStatement,
    ChaumPed: ChaumPedStatement,
    Okamoto: OkamotoStatementDecoded,
    Pedersen: PedersenStatement,
    PedersenEq: PedersenEqStatement,
    PedersenRerand: PedersenRerandStatement,
}

#[derive(Drop)]
pub enum DecodedSigmaProof {
    Schnorr: SchnorrProof,
    DLog: DLogProof,
    ChaumPed: ChaumPedProof,
    Okamoto: OkamotoProofDecoded,
    Pedersen: PedersenProof,
    PedersenEq: PedersenEqProof,
    PedersenRerand: PedersenRerandProof,
}

#[inline]
fn pop_felt(mut data: Span<felt252>) -> Result<(felt252, Span<felt252>), VerifyError> {
    match data.pop_front() {
        Some(v) => Ok((*v, data)),
        None => Err(VerifyError::InvalidEncoding),
    }
}

#[inline]
fn pop_scalar(mut data: Span<felt252>) -> Result<(felt252, Span<felt252>), VerifyError> {
    let (s, data) = pop_felt(data)?;
    if !is_canonical_scalar(s) {
        return Err(VerifyError::NonCanonicalScalar);
    }
    Ok((s, data))
}

#[inline]
fn pop_point(mut data: Span<felt252>) -> Result<(NonZeroEcPoint, Span<felt252>), VerifyError> {
    let (x, data) = pop_felt(data)?;
    let (y, data) = pop_felt(data)?;
    let p = validate_point(x, y).ok_or(VerifyError::InvalidPoint)?;
    Ok((p, data))
}

#[inline]
fn ensure_empty(rest: Span<felt252>) -> Result<(), VerifyError> {
    if rest.len() == 0 {
        Ok(())
    } else {
        Err(VerifyError::InvalidEncoding)
    }
}

#[inline]
fn is_power_of_two_u32(mut n: u32) -> bool {
    if n == 0_u32 {
        return false;
    }
    loop {
        if n == 1_u32 {
            return true;
        }
        if n % 2_u32 != 0_u32 {
            return false;
        }
        n = n / 2_u32;
    }
}

#[inline]
fn max_one_out_of_many_log2_u256() -> Option<u256> {
    let mut n: u32 = MAX_ONE_OUT_OF_MANY;
    if !is_power_of_two_u32(n) {
        return None;
    }

    let mut bits: u32 = 0_u32;
    loop {
        if n == 1_u32 {
            break;
        }
        n = n / 2_u32;
        bits = bits + 1_u32;
    }

    Some(bits.into())
}

/// canonical statement encodings

pub fn encode_schnorr_statement(stmt: SchnorrStatement) -> Array<felt252> {
    let mut out = ArrayTrait::new();
    append_point(ref out, stmt.public_key);
    out
}

pub fn encode_dlog_statement(stmt: DLogStatement) -> Array<felt252> {
    let mut out = ArrayTrait::new();
    append_point(ref out, stmt.base);
    append_point(ref out, stmt.public_key);
    out
}


pub fn encode_chaum_ped_statement(stmt: ChaumPedStatement) -> Array<felt252> {
    let mut out = ArrayTrait::new();
    append_point(ref out, stmt.y1);
    append_point(ref out, stmt.y2);
    append_point(ref out, stmt.h);
    out
}

pub fn encode_okamoto_statement(stmt: OkamotoStatement) -> Result<Array<felt252>, VerifyError> {
    let mut out = ArrayTrait::new();
    let n_felt: felt252 = stmt.bases.len().into();
    let n_u256: u256 = n_felt.into();
    let zero: u256 = 0;
    if n_u256 == zero || n_u256 > MAX_OKAMOTO_BASES_U256 {
        return Err(VerifyError::InvalidStatement);
    }
    out.append(n_felt);
    let mut bases = stmt.bases;
    loop {
        match bases.pop_front() {
            Some(p) => append_point(ref out, *p),
            None => { break; },
        }
    }
    append_point(ref out, stmt.y);
    Ok(out)
}

pub fn encode_pedersen_statement(stmt: PedersenStatement) -> Array<felt252> {
    let mut out = ArrayTrait::new();
    append_point(ref out, stmt.value_base);
    append_point(ref out, stmt.blinding_base);
    append_point(ref out, stmt.commitment);
    out
}

pub fn encode_pedersen_eq_statement(stmt: PedersenEqStatement) -> Array<felt252> {
    let mut out = ArrayTrait::new();
    append_point(ref out, stmt.value_base1);
    append_point(ref out, stmt.blinding_base1);
    append_point(ref out, stmt.commitment1);
    append_point(ref out, stmt.value_base2);
    append_point(ref out, stmt.blinding_base2);
    append_point(ref out, stmt.commitment2);
    out
}

pub fn encode_pedersen_rerand_statement(stmt: PedersenRerandStatement) -> Array<felt252> {
    let mut out = ArrayTrait::new();
    append_point(ref out, stmt.rerand_base);
    append_point(ref out, stmt.commitment_from);
    append_point(ref out, stmt.commitment_to);
    out
}

pub fn encode_sigma_statement(stmt: SigmaStatement) -> Result<Array<felt252>, VerifyError> {
    let mut out = ArrayTrait::new();
    match stmt {
        SigmaStatement::Schnorr(s) => {
            out.append(TAG_SCHNORR);
            out.append_span(encode_schnorr_statement(s).span());
        },
        SigmaStatement::DLog(s) => {
            out.append(TAG_DLOG);
            out.append_span(encode_dlog_statement(s).span());
        },
        SigmaStatement::ChaumPed(s) => {
            out.append(TAG_CHAUM_PED);
            out.append_span(encode_chaum_ped_statement(s).span());
        },
        SigmaStatement::Okamoto(s) => {
            out.append(TAG_OKAMOTO);
            out.append_span(encode_okamoto_statement(s)?.span());
        },
        SigmaStatement::Pedersen(s) => {
            out.append(TAG_PEDERSEN);
            out.append_span(encode_pedersen_statement(s).span());
        },
        SigmaStatement::PedersenEq(s) => {
            out.append(TAG_PEDERSEN_EQ);
            out.append_span(encode_pedersen_eq_statement(s).span());
        },
        SigmaStatement::PedersenRerand(s) => {
            out.append(TAG_PEDERSEN_RERAND);
            out.append_span(encode_pedersen_rerand_statement(s).span());
        },
    }
    Ok(out)
}

/// canonical commitment encodings (protocol-specific commitments)

pub fn encode_schnorr_commitment(commitment: NonZeroEcPoint) -> Array<felt252> {
    let mut out = ArrayTrait::new();
    append_point(ref out, commitment);
    out
}

pub fn encode_dlog_commitment(commitment: NonZeroEcPoint) -> Array<felt252> {
    let mut out = ArrayTrait::new();
    append_point(ref out, commitment);
    out
}


pub fn encode_chaum_ped_commitment(r1: NonZeroEcPoint, r2: NonZeroEcPoint) -> Array<felt252> {
    let mut out = ArrayTrait::new();
    append_point(ref out, r1);
    append_point(ref out, r2);
    out
}

pub fn encode_okamoto_commitment(commitment: NonZeroEcPoint) -> Array<felt252> {
    let mut out = ArrayTrait::new();
    append_point(ref out, commitment);
    out
}

pub fn encode_pedersen_commitment(nonce_commitment: NonZeroEcPoint) -> Array<felt252> {
    let mut out = ArrayTrait::new();
    append_point(ref out, nonce_commitment);
    out
}

pub fn encode_pedersen_eq_commitment(
    nonce_commitment1: NonZeroEcPoint,
    nonce_commitment2: NonZeroEcPoint,
) -> Array<felt252> {
    let mut out = ArrayTrait::new();
    append_point(ref out, nonce_commitment1);
    append_point(ref out, nonce_commitment2);
    out
}

pub fn encode_pedersen_rerand_commitment(nonce_commitment: NonZeroEcPoint) -> Array<felt252> {
    let mut out = ArrayTrait::new();
    append_point(ref out, nonce_commitment);
    out
}

pub fn encode_sigma_commitment(stmt: SigmaStatement, proof: SigmaProof) -> Result<Array<felt252>, VerifyError> {
    match (stmt, proof) {
        (SigmaStatement::Schnorr(_s), SigmaProof::Schnorr(p)) => Ok(encode_schnorr_commitment(p.commitment)),
        (SigmaStatement::DLog(_s), SigmaProof::DLog(p)) => Ok(encode_dlog_commitment(p.commitment)),
        (SigmaStatement::ChaumPed(_s), SigmaProof::ChaumPed(p)) => Ok(encode_chaum_ped_commitment(p.r1, p.r2)),
        (SigmaStatement::Okamoto(_s), SigmaProof::Okamoto(p)) => Ok(encode_okamoto_commitment(p.commitment)),
        (SigmaStatement::Pedersen(_s), SigmaProof::Pedersen(p)) => Ok(encode_pedersen_commitment(p.nonce_commitment)),
        (SigmaStatement::PedersenEq(_s), SigmaProof::PedersenEq(p)) => {
            Ok(encode_pedersen_eq_commitment(p.nonce_commitment1, p.nonce_commitment2))
        },
        (SigmaStatement::PedersenRerand(_s), SigmaProof::PedersenRerand(p)) => {
            Ok(encode_pedersen_rerand_commitment(p.nonce_commitment))
        },
        _ => Err(VerifyError::MismatchedProofType),
    }
}

/// canonical proof encodings

pub fn encode_schnorr_proof(proof: SchnorrProof) -> Result<Array<felt252>, VerifyError> {
    let mut out = ArrayTrait::new();
    append_point(ref out, proof.commitment);
    append_scalar(ref out, proof.response).ok_or(VerifyError::NonCanonicalScalar)?;
    Ok(out)
}

pub fn encode_dlog_proof(proof: DLogProof) -> Result<Array<felt252>, VerifyError> {
    let mut out = ArrayTrait::new();
    append_point(ref out, proof.commitment);
    append_scalar(ref out, proof.response).ok_or(VerifyError::NonCanonicalScalar)?;
    Ok(out)
}


pub fn encode_chaum_ped_proof(proof: ChaumPedProof) -> Result<Array<felt252>, VerifyError> {
    let mut out = ArrayTrait::new();
    append_point(ref out, proof.r1);
    append_point(ref out, proof.r2);
    append_scalar(ref out, proof.response).ok_or(VerifyError::NonCanonicalScalar)?;
    Ok(out)
}

pub fn encode_okamoto_proof(proof: OkamotoProof) -> Result<Array<felt252>, VerifyError> {
    let mut out = ArrayTrait::new();
    append_point(ref out, proof.commitment);
    let n_felt: felt252 = proof.responses.len().into();
    let n_u256: u256 = n_felt.into();
    let zero: u256 = 0;
    if n_u256 == zero || n_u256 > MAX_OKAMOTO_BASES_U256 {
        return Err(VerifyError::InvalidStatement);
    }
    out.append(n_felt);
    let mut responses = proof.responses;
    loop {
        match responses.pop_front() {
            Some(s) => {
                append_scalar(ref out, *s).ok_or(VerifyError::NonCanonicalScalar)?;
            },
            None => { break; },
        }
    }
    Ok(out)
}

pub fn encode_pedersen_proof(proof: PedersenProof) -> Result<Array<felt252>, VerifyError> {
    let mut out = ArrayTrait::new();
    append_point(ref out, proof.nonce_commitment);
    append_scalar(ref out, proof.response_value).ok_or(VerifyError::NonCanonicalScalar)?;
    append_scalar(ref out, proof.response_blinding).ok_or(VerifyError::NonCanonicalScalar)?;
    Ok(out)
}

pub fn encode_pedersen_eq_proof(proof: PedersenEqProof) -> Result<Array<felt252>, VerifyError> {
    let mut out = ArrayTrait::new();
    append_point(ref out, proof.nonce_commitment1);
    append_point(ref out, proof.nonce_commitment2);
    append_scalar(ref out, proof.response_value).ok_or(VerifyError::NonCanonicalScalar)?;
    append_scalar(ref out, proof.response_blinding1).ok_or(VerifyError::NonCanonicalScalar)?;
    append_scalar(ref out, proof.response_blinding2).ok_or(VerifyError::NonCanonicalScalar)?;
    Ok(out)
}

pub fn encode_pedersen_rerand_proof(proof: PedersenRerandProof) -> Result<Array<felt252>, VerifyError> {
    let mut out = ArrayTrait::new();
    append_point(ref out, proof.nonce_commitment);
    append_scalar(ref out, proof.response).ok_or(VerifyError::NonCanonicalScalar)?;
    Ok(out)
}

pub fn encode_sigma_proof(proof: SigmaProof) -> Result<Array<felt252>, VerifyError> {
    let mut out = ArrayTrait::new();
    match proof {
        SigmaProof::Schnorr(p) => {
            out.append(TAG_SCHNORR);
            out.append_span(encode_schnorr_proof(p)?.span());
        },
        SigmaProof::DLog(p) => {
            out.append(TAG_DLOG);
            out.append_span(encode_dlog_proof(p)?.span());
        },
        SigmaProof::ChaumPed(p) => {
            out.append(TAG_CHAUM_PED);
            out.append_span(encode_chaum_ped_proof(p)?.span());
        },
        SigmaProof::Okamoto(p) => {
            out.append(TAG_OKAMOTO);
            out.append_span(encode_okamoto_proof(p)?.span());
        },
        SigmaProof::Pedersen(p) => {
            out.append(TAG_PEDERSEN);
            out.append_span(encode_pedersen_proof(p)?.span());
        },
        SigmaProof::PedersenEq(p) => {
            out.append(TAG_PEDERSEN_EQ);
            out.append_span(encode_pedersen_eq_proof(p)?.span());
        },
        SigmaProof::PedersenRerand(p) => {
            out.append(TAG_PEDERSEN_RERAND);
            out.append_span(encode_pedersen_rerand_proof(p)?.span());
        },
    }
    Ok(out)
}

/// deserialization helpers that return the remaining span after decoding

pub fn decode_schnorr_statement(data: Span<felt252>) -> Result<(SchnorrStatement, Span<felt252>), VerifyError> {
    let (pk, data) = pop_point(data)?;
    Ok((SchnorrStatement { public_key: pk }, data))
}

pub fn decode_schnorr_statement_strict(data: Span<felt252>) -> Result<SchnorrStatement, VerifyError> {
    let (stmt, rest) = decode_schnorr_statement(data)?;
    ensure_empty(rest)?;
    Ok(stmt)
}

pub fn decode_dlog_statement(data: Span<felt252>) -> Result<(DLogStatement, Span<felt252>), VerifyError> {
    let (base, data) = pop_point(data)?;
    let (pk, data) = pop_point(data)?;
    Ok((DLogStatement { base, public_key: pk }, data))
}

pub fn decode_dlog_statement_strict(data: Span<felt252>) -> Result<DLogStatement, VerifyError> {
    let (stmt, rest) = decode_dlog_statement(data)?;
    ensure_empty(rest)?;
    Ok(stmt)
}


pub fn decode_chaum_ped_statement(data: Span<felt252>) -> Result<(ChaumPedStatement, Span<felt252>), VerifyError> {
    let (y1, data) = pop_point(data)?;
    let (y2, data) = pop_point(data)?;
    let (h, data) = pop_point(data)?;
    Ok((ChaumPedStatement { y1, y2, h }, data))
}

pub fn decode_chaum_ped_statement_strict(data: Span<felt252>) -> Result<ChaumPedStatement, VerifyError> {
    let (stmt, rest) = decode_chaum_ped_statement(data)?;
    ensure_empty(rest)?;
    Ok(stmt)
}

pub fn decode_okamoto_statement(data: Span<felt252>) -> Result<(OkamotoStatementDecoded, Span<felt252>), VerifyError> {
    let (n_felt, mut data) = pop_felt(data)?;
    let n_u256: u256 = n_felt.into();
    let zero: u256 = 0;
    if n_u256 == zero || n_u256 > MAX_OKAMOTO_BASES_U256 {
        return Err(VerifyError::InvalidStatement);
    }
    let mut bases: Array<NonZeroEcPoint> = ArrayTrait::new();
    let mut i: felt252 = 0;
    loop {
        if i == n_felt {
            break;
        }
        let (p, next) = pop_point(data)?;
        bases.append(p);
        data = next;
        i = i + 1;
    }
    let (y, data) = pop_point(data)?;
    Ok((OkamotoStatementDecoded { bases, y }, data))
}

pub fn decode_okamoto_statement_strict(data: Span<felt252>) -> Result<OkamotoStatementDecoded, VerifyError> {
    let (stmt, rest) = decode_okamoto_statement(data)?;
    ensure_empty(rest)?;
    Ok(stmt)
}

pub fn decode_pedersen_statement(data: Span<felt252>) -> Result<(PedersenStatement, Span<felt252>), VerifyError> {
    let (value_base, data) = pop_point(data)?;
    let (blinding_base, data) = pop_point(data)?;
    let (commitment, data) = pop_point(data)?;
    Ok((PedersenStatement { value_base, blinding_base, commitment }, data))
}

pub fn decode_pedersen_statement_strict(data: Span<felt252>) -> Result<PedersenStatement, VerifyError> {
    let (stmt, rest) = decode_pedersen_statement(data)?;
    ensure_empty(rest)?;
    Ok(stmt)
}

pub fn decode_pedersen_eq_statement(data: Span<felt252>) -> Result<(PedersenEqStatement, Span<felt252>), VerifyError> {
    let (value_base1, data) = pop_point(data)?;
    let (blinding_base1, data) = pop_point(data)?;
    let (commitment1, data) = pop_point(data)?;
    let (value_base2, data) = pop_point(data)?;
    let (blinding_base2, data) = pop_point(data)?;
    let (commitment2, data) = pop_point(data)?;
    Ok((PedersenEqStatement {
        commitment1,
        commitment2,
        value_base1,
        blinding_base1,
        value_base2,
        blinding_base2,
    }, data))
}

pub fn decode_pedersen_eq_statement_strict(data: Span<felt252>) -> Result<PedersenEqStatement, VerifyError> {
    let (stmt, rest) = decode_pedersen_eq_statement(data)?;
    ensure_empty(rest)?;
    Ok(stmt)
}

pub fn decode_pedersen_rerand_statement(data: Span<felt252>) -> Result<(PedersenRerandStatement, Span<felt252>), VerifyError> {
    let (rerand_base, data) = pop_point(data)?;
    let (commitment_from, data) = pop_point(data)?;
    let (commitment_to, data) = pop_point(data)?;
    Ok((PedersenRerandStatement { rerand_base, commitment_from, commitment_to }, data))
}

pub fn decode_pedersen_rerand_statement_strict(data: Span<felt252>) -> Result<PedersenRerandStatement, VerifyError> {
    let (stmt, rest) = decode_pedersen_rerand_statement(data)?;
    ensure_empty(rest)?;
    Ok(stmt)
}

pub fn decode_sigma_statement(data: Span<felt252>) -> Result<(DecodedSigmaStatement, Span<felt252>), VerifyError> {
    let (tag, data) = pop_felt(data)?;
    if tag == TAG_SCHNORR {
        let (stmt, rest) = decode_schnorr_statement(data)?;
        Ok((DecodedSigmaStatement::Schnorr(stmt), rest))
    } else if tag == TAG_DLOG {
        let (stmt, rest) = decode_dlog_statement(data)?;
        Ok((DecodedSigmaStatement::DLog(stmt), rest))
    } else if tag == TAG_CHAUM_PED {
        let (stmt, rest) = decode_chaum_ped_statement(data)?;
        Ok((DecodedSigmaStatement::ChaumPed(stmt), rest))
    } else if tag == TAG_OKAMOTO {
        let (stmt, rest) = decode_okamoto_statement(data)?;
        Ok((DecodedSigmaStatement::Okamoto(stmt), rest))
    } else if tag == TAG_PEDERSEN {
        let (stmt, rest) = decode_pedersen_statement(data)?;
        Ok((DecodedSigmaStatement::Pedersen(stmt), rest))
    } else if tag == TAG_PEDERSEN_EQ {
        let (stmt, rest) = decode_pedersen_eq_statement(data)?;
        Ok((DecodedSigmaStatement::PedersenEq(stmt), rest))
    } else if tag == TAG_PEDERSEN_RERAND {
        let (stmt, rest) = decode_pedersen_rerand_statement(data)?;
        Ok((DecodedSigmaStatement::PedersenRerand(stmt), rest))
    } else {
        Err(VerifyError::InvalidEncoding)
    }
}

pub fn decode_sigma_statement_strict(data: Span<felt252>) -> Result<DecodedSigmaStatement, VerifyError> {
    let (stmt, rest) = decode_sigma_statement(data)?;
    ensure_empty(rest)?;
    Ok(stmt)
}

pub fn decode_schnorr_commitment(data: Span<felt252>) -> Result<(NonZeroEcPoint, Span<felt252>), VerifyError> {
    pop_point(data)
}

pub fn decode_schnorr_commitment_strict(data: Span<felt252>) -> Result<NonZeroEcPoint, VerifyError> {
    let (commitment, rest) = decode_schnorr_commitment(data)?;
    ensure_empty(rest)?;
    Ok(commitment)
}

pub fn decode_dlog_commitment(data: Span<felt252>) -> Result<(NonZeroEcPoint, Span<felt252>), VerifyError> {
    pop_point(data)
}

pub fn decode_dlog_commitment_strict(data: Span<felt252>) -> Result<NonZeroEcPoint, VerifyError> {
    let (commitment, rest) = decode_dlog_commitment(data)?;
    ensure_empty(rest)?;
    Ok(commitment)
}


pub fn decode_chaum_ped_commitment(data: Span<felt252>) -> Result<((NonZeroEcPoint, NonZeroEcPoint), Span<felt252>), VerifyError> {
    let (r1, data) = pop_point(data)?;
    let (r2, data) = pop_point(data)?;
    Ok(((r1, r2), data))
}

pub fn decode_chaum_ped_commitment_strict(data: Span<felt252>) -> Result<(NonZeroEcPoint, NonZeroEcPoint), VerifyError> {
    let (pair, rest) = decode_chaum_ped_commitment(data)?;
    ensure_empty(rest)?;
    Ok(pair)
}

pub fn decode_okamoto_commitment(data: Span<felt252>) -> Result<(NonZeroEcPoint, Span<felt252>), VerifyError> {
    pop_point(data)
}

pub fn decode_okamoto_commitment_strict(data: Span<felt252>) -> Result<NonZeroEcPoint, VerifyError> {
    let (commitment, rest) = decode_okamoto_commitment(data)?;
    ensure_empty(rest)?;
    Ok(commitment)
}

pub fn decode_pedersen_commitment(data: Span<felt252>) -> Result<(NonZeroEcPoint, Span<felt252>), VerifyError> {
    pop_point(data)
}

pub fn decode_pedersen_commitment_strict(data: Span<felt252>) -> Result<NonZeroEcPoint, VerifyError> {
    let (commitment, rest) = decode_pedersen_commitment(data)?;
    ensure_empty(rest)?;
    Ok(commitment)
}

pub fn decode_pedersen_eq_commitment(data: Span<felt252>) -> Result<((NonZeroEcPoint, NonZeroEcPoint), Span<felt252>), VerifyError> {
    let (r1, data) = pop_point(data)?;
    let (r2, data) = pop_point(data)?;
    Ok(((r1, r2), data))
}

pub fn decode_pedersen_eq_commitment_strict(data: Span<felt252>) -> Result<(NonZeroEcPoint, NonZeroEcPoint), VerifyError> {
    let (pair, rest) = decode_pedersen_eq_commitment(data)?;
    ensure_empty(rest)?;
    Ok(pair)
}

pub fn decode_pedersen_rerand_commitment(data: Span<felt252>) -> Result<(NonZeroEcPoint, Span<felt252>), VerifyError> {
    pop_point(data)
}

pub fn decode_pedersen_rerand_commitment_strict(data: Span<felt252>) -> Result<NonZeroEcPoint, VerifyError> {
    let (commitment, rest) = decode_pedersen_rerand_commitment(data)?;
    ensure_empty(rest)?;
    Ok(commitment)
}

pub fn decode_schnorr_proof(data: Span<felt252>) -> Result<(SchnorrProof, Span<felt252>), VerifyError> {
    let (commitment, data) = pop_point(data)?;
    let (response, data) = pop_scalar(data)?;
    Ok((SchnorrProof { commitment, response }, data))
}

pub fn decode_schnorr_proof_strict(data: Span<felt252>) -> Result<SchnorrProof, VerifyError> {
    let (proof, rest) = decode_schnorr_proof(data)?;
    ensure_empty(rest)?;
    Ok(proof)
}

pub fn decode_dlog_proof(data: Span<felt252>) -> Result<(DLogProof, Span<felt252>), VerifyError> {
    let (commitment, data) = pop_point(data)?;
    let (response, data) = pop_scalar(data)?;
    Ok((DLogProof { commitment, response }, data))
}

pub fn decode_dlog_proof_strict(data: Span<felt252>) -> Result<DLogProof, VerifyError> {
    let (proof, rest) = decode_dlog_proof(data)?;
    ensure_empty(rest)?;
    Ok(proof)
}


pub fn decode_chaum_ped_proof(data: Span<felt252>) -> Result<(ChaumPedProof, Span<felt252>), VerifyError> {
    let (r1, data) = pop_point(data)?;
    let (r2, data) = pop_point(data)?;
    let (response, data) = pop_scalar(data)?;
    Ok((ChaumPedProof { r1, r2, response }, data))
}

pub fn decode_chaum_ped_proof_strict(data: Span<felt252>) -> Result<ChaumPedProof, VerifyError> {
    let (proof, rest) = decode_chaum_ped_proof(data)?;
    ensure_empty(rest)?;
    Ok(proof)
}

pub fn decode_okamoto_proof(data: Span<felt252>) -> Result<(OkamotoProofDecoded, Span<felt252>), VerifyError> {
    let (commitment, mut data) = pop_point(data)?;
    let (n_felt, next) = pop_felt(data)?;
    let n_u256: u256 = n_felt.into();
    let zero: u256 = 0;
    if n_u256 == zero || n_u256 > MAX_OKAMOTO_BASES_U256 {
        return Err(VerifyError::InvalidStatement);
    }
    data = next;
    let mut responses: Array<felt252> = ArrayTrait::new();
    let mut i: felt252 = 0;
    loop {
        if i == n_felt {
            break;
        }
        let (s, next) = pop_scalar(data)?;
        responses.append(s);
        data = next;
        i = i + 1;
    }
    Ok((OkamotoProofDecoded { commitment, responses }, data))
}

pub fn decode_okamoto_proof_strict(data: Span<felt252>) -> Result<OkamotoProofDecoded, VerifyError> {
    let (proof, rest) = decode_okamoto_proof(data)?;
    ensure_empty(rest)?;
    Ok(proof)
}

pub fn decode_pedersen_proof(data: Span<felt252>) -> Result<(PedersenProof, Span<felt252>), VerifyError> {
    let (nonce_commitment, data) = pop_point(data)?;
    let (response_value, data) = pop_scalar(data)?;
    let (response_blinding, data) = pop_scalar(data)?;
    Ok((PedersenProof { nonce_commitment, response_value, response_blinding }, data))
}

pub fn decode_pedersen_proof_strict(data: Span<felt252>) -> Result<PedersenProof, VerifyError> {
    let (proof, rest) = decode_pedersen_proof(data)?;
    ensure_empty(rest)?;
    Ok(proof)
}

pub fn decode_pedersen_eq_proof(data: Span<felt252>) -> Result<(PedersenEqProof, Span<felt252>), VerifyError> {
    let (nonce_commitment1, data) = pop_point(data)?;
    let (nonce_commitment2, data) = pop_point(data)?;
    let (response_value, data) = pop_scalar(data)?;
    let (response_blinding1, data) = pop_scalar(data)?;
    let (response_blinding2, data) = pop_scalar(data)?;
    Ok((PedersenEqProof {
        nonce_commitment1,
        nonce_commitment2,
        response_value,
        response_blinding1,
        response_blinding2,
    }, data))
}

pub fn decode_pedersen_eq_proof_strict(data: Span<felt252>) -> Result<PedersenEqProof, VerifyError> {
    let (proof, rest) = decode_pedersen_eq_proof(data)?;
    ensure_empty(rest)?;
    Ok(proof)
}

pub fn decode_pedersen_rerand_proof(data: Span<felt252>) -> Result<(PedersenRerandProof, Span<felt252>), VerifyError> {
    let (nonce_commitment, data) = pop_point(data)?;
    let (response, data) = pop_scalar(data)?;
    Ok((PedersenRerandProof { nonce_commitment, response }, data))
}

pub fn decode_pedersen_rerand_proof_strict(data: Span<felt252>) -> Result<PedersenRerandProof, VerifyError> {
    let (proof, rest) = decode_pedersen_rerand_proof(data)?;
    ensure_empty(rest)?;
    Ok(proof)
}

pub fn decode_sigma_proof(data: Span<felt252>) -> Result<(DecodedSigmaProof, Span<felt252>), VerifyError> {
    let (tag, data) = pop_felt(data)?;
    if tag == TAG_SCHNORR {
        let (proof, rest) = decode_schnorr_proof(data)?;
        Ok((DecodedSigmaProof::Schnorr(proof), rest))
    } else if tag == TAG_DLOG {
        let (proof, rest) = decode_dlog_proof(data)?;
        Ok((DecodedSigmaProof::DLog(proof), rest))
    } else if tag == TAG_CHAUM_PED {
        let (proof, rest) = decode_chaum_ped_proof(data)?;
        Ok((DecodedSigmaProof::ChaumPed(proof), rest))
    } else if tag == TAG_OKAMOTO {
        let (proof, rest) = decode_okamoto_proof(data)?;
        Ok((DecodedSigmaProof::Okamoto(proof), rest))
    } else if tag == TAG_PEDERSEN {
        let (proof, rest) = decode_pedersen_proof(data)?;
        Ok((DecodedSigmaProof::Pedersen(proof), rest))
    } else if tag == TAG_PEDERSEN_EQ {
        let (proof, rest) = decode_pedersen_eq_proof(data)?;
        Ok((DecodedSigmaProof::PedersenEq(proof), rest))
    } else if tag == TAG_PEDERSEN_RERAND {
        let (proof, rest) = decode_pedersen_rerand_proof(data)?;
        Ok((DecodedSigmaProof::PedersenRerand(proof), rest))
    } else {
        Err(VerifyError::InvalidEncoding)
    }
}

pub fn decode_sigma_proof_strict(data: Span<felt252>) -> Result<DecodedSigmaProof, VerifyError> {
    let (proof, rest) = decode_sigma_proof(data)?;
    ensure_empty(rest)?;
    Ok(proof)
}

/// ring membership encodings

pub fn encode_ring_statement(stmt: RingStatement) -> Result<Array<felt252>, VerifyError> {
    let mut out = ArrayTrait::new();
    let n_felt: felt252 = stmt.public_keys.len().into();
    let n_u256: u256 = n_felt.into();
    let zero: u256 = 0;
    if n_u256 == zero || n_u256 > MAX_RING_SIZE_U256 {
        return Err(VerifyError::InvalidStatement);
    }
    out.append(n_felt);
    let mut keys = stmt.public_keys;
    loop {
        match keys.pop_front() {
            Some(p) => append_point(ref out, *p),
            None => { break; },
        }
    }
    Ok(out)
}

pub fn encode_ring_commitment(commitments: Span<NonZeroEcPoint>) -> Result<Array<felt252>, VerifyError> {
    let mut out = ArrayTrait::new();
    let n_felt: felt252 = commitments.len().into();
    let n_u256: u256 = n_felt.into();
    let zero: u256 = 0;
    if n_u256 == zero || n_u256 > MAX_RING_SIZE_U256 {
        return Err(VerifyError::InvalidStatement);
    }
    out.append(n_felt);
    let mut comm_iter = commitments;
    loop {
        match comm_iter.pop_front() {
            Some(p) => append_point(ref out, *p),
            None => { break; },
        }
    }
    Ok(out)
}

pub fn encode_ring_proof(proof: RingProof) -> Result<Array<felt252>, VerifyError> {
    let n = proof.commitments.len();
    if n != proof.challenges.len() || n != proof.responses.len() {
        return Err(VerifyError::MismatchedLength);
    }
    let mut out = ArrayTrait::new();
    let n_felt: felt252 = n.into();
    let n_u256: u256 = n_felt.into();
    let zero: u256 = 0;
    if n_u256 == zero || n_u256 > MAX_RING_SIZE_U256 {
        return Err(VerifyError::InvalidStatement);
    }
    out.append(n_felt);
    let mut comm_iter = proof.commitments;
    loop {
        match comm_iter.pop_front() {
            Some(p) => append_point(ref out, *p),
            None => { break; },
        }
    }
    let mut chall_iter = proof.challenges;
    loop {
        match chall_iter.pop_front() {
            Some(c_ref) => {
                append_scalar(ref out, *c_ref).ok_or(VerifyError::NonCanonicalScalar)?;
            },
            None => { break; },
        }
    }
    let mut resp_iter = proof.responses;
    loop {
        match resp_iter.pop_front() {
            Some(s_ref) => {
                append_scalar(ref out, *s_ref).ok_or(VerifyError::NonCanonicalScalar)?;
            },
            None => { break; },
        }
    }
    Ok(out)
}

pub fn decode_ring_statement(data: Span<felt252>) -> Result<(RingStatementDecoded, Span<felt252>), VerifyError> {
    let (n_felt, mut data) = pop_felt(data)?;
    let n_u256: u256 = n_felt.into();
    let zero: u256 = 0;
    if n_u256 == zero || n_u256 > MAX_RING_SIZE_U256 {
        return Err(VerifyError::InvalidStatement);
    }
    let mut keys: Array<NonZeroEcPoint> = ArrayTrait::new();
    let mut i: felt252 = 0;
    loop {
        if i == n_felt {
            break;
        }
        let (p, next) = pop_point(data)?;
        keys.append(p);
        data = next;
        i = i + 1;
    }
    Ok((RingStatementDecoded { public_keys: keys }, data))
}

pub fn decode_ring_statement_strict(data: Span<felt252>) -> Result<RingStatementDecoded, VerifyError> {
    let (stmt, rest) = decode_ring_statement(data)?;
    ensure_empty(rest)?;
    Ok(stmt)
}

pub fn decode_ring_commitment(data: Span<felt252>) -> Result<(Array<NonZeroEcPoint>, Span<felt252>), VerifyError> {
    let (n_felt, mut data) = pop_felt(data)?;
    let n_u256: u256 = n_felt.into();
    let zero: u256 = 0;
    if n_u256 == zero || n_u256 > MAX_RING_SIZE_U256 {
        return Err(VerifyError::InvalidStatement);
    }
    let mut commitments: Array<NonZeroEcPoint> = ArrayTrait::new();
    let mut i: felt252 = 0;
    loop {
        if i == n_felt {
            break;
        }
        let (p, next) = pop_point(data)?;
        commitments.append(p);
        data = next;
        i = i + 1;
    }
    Ok((commitments, data))
}

pub fn decode_ring_commitment_strict(data: Span<felt252>) -> Result<Array<NonZeroEcPoint>, VerifyError> {
    let (commitments, rest) = decode_ring_commitment(data)?;
    ensure_empty(rest)?;
    Ok(commitments)
}

pub fn decode_ring_proof(data: Span<felt252>) -> Result<(RingProofDecoded, Span<felt252>), VerifyError> {
    let (n_felt, mut data) = pop_felt(data)?;
    let n_u256: u256 = n_felt.into();
    let zero: u256 = 0;
    if n_u256 == zero || n_u256 > MAX_RING_SIZE_U256 {
        return Err(VerifyError::InvalidStatement);
    }
    let mut commitments: Array<NonZeroEcPoint> = ArrayTrait::new();
    let mut i: felt252 = 0;
    loop {
        if i == n_felt { break; }
        let (p, next) = pop_point(data)?;
        commitments.append(p);
        data = next;
        i = i + 1;
    }
    let mut challenges: Array<felt252> = ArrayTrait::new();
    let mut j: felt252 = 0;
    loop {
        if j == n_felt { break; }
        let (c, next) = pop_scalar(data)?;
        challenges.append(c);
        data = next;
        j = j + 1;
    }
    let mut responses: Array<felt252> = ArrayTrait::new();
    let mut k: felt252 = 0;
    loop {
        if k == n_felt { break; }
        let (s, next) = pop_scalar(data)?;
        responses.append(s);
        data = next;
        k = k + 1;
    }
    Ok((RingProofDecoded { commitments, challenges, responses }, data))
}

pub fn decode_ring_proof_strict(data: Span<felt252>) -> Result<RingProofDecoded, VerifyError> {
    let (proof, rest) = decode_ring_proof(data)?;
    ensure_empty(rest)?;
    Ok(proof)
}

/// one-out-of-many encodings

pub fn encode_one_out_of_many_statement(
    stmt: PedersenOneOutOfManyStatement,
) -> Result<Array<felt252>, VerifyError> {
    let mut out = ArrayTrait::new();
    let n: u32 = stmt.candidates.len();
    let n_u256: u256 = n.into();
    let zero: u256 = 0;
    if n_u256 == zero || n_u256 > MAX_ONE_OUT_OF_MANY_U256 {
        return Err(VerifyError::InvalidStatement);
    }
    if !is_power_of_two_u32(n) {
        return Err(VerifyError::RingSizeMustBePowerOfTwo);
    }
    let n_felt: felt252 = n.into();
    out.append(n_felt);
    append_point(ref out, stmt.commitment);
    let mut iter = stmt.candidates;
    loop {
        match iter.pop_front() {
            Some(p_ref) => append_point(ref out, *p_ref),
            None => { break; },
        }
    }
    Ok(out)
}

pub fn encode_one_out_of_many_proof(
    proof: PedersenOneOutOfManyProof,
) -> Result<Array<felt252>, VerifyError> {
    let mut out = ArrayTrait::new();
    let n_felt: felt252 = proof.f.len().into();
    let n_u256: u256 = n_felt.into();
    let Some(max_n_u256) = max_one_out_of_many_log2_u256() else {
        return Err(VerifyError::InvalidStatement);
    };
    if n_u256 > max_n_u256 {
        return Err(VerifyError::InvalidStatement);
    }
    if proof.cl.len() != proof.f.len()
        || proof.ca.len() != proof.f.len()
        || proof.cb.len() != proof.f.len()
        || proof.cd.len() != proof.f.len()
        || proof.za.len() != proof.f.len()
        || proof.zb.len() != proof.f.len()
    {
        return Err(VerifyError::MismatchedLength);
    }
    out.append(n_felt);
    let mut cl_iter = proof.cl;
    loop {
        match cl_iter.pop_front() {
            Some(p_ref) => {
                append_point(ref out, *p_ref);
            },
            None => { break; },
        }
    }
    let mut ca_iter = proof.ca;
    loop {
        match ca_iter.pop_front() {
            Some(p_ref) => {
                append_point(ref out, *p_ref);
            },
            None => { break; },
        }
    }
    let mut cb_iter = proof.cb;
    loop {
        match cb_iter.pop_front() {
            Some(p_ref) => {
                append_point(ref out, *p_ref);
            },
            None => { break; },
        }
    }
    let mut cd_iter = proof.cd;
    loop {
        match cd_iter.pop_front() {
            Some(p_ref) => {
                append_point(ref out, *p_ref);
            },
            None => { break; },
        }
    }
    let mut f_iter = proof.f;
    loop {
        match f_iter.pop_front() {
            Some(s_ref) => {
                append_scalar(ref out, *s_ref).ok_or(VerifyError::NonCanonicalScalar)?;
            },
            None => { break; },
        }
    }
    let mut za_iter = proof.za;
    loop {
        match za_iter.pop_front() {
            Some(s_ref) => {
                append_scalar(ref out, *s_ref).ok_or(VerifyError::NonCanonicalScalar)?;
            },
            None => { break; },
        }
    }
    let mut zb_iter = proof.zb;
    loop {
        match zb_iter.pop_front() {
            Some(s_ref) => {
                append_scalar(ref out, *s_ref).ok_or(VerifyError::NonCanonicalScalar)?;
            },
            None => { break; },
        }
    }
    append_scalar(ref out, proof.zd).ok_or(VerifyError::NonCanonicalScalar)?;
    Ok(out)
}

pub fn decode_one_out_of_many_statement(
    data: Span<felt252>,
) -> Result<(OneOutOfManyStatementDecoded, Span<felt252>), VerifyError> {
    let (n_felt, mut data) = pop_felt(data)?;
    let n_u256: u256 = n_felt.into();
    let zero: u256 = 0;
    if n_u256 == zero || n_u256 > MAX_ONE_OUT_OF_MANY_U256 {
        return Err(VerifyError::InvalidStatement);
    }
    let n: u32 = n_felt.try_into().ok_or(VerifyError::InvalidStatement)?;
    if !is_power_of_two_u32(n) {
        return Err(VerifyError::RingSizeMustBePowerOfTwo);
    }
    let (commitment, next) = pop_point(data)?;
    data = next;
    let mut candidates: Array<NonZeroEcPoint> = ArrayTrait::new();
    let mut i: felt252 = 0;
    loop {
        if i == n_felt { break; }
        let (p, next) = pop_point(data)?;
        candidates.append(p);
        data = next;
        i = i + 1;
    }
    Ok((OneOutOfManyStatementDecoded { commitment, candidates }, data))
}

pub fn decode_one_out_of_many_statement_strict(
    data: Span<felt252>,
) -> Result<OneOutOfManyStatementDecoded, VerifyError> {
    let (stmt, rest) = decode_one_out_of_many_statement(data)?;
    ensure_empty(rest)?;
    Ok(stmt)
}

pub fn decode_one_out_of_many_proof(
    data: Span<felt252>,
) -> Result<(OneOutOfManyProofDecoded, Span<felt252>), VerifyError> {
    let (n_felt, mut data) = pop_felt(data)?;
    let n_u256: u256 = n_felt.into();
    let Some(max_n_u256) = max_one_out_of_many_log2_u256() else {
        return Err(VerifyError::InvalidStatement);
    };
    if n_u256 > max_n_u256 {
        return Err(VerifyError::InvalidStatement);
    }
    let mut cl: Array<NonZeroEcPoint> = ArrayTrait::new();
    let mut i: felt252 = 0;
    loop {
        if i == n_felt { break; }
        let (p, next) = pop_point(data)?;
        cl.append(p);
        data = next;
        i = i + 1;
    }
    let mut ca: Array<NonZeroEcPoint> = ArrayTrait::new();
    let mut j: felt252 = 0;
    loop {
        if j == n_felt { break; }
        let (p, next) = pop_point(data)?;
        ca.append(p);
        data = next;
        j = j + 1;
    }
    let mut cb: Array<NonZeroEcPoint> = ArrayTrait::new();
    let mut k: felt252 = 0;
    loop {
        if k == n_felt { break; }
        let (p, next) = pop_point(data)?;
        cb.append(p);
        data = next;
        k = k + 1;
    }
    let mut cd: Array<NonZeroEcPoint> = ArrayTrait::new();
    let mut m: felt252 = 0;
    loop {
        if m == n_felt { break; }
        let (p, next) = pop_point(data)?;
        cd.append(p);
        data = next;
        m = m + 1;
    }
    let mut f: Array<felt252> = ArrayTrait::new();
    let mut a: felt252 = 0;
    loop {
        if a == n_felt { break; }
        let (c, next) = pop_scalar(data)?;
        f.append(c);
        data = next;
        a = a + 1;
    }
    let mut za: Array<felt252> = ArrayTrait::new();
    let mut b: felt252 = 0;
    loop {
        if b == n_felt { break; }
        let (c, next) = pop_scalar(data)?;
        za.append(c);
        data = next;
        b = b + 1;
    }
    let mut zb: Array<felt252> = ArrayTrait::new();
    let mut c_idx: felt252 = 0;
    loop {
        if c_idx == n_felt { break; }
        let (c, next) = pop_scalar(data)?;
        zb.append(c);
        data = next;
        c_idx = c_idx + 1;
    }
    let (zd, data) = pop_scalar(data)?;
    Ok((OneOutOfManyProofDecoded { cl, ca, cb, cd, f, za, zb, zd }, data))
}

pub fn decode_one_out_of_many_proof_strict(
    data: Span<felt252>,
) -> Result<OneOutOfManyProofDecoded, VerifyError> {
    let (proof, rest) = decode_one_out_of_many_proof(data)?;
    ensure_empty(rest)?;
    Ok(proof)
}

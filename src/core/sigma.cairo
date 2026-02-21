use core::array::SpanTrait;
use core::integer::u256;
use core::option::Option;
use core::traits::{Into, TryInto};
use core::ec::{EcPoint, EcStateTrait, NonZeroEcPoint};

use crate::core::curve::generator;
use crate::core::errors::{VerifyError, VerifyResult};
use crate::core::limits::MAX_OKAMOTO_BASES_U256;
use crate::core::scalar::{is_canonical_scalar, is_nonzero_scalar};
use crate::core::transcript::{
    transcript_new_schnorr,
    transcript_new_dlog,
    transcript_new_chaum_ped,
    transcript_new_okamoto,
    transcript_new_pedersen,
    transcript_new_pedersen_eq,
    transcript_new_pedersen_rerand,
    transcript_append_felt,
    transcript_append_point,
    transcript_append_span,
    transcript_hash,
    transcript_challenge,
    Transcript,
};
use crate::core::canonical::{
    TAG_SCHNORR,
    TAG_DLOG,
    TAG_CHAUM_PED,
    TAG_OKAMOTO,
    TAG_PEDERSEN,
    TAG_PEDERSEN_EQ,
    TAG_PEDERSEN_RERAND,
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

#[inline]
fn points_equal(a: EcPoint, b: EcPoint) -> bool {
    let delta = a + (-b);
    let maybe: Option<NonZeroEcPoint> = delta.try_into();
    match maybe {
        Some(_) => false,
        None => true,
    }
}

#[inline]
fn validate_canonical_challenge(challenge: felt252) -> VerifyResult {
    if !is_canonical_scalar(challenge) {
        return Err(VerifyError::NonCanonicalScalar);
    }
    Ok(())
}

#[inline]
fn validate_nonzero_canonical_challenge(challenge: felt252) -> VerifyResult {
    validate_canonical_challenge(challenge)?;
    if !is_nonzero_scalar(challenge) {
        return Err(VerifyError::ZeroChallenge);
    }
    Ok(())
}

#[inline]
pub fn absorb_statement(ref t: Transcript, stmt: SigmaStatement) {
    match stmt {
        SigmaStatement::Schnorr(s) => {
            transcript_append_felt(ref t, TAG_SCHNORR);
            transcript_append_point(ref t, s.public_key);
        },
        SigmaStatement::DLog(s) => {
            transcript_append_felt(ref t, TAG_DLOG);
            transcript_append_point(ref t, s.base);
            transcript_append_point(ref t, s.public_key);
        },
        SigmaStatement::ChaumPed(s) => {
            transcript_append_felt(ref t, TAG_CHAUM_PED);
            transcript_append_point(ref t, s.y1);
            transcript_append_point(ref t, s.y2);
            transcript_append_point(ref t, s.h);
        },
        SigmaStatement::Okamoto(s) => {
            transcript_append_felt(ref t, TAG_OKAMOTO);
            let n_felt: felt252 = s.bases.len().into();
            transcript_append_felt(ref t, n_felt);
            let mut bases = s.bases;
            loop {
                match bases.pop_front() {
                    Some(p) => transcript_append_point(ref t, *p),
                    None => { break; },
                }
            }
            transcript_append_point(ref t, s.y);
        },
        SigmaStatement::Pedersen(s) => {
            transcript_append_felt(ref t, TAG_PEDERSEN);
            transcript_append_point(ref t, s.value_base);
            transcript_append_point(ref t, s.blinding_base);
            transcript_append_point(ref t, s.commitment);
        },
        SigmaStatement::PedersenEq(s) => {
            transcript_append_felt(ref t, TAG_PEDERSEN_EQ);
            transcript_append_point(ref t, s.value_base1);
            transcript_append_point(ref t, s.blinding_base1);
            transcript_append_point(ref t, s.commitment1);
            transcript_append_point(ref t, s.value_base2);
            transcript_append_point(ref t, s.blinding_base2);
            transcript_append_point(ref t, s.commitment2);
        },
        SigmaStatement::PedersenRerand(s) => {
            transcript_append_felt(ref t, TAG_PEDERSEN_RERAND);
            transcript_append_point(ref t, s.rerand_base);
            transcript_append_point(ref t, s.commitment_from);
            transcript_append_point(ref t, s.commitment_to);
        },
    }
}

#[inline]
fn absorb_statement_protocol(ref t: Transcript, stmt: SigmaStatement) {
    match stmt {
        SigmaStatement::Schnorr(s) => {
            transcript_append_point(ref t, s.public_key);
        },
        SigmaStatement::DLog(s) => {
            transcript_append_point(ref t, s.base);
            transcript_append_point(ref t, s.public_key);
        },
        SigmaStatement::ChaumPed(s) => {
            transcript_append_point(ref t, s.y1);
            transcript_append_point(ref t, s.y2);
            transcript_append_point(ref t, s.h);
        },
        SigmaStatement::Okamoto(s) => {
            let n_felt: felt252 = s.bases.len().into();
            transcript_append_felt(ref t, n_felt);
            let mut bases = s.bases;
            loop {
                match bases.pop_front() {
                    Some(p) => transcript_append_point(ref t, *p),
                    None => { break; },
                }
            }
            transcript_append_point(ref t, s.y);
        },
        SigmaStatement::Pedersen(s) => {
            transcript_append_point(ref t, s.value_base);
            transcript_append_point(ref t, s.blinding_base);
            transcript_append_point(ref t, s.commitment);
        },
        SigmaStatement::PedersenEq(s) => {
            transcript_append_point(ref t, s.value_base1);
            transcript_append_point(ref t, s.blinding_base1);
            transcript_append_point(ref t, s.commitment1);
            transcript_append_point(ref t, s.value_base2);
            transcript_append_point(ref t, s.blinding_base2);
            transcript_append_point(ref t, s.commitment2);
        },
        SigmaStatement::PedersenRerand(s) => {
            transcript_append_point(ref t, s.rerand_base);
            transcript_append_point(ref t, s.commitment_from);
            transcript_append_point(ref t, s.commitment_to);
        },
    }
}

#[inline]
fn transcript_for_statement(stmt: SigmaStatement) -> Transcript {
    match stmt {
        SigmaStatement::Schnorr(_) => transcript_new_schnorr(),
        SigmaStatement::DLog(_) => transcript_new_dlog(),
        SigmaStatement::ChaumPed(_) => transcript_new_chaum_ped(),
        SigmaStatement::Okamoto(_) => transcript_new_okamoto(),
        SigmaStatement::Pedersen(_) => transcript_new_pedersen(),
        SigmaStatement::PedersenEq(_) => transcript_new_pedersen_eq(),
        SigmaStatement::PedersenRerand(_) => transcript_new_pedersen_rerand(),
    }
}

/// computes a statement label used by and/or composition transcripts
/// label = h(protocol_domain, curve_id, statement_payload)
#[inline]
pub fn statement_label(stmt: SigmaStatement) -> felt252 {
    let mut t = transcript_for_statement(stmt);
    absorb_statement_protocol(ref t, stmt);
    transcript_hash(@t)
}

#[inline]
pub fn absorb_commitment(
    ref t: Transcript,
    stmt: SigmaStatement,
    proof: SigmaProof,
) -> VerifyResult {
    match (stmt, proof) {
        (SigmaStatement::Schnorr(_s), SigmaProof::Schnorr(p)) => {
            transcript_append_point(ref t, p.commitment);
            Ok(())
        },
        (SigmaStatement::DLog(_s), SigmaProof::DLog(p)) => {
            transcript_append_point(ref t, p.commitment);
            Ok(())
        },
        (SigmaStatement::ChaumPed(_s), SigmaProof::ChaumPed(p)) => {
            transcript_append_point(ref t, p.r1);
            transcript_append_point(ref t, p.r2);
            Ok(())
        },
        (SigmaStatement::Okamoto(_s), SigmaProof::Okamoto(p)) => {
            transcript_append_point(ref t, p.commitment);
            Ok(())
        },
        (SigmaStatement::Pedersen(_s), SigmaProof::Pedersen(p)) => {
            transcript_append_point(ref t, p.nonce_commitment);
            Ok(())
        },
        (SigmaStatement::PedersenEq(_s), SigmaProof::PedersenEq(p)) => {
            transcript_append_point(ref t, p.nonce_commitment1);
            transcript_append_point(ref t, p.nonce_commitment2);
            Ok(())
        },
        (SigmaStatement::PedersenRerand(_s), SigmaProof::PedersenRerand(p)) => {
            transcript_append_point(ref t, p.nonce_commitment);
            Ok(())
        },
        _ => Err(VerifyError::MismatchedProofType),
    }
}

#[inline]
fn verify_schnorr_with_challenge(
    stmt: SchnorrStatement,
    proof: SchnorrProof,
    challenge: felt252,
) -> VerifyResult {
    if !is_canonical_scalar(proof.response) {
        return Err(VerifyError::NonCanonicalScalar);
    }
    validate_canonical_challenge(challenge)?;

    let Some(g) = generator() else {
        return Err(VerifyError::InvalidPoint);
    };

    let mut lhs_state = EcStateTrait::init();
    lhs_state.add_mul(proof.response, g);
    let lhs = lhs_state.finalize();

    let mut rhs_state = EcStateTrait::init();
    rhs_state.add(proof.commitment);
    rhs_state.add_mul(challenge, stmt.public_key);
    let rhs = rhs_state.finalize();

    if points_equal(lhs, rhs) {
        Ok(())
    } else {
        Err(VerifyError::InvalidProof)
    }
}

#[inline]
fn verify_dlog_with_challenge(
    stmt: DLogStatement,
    proof: DLogProof,
    challenge: felt252,
) -> VerifyResult {
    if !is_canonical_scalar(proof.response) {
        return Err(VerifyError::NonCanonicalScalar);
    }
    validate_canonical_challenge(challenge)?;

    let mut lhs_state = EcStateTrait::init();
    lhs_state.add_mul(proof.response, stmt.base);
    let lhs = lhs_state.finalize();

    let mut rhs_state = EcStateTrait::init();
    rhs_state.add(proof.commitment);
    rhs_state.add_mul(challenge, stmt.public_key);
    let rhs = rhs_state.finalize();

    if points_equal(lhs, rhs) {
        Ok(())
    } else {
        Err(VerifyError::InvalidProof)
    }
}

#[inline]
fn verify_chaum_ped_with_challenge(
    stmt: ChaumPedStatement,
    proof: ChaumPedProof,
    challenge: felt252,
) -> VerifyResult {
    if !is_canonical_scalar(proof.response) {
        return Err(VerifyError::NonCanonicalScalar);
    }
    validate_canonical_challenge(challenge)?;

    let Some(g) = generator() else {
        return Err(VerifyError::InvalidPoint);
    };

    let mut lhs1_state = EcStateTrait::init();
    lhs1_state.add_mul(proof.response, g);
    let lhs1 = lhs1_state.finalize();

    let mut rhs1_state = EcStateTrait::init();
    rhs1_state.add(proof.r1);
    rhs1_state.add_mul(challenge, stmt.y1);
    let rhs1 = rhs1_state.finalize();

    if !points_equal(lhs1, rhs1) {
        return Err(VerifyError::InvalidProof);
    }

    let mut lhs2_state = EcStateTrait::init();
    lhs2_state.add_mul(proof.response, stmt.h);
    let lhs2 = lhs2_state.finalize();

    let mut rhs2_state = EcStateTrait::init();
    rhs2_state.add(proof.r2);
    rhs2_state.add_mul(challenge, stmt.y2);
    let rhs2 = rhs2_state.finalize();

    if points_equal(lhs2, rhs2) {
        Ok(())
    } else {
        Err(VerifyError::InvalidProof)
    }
}

#[inline]
fn verify_okamoto_with_challenge(
    stmt: OkamotoStatement,
    proof: OkamotoProof,
    challenge: felt252,
) -> VerifyResult {
    validate_canonical_challenge(challenge)?;
    if stmt.bases.len() != proof.responses.len() {
        return Err(VerifyError::MismatchedLength);
    }
    let n_u256: u256 = stmt.bases.len().into();
    let zero: u256 = 0;
    if n_u256 == zero || n_u256 > MAX_OKAMOTO_BASES_U256 {
        return Err(VerifyError::InvalidStatement);
    }

    let mut lhs_state = EcStateTrait::init();
    let mut bases_iter = stmt.bases;
    let mut responses_iter = proof.responses;

    loop {
        match bases_iter.pop_front() {
            Some(base) => {
                let Some(s_ref) = responses_iter.pop_front() else {
                    return Err(VerifyError::MismatchedLength);
                };
                let s = *s_ref;
                if !is_canonical_scalar(s) {
                    return Err(VerifyError::NonCanonicalScalar);
                }
                lhs_state.add_mul(s, *base);
            },
            None => { break; },
        }
    }

    let lhs = lhs_state.finalize();

    let mut rhs_state = EcStateTrait::init();
    rhs_state.add(proof.commitment);
    rhs_state.add_mul(challenge, stmt.y);
    let rhs = rhs_state.finalize();

    if points_equal(lhs, rhs) {
        Ok(())
    } else {
        Err(VerifyError::InvalidProof)
    }
}

#[inline]
fn verify_pedersen_with_challenge(
    stmt: PedersenStatement,
    proof: PedersenProof,
    challenge: felt252,
) -> VerifyResult {
    if !is_canonical_scalar(proof.response_value) || !is_canonical_scalar(proof.response_blinding) {
        return Err(VerifyError::NonCanonicalScalar);
    }
    validate_canonical_challenge(challenge)?;

    let mut lhs_state = EcStateTrait::init();
    lhs_state.add_mul(proof.response_value, stmt.value_base);
    lhs_state.add_mul(proof.response_blinding, stmt.blinding_base);
    let lhs = lhs_state.finalize();

    let mut rhs_state = EcStateTrait::init();
    rhs_state.add(proof.nonce_commitment);
    rhs_state.add_mul(challenge, stmt.commitment);
    let rhs = rhs_state.finalize();

    if points_equal(lhs, rhs) {
        Ok(())
    } else {
        Err(VerifyError::InvalidProof)
    }
}

#[inline]
fn verify_pedersen_eq_with_challenge(
    stmt: PedersenEqStatement,
    proof: PedersenEqProof,
    challenge: felt252,
) -> VerifyResult {
    if !is_canonical_scalar(proof.response_value)
        || !is_canonical_scalar(proof.response_blinding1)
        || !is_canonical_scalar(proof.response_blinding2)
    {
        return Err(VerifyError::NonCanonicalScalar);
    }
    validate_canonical_challenge(challenge)?;

    let mut lhs1_state = EcStateTrait::init();
    lhs1_state.add_mul(proof.response_value, stmt.value_base1);
    lhs1_state.add_mul(proof.response_blinding1, stmt.blinding_base1);
    let lhs1 = lhs1_state.finalize();

    let mut rhs1_state = EcStateTrait::init();
    rhs1_state.add(proof.nonce_commitment1);
    rhs1_state.add_mul(challenge, stmt.commitment1);
    let rhs1 = rhs1_state.finalize();

    if !points_equal(lhs1, rhs1) {
        return Err(VerifyError::InvalidProof);
    }

    let mut lhs2_state = EcStateTrait::init();
    lhs2_state.add_mul(proof.response_value, stmt.value_base2);
    lhs2_state.add_mul(proof.response_blinding2, stmt.blinding_base2);
    let lhs2 = lhs2_state.finalize();

    let mut rhs2_state = EcStateTrait::init();
    rhs2_state.add(proof.nonce_commitment2);
    rhs2_state.add_mul(challenge, stmt.commitment2);
    let rhs2 = rhs2_state.finalize();

    if points_equal(lhs2, rhs2) {
        Ok(())
    } else {
        Err(VerifyError::InvalidProof)
    }
}

#[inline]
fn verify_pedersen_rerand_with_challenge(
    stmt: PedersenRerandStatement,
    proof: PedersenRerandProof,
    challenge: felt252,
) -> VerifyResult {
    if !is_canonical_scalar(proof.response) {
        return Err(VerifyError::NonCanonicalScalar);
    }
    validate_canonical_challenge(challenge)?;

    let mut delta_state = EcStateTrait::init();
    delta_state.add(stmt.commitment_to);
    delta_state.add(-stmt.commitment_from);
    let delta = delta_state.finalize();
    let Some(delta_nz) = delta.try_into() else {
        return Err(VerifyError::InvalidStatement);
    };

    let mut lhs_state = EcStateTrait::init();
    lhs_state.add_mul(proof.response, stmt.rerand_base);
    let lhs = lhs_state.finalize();

    let mut rhs_state = EcStateTrait::init();
    rhs_state.add(proof.nonce_commitment);
    rhs_state.add_mul(challenge, delta_nz);
    let rhs = rhs_state.finalize();

    if points_equal(lhs, rhs) {
        Ok(())
    } else {
        Err(VerifyError::InvalidProof)
    }
}

#[inline]
pub fn validate_statement_and_proof(stmt: SigmaStatement, proof: SigmaProof) -> VerifyResult {
    match (stmt, proof) {
        (SigmaStatement::Schnorr(_s), SigmaProof::Schnorr(p)) => {
            if is_canonical_scalar(p.response) { Ok(()) } else { Err(VerifyError::NonCanonicalScalar) }
        },
        (SigmaStatement::DLog(_s), SigmaProof::DLog(p)) => {
            if is_canonical_scalar(p.response) { Ok(()) } else { Err(VerifyError::NonCanonicalScalar) }
        },
        (SigmaStatement::ChaumPed(_s), SigmaProof::ChaumPed(p)) => {
            if is_canonical_scalar(p.response) { Ok(()) } else { Err(VerifyError::NonCanonicalScalar) }
        },
        (SigmaStatement::Okamoto(s), SigmaProof::Okamoto(p)) => {
            if s.bases.len() != p.responses.len() {
                return Err(VerifyError::MismatchedLength);
            }
            let n_u256: u256 = s.bases.len().into();
            let zero: u256 = 0;
            if n_u256 == zero || n_u256 > MAX_OKAMOTO_BASES_U256 {
                return Err(VerifyError::InvalidStatement);
            }
            let mut responses = p.responses;
            loop {
                match responses.pop_front() {
                    Some(s_ref) => {
                        let s_val = *s_ref;
                        if !is_canonical_scalar(s_val) {
                            return Err(VerifyError::NonCanonicalScalar);
                        }
                    },
                    None => { break; },
                }
            }
            Ok(())
        },
        (SigmaStatement::Pedersen(_s), SigmaProof::Pedersen(p)) => {
            if !is_canonical_scalar(p.response_value) || !is_canonical_scalar(p.response_blinding) {
                return Err(VerifyError::NonCanonicalScalar);
            }
            Ok(())
        },
        (SigmaStatement::PedersenEq(_s), SigmaProof::PedersenEq(p)) => {
            if !is_canonical_scalar(p.response_value)
                || !is_canonical_scalar(p.response_blinding1)
                || !is_canonical_scalar(p.response_blinding2)
            {
                return Err(VerifyError::NonCanonicalScalar);
            }
            Ok(())
        },
        (SigmaStatement::PedersenRerand(s), SigmaProof::PedersenRerand(p)) => {
            if !is_canonical_scalar(p.response) {
                return Err(VerifyError::NonCanonicalScalar);
            }
            let mut delta_state = EcStateTrait::init();
            delta_state.add(s.commitment_to);
            delta_state.add(-s.commitment_from);
            let delta = delta_state.finalize();
            let maybe_delta_nz: Option<NonZeroEcPoint> = delta.try_into();
            let Some(_delta_nz) = maybe_delta_nz else {
                return Err(VerifyError::InvalidStatement);
            };
            Ok(())
        },
        _ => Err(VerifyError::MismatchedProofType),
    }
}

#[inline]
pub(crate) fn verify_with_challenge_allow_zero(
    stmt: SigmaStatement, proof: SigmaProof, challenge: felt252
) -> VerifyResult {
    match (stmt, proof) {
        (SigmaStatement::Schnorr(s), SigmaProof::Schnorr(p)) => {
            verify_schnorr_with_challenge(s, p, challenge)
        },
        (SigmaStatement::DLog(s), SigmaProof::DLog(p)) => {
            verify_dlog_with_challenge(s, p, challenge)
        },
        (SigmaStatement::ChaumPed(s), SigmaProof::ChaumPed(p)) => {
            verify_chaum_ped_with_challenge(s, p, challenge)
        },
        (SigmaStatement::Okamoto(s), SigmaProof::Okamoto(p)) => {
            verify_okamoto_with_challenge(s, p, challenge)
        },
        (SigmaStatement::Pedersen(s), SigmaProof::Pedersen(p)) => {
            verify_pedersen_with_challenge(s, p, challenge)
        },
        (SigmaStatement::PedersenEq(s), SigmaProof::PedersenEq(p)) => {
            verify_pedersen_eq_with_challenge(s, p, challenge)
        },
        (SigmaStatement::PedersenRerand(s), SigmaProof::PedersenRerand(p)) => {
            verify_pedersen_rerand_with_challenge(s, p, challenge)
        },
        _ => Err(VerifyError::MismatchedProofType),
    }
}

#[inline]
pub fn verify_with_challenge(stmt: SigmaStatement, proof: SigmaProof, challenge: felt252) -> VerifyResult {
    validate_nonzero_canonical_challenge(challenge)?;
    verify_with_challenge_allow_zero(stmt, proof, challenge)
}

pub fn derive_challenge(
    stmt: SigmaStatement,
    proof: SigmaProof,
    context: Span<felt252>,
) -> Result<felt252, VerifyError> {
    validate_statement_and_proof(stmt, proof)?;
    let mut t = transcript_for_statement(stmt);
    absorb_statement_protocol(ref t, stmt);
    absorb_commitment(ref t, stmt, proof)?;
    transcript_append_span(ref t, context);
    let Some(challenge) = transcript_challenge(@t) else {
        return Err(VerifyError::ZeroChallenge);
    };
    Ok(challenge)
}

pub fn verify_batchable(
    stmt: SigmaStatement,
    proof: SigmaProof,
    context: Span<felt252>,
) -> VerifyResult {
    let challenge = derive_challenge(stmt, proof, context)?;
    verify_with_challenge(stmt, proof, challenge)
}

use core::array::{Array, ArrayTrait, Span, SpanTrait};
use core::ec::{EcPoint, EcStateTrait, NonZeroEcPoint};
use core::option::Option;
use core::traits::{Into, TryInto};

use crate::protocols::types::{
    SchnorrStatement, SchnorrProof,
    DLogStatement, DLogProof,
    ChaumPedStatement, ChaumPedProof,
    OkamotoStatement, OkamotoProof,
    PedersenStatement, PedersenProof,
    PedersenEqStatement, PedersenEqProof,
    PedersenRerandStatement, PedersenRerandProof,
};
use crate::core::curve::{generator, reject_identity};
use crate::core::errors::{VerifyError, VerifyResult};
use crate::core::limits::MAX_OKAMOTO_BASES_U256;
use crate::core::scalar::{is_canonical_scalar, reduce_mod_order};
use crate::utils::bytes::{pop_point_be64, pop_scalar_be32, POINT_BYTES, SCALAR_BYTES};
use crate::core::transcript::{
    transcript_new_batch,
    transcript_append_felt,
    transcript_append_scalar,
    transcript_hash,
    transcript_challenge,
    build_schnorr_transcript,
    build_dlog_transcript,
    build_chaum_ped_transcript,
    build_okamoto_transcript,
    build_pedersen_transcript,
    build_pedersen_eq_transcript,
    build_pedersen_rerand_transcript,
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
fn derive_batch_seed(
    challenges: Span<felt252>,
    responses: Span<felt252>,
) -> Result<felt252, VerifyError> {
    // spec 3.5 seeds coefficients from h(c, s)
    let mut t = transcript_new_batch();
    let c_len: felt252 = challenges.len().into();
    transcript_append_felt(ref t, c_len);
    let mut c_iter = challenges;
    loop {
        match c_iter.pop_front() {
            Some(c_ref) => {
                let Some(_) = transcript_append_scalar(ref t, *c_ref) else {
                    return Err(VerifyError::NonCanonicalScalar);
                };
            },
            None => { break; },
        }
    }

    let s_len: felt252 = responses.len().into();
    transcript_append_felt(ref t, s_len);
    let mut s_iter = responses;
    loop {
        match s_iter.pop_front() {
            Some(s_ref) => {
                let Some(_) = transcript_append_scalar(ref t, *s_ref) else {
                    return Err(VerifyError::NonCanonicalScalar);
                };
            },
            None => { break; },
        }
    }
    Ok(transcript_hash(@t))
}

#[inline]
fn batch_alpha(seed: felt252, index: u32) -> felt252 {
    if index == 0 {
        return 1;
    }
    let idx: felt252 = index.into();
    let mut t = transcript_new_batch();
    transcript_append_felt(ref t, seed);
    transcript_append_felt(ref t, idx);
    // keep batch coefficients in f* so no instance is dropped from the aggregate check
    let alpha = reduce_mod_order(transcript_hash(@t));
    if alpha == 0 { 1 } else { alpha }
}

const SCHNORR_STATEMENT_BYTES: u32 = POINT_BYTES;
const SCHNORR_PROOF_BYTES: u32 = POINT_BYTES + SCALAR_BYTES;
const DLOG_STATEMENT_BYTES: u32 = 2 * POINT_BYTES;
const DLOG_PROOF_BYTES: u32 = POINT_BYTES + SCALAR_BYTES;
const CHAUM_PED_STATEMENT_BYTES: u32 = 3 * POINT_BYTES;
const CHAUM_PED_PROOF_BYTES: u32 = 2 * POINT_BYTES + SCALAR_BYTES;
const PEDERSEN_STATEMENT_BYTES: u32 = 3 * POINT_BYTES;
const PEDERSEN_PROOF_BYTES: u32 = POINT_BYTES + 2 * SCALAR_BYTES;
const PEDERSEN_EQ_STATEMENT_BYTES: u32 = 6 * POINT_BYTES;
const PEDERSEN_EQ_PROOF_BYTES: u32 = 2 * POINT_BYTES + 3 * SCALAR_BYTES;
const PEDERSEN_RERAND_STATEMENT_BYTES: u32 = 3 * POINT_BYTES;
const PEDERSEN_RERAND_PROOF_BYTES: u32 = POINT_BYTES + SCALAR_BYTES;

pub fn batch_verify_schnorr(
    statements: Span<SchnorrStatement>,
    proofs: Span<SchnorrProof>,
    context: Span<felt252>,
) -> VerifyResult {
    if statements.len() == 0 {
        return Err(VerifyError::EmptyInstances);
    }
    if statements.len() != proofs.len() {
        return Err(VerifyError::MismatchedLength);
    }

    let mut challenges: Array<felt252> = ArrayTrait::new();
    let mut responses_material: Array<felt252> = ArrayTrait::new();
    let mut pre_stmt_iter = statements;
    let mut pre_proof_iter = proofs;
    loop {
        match pre_stmt_iter.pop_front() {
            Some(stmt_ref) => {
                let Some(proof_ref) = pre_proof_iter.pop_front() else {
                    return Err(VerifyError::MismatchedLength);
                };
                let stmt = *stmt_ref;
                let proof = *proof_ref;
                if !is_canonical_scalar(proof.response) {
                    return Err(VerifyError::NonCanonicalScalar);
                }

                let transcript = build_schnorr_transcript(stmt.public_key, proof.commitment, context);
                let Some(challenge) = transcript_challenge(@transcript) else {
                    return Err(VerifyError::ZeroChallenge);
                };
                challenges.append(challenge);
                responses_material.append(proof.response);
            },
            None => { break; },
        }
    }

    let seed = derive_batch_seed(challenges.span(), responses_material.span())?;

    let Some(g) = generator() else {
        return Err(VerifyError::InvalidPoint);
    };
    let mut lhs_state = EcStateTrait::init();
    let mut rhs_state = EcStateTrait::init();

    let mut idx: u32 = 0;
    let mut challenge_iter = challenges.span();
    let mut stmt_iter = statements;
    let mut proof_iter = proofs;
    loop {
        match stmt_iter.pop_front() {
            Some(stmt_ref) => {
                let Some(proof_ref) = proof_iter.pop_front() else {
                    return Err(VerifyError::MismatchedLength);
                };
                let Some(challenge_ref) = challenge_iter.pop_front() else {
                    return Err(VerifyError::MismatchedLength);
                };
                let stmt = *stmt_ref;
                let proof = *proof_ref;
                let challenge = *challenge_ref;
                let alpha = batch_alpha(seed, idx);

                let mut s_state = EcStateTrait::init();
                s_state.add_mul(proof.response, g);
                let s_point = s_state.finalize();
                if let Some(s_nz) = reject_identity(s_point) {
                    lhs_state.add_mul(alpha, s_nz);
                }

                rhs_state.add_mul(alpha, proof.commitment);
                let mut c_state = EcStateTrait::init();
                c_state.add_mul(challenge, stmt.public_key);
                let c_point = c_state.finalize();
                let Some(c_nz) = reject_identity(c_point) else {
                    return Err(VerifyError::InvalidProof);
                };
                rhs_state.add_mul(alpha, c_nz);
                idx += 1;
            },
            None => { break; },
        }
    }

    let lhs = lhs_state.finalize();
    let rhs = rhs_state.finalize();
    if points_equal(lhs, rhs) { Ok(()) } else { Err(VerifyError::InvalidProof) }
}

pub fn batch_verify_dlog(
    statements: Span<DLogStatement>,
    proofs: Span<DLogProof>,
    context: Span<felt252>,
) -> VerifyResult {
    if statements.len() == 0 {
        return Err(VerifyError::EmptyInstances);
    }
    if statements.len() != proofs.len() {
        return Err(VerifyError::MismatchedLength);
    }

    let mut challenges: Array<felt252> = ArrayTrait::new();
    let mut responses_material: Array<felt252> = ArrayTrait::new();
    let mut pre_stmt_iter = statements;
    let mut pre_proof_iter = proofs;
    loop {
        match pre_stmt_iter.pop_front() {
            Some(stmt_ref) => {
                let Some(proof_ref) = pre_proof_iter.pop_front() else {
                    return Err(VerifyError::MismatchedLength);
                };
                let stmt = *stmt_ref;
                let proof = *proof_ref;
                if !is_canonical_scalar(proof.response) {
                    return Err(VerifyError::NonCanonicalScalar);
                }

                let transcript = build_dlog_transcript(stmt.base, stmt.public_key, proof.commitment, context);
                let Some(challenge) = transcript_challenge(@transcript) else {
                    return Err(VerifyError::ZeroChallenge);
                };
                challenges.append(challenge);
                responses_material.append(proof.response);
            },
            None => { break; },
        }
    }

    let seed = derive_batch_seed(challenges.span(), responses_material.span())?;

    let mut lhs_state = EcStateTrait::init();
    let mut rhs_state = EcStateTrait::init();

    let mut idx: u32 = 0;
    let mut challenge_iter = challenges.span();
    let mut stmt_iter = statements;
    let mut proof_iter = proofs;
    loop {
        match stmt_iter.pop_front() {
            Some(stmt_ref) => {
                let Some(proof_ref) = proof_iter.pop_front() else {
                    return Err(VerifyError::MismatchedLength);
                };
                let Some(challenge_ref) = challenge_iter.pop_front() else {
                    return Err(VerifyError::MismatchedLength);
                };
                let stmt = *stmt_ref;
                let proof = *proof_ref;
                let challenge = *challenge_ref;
                let alpha = batch_alpha(seed, idx);

                let mut s_state = EcStateTrait::init();
                s_state.add_mul(proof.response, stmt.base);
                let s_point = s_state.finalize();
                if let Some(s_nz) = reject_identity(s_point) {
                    lhs_state.add_mul(alpha, s_nz);
                }

                rhs_state.add_mul(alpha, proof.commitment);
                let mut c_state = EcStateTrait::init();
                c_state.add_mul(challenge, stmt.public_key);
                let c_point = c_state.finalize();
                let Some(c_nz) = reject_identity(c_point) else {
                    return Err(VerifyError::InvalidProof);
                };
                rhs_state.add_mul(alpha, c_nz);
                idx += 1;
            },
            None => { break; },
        }
    }

    let lhs = lhs_state.finalize();
    let rhs = rhs_state.finalize();
    if points_equal(lhs, rhs) { Ok(()) } else { Err(VerifyError::InvalidProof) }
}

pub fn batch_verify_chaum_ped(
    statements: Span<ChaumPedStatement>,
    proofs: Span<ChaumPedProof>,
    context: Span<felt252>,
) -> VerifyResult {
    if statements.len() == 0 {
        return Err(VerifyError::EmptyInstances);
    }
    if statements.len() != proofs.len() {
        return Err(VerifyError::MismatchedLength);
    }

    let mut challenges: Array<felt252> = ArrayTrait::new();
    let mut responses_material: Array<felt252> = ArrayTrait::new();
    let mut pre_stmt_iter = statements;
    let mut pre_proof_iter = proofs;
    loop {
        match pre_stmt_iter.pop_front() {
            Some(stmt_ref) => {
                let Some(proof_ref) = pre_proof_iter.pop_front() else {
                    return Err(VerifyError::MismatchedLength);
                };
                let stmt = *stmt_ref;
                let proof = *proof_ref;
                if !is_canonical_scalar(proof.response) {
                    return Err(VerifyError::NonCanonicalScalar);
                }

                let transcript = build_chaum_ped_transcript(
                    stmt.y1,
                    stmt.y2,
                    stmt.h,
                    proof.r1,
                    proof.r2,
                    context,
                );
                let Some(challenge) = transcript_challenge(@transcript) else {
                    return Err(VerifyError::ZeroChallenge);
                };
                challenges.append(challenge);
                responses_material.append(proof.response);
            },
            None => { break; },
        }
    }

    let seed = derive_batch_seed(challenges.span(), responses_material.span())?;

    let Some(g) = generator() else {
        return Err(VerifyError::InvalidPoint);
    };
    let mut lhs1_state = EcStateTrait::init();
    let mut rhs1_state = EcStateTrait::init();
    let mut lhs2_state = EcStateTrait::init();
    let mut rhs2_state = EcStateTrait::init();

    let mut idx: u32 = 0;
    let mut challenge_iter = challenges.span();
    let mut stmt_iter = statements;
    let mut proof_iter = proofs;
    loop {
        match stmt_iter.pop_front() {
            Some(stmt_ref) => {
                let Some(proof_ref) = proof_iter.pop_front() else {
                    return Err(VerifyError::MismatchedLength);
                };
                let Some(challenge_ref) = challenge_iter.pop_front() else {
                    return Err(VerifyError::MismatchedLength);
                };
                let stmt = *stmt_ref;
                let proof = *proof_ref;
                let challenge = *challenge_ref;
                let alpha = batch_alpha(seed, idx);

                let mut s1_state = EcStateTrait::init();
                s1_state.add_mul(proof.response, g);
                let s1_point = s1_state.finalize();
                if let Some(s1_nz) = reject_identity(s1_point) {
                    lhs1_state.add_mul(alpha, s1_nz);
                }
                rhs1_state.add_mul(alpha, proof.r1);
                let mut c1_state = EcStateTrait::init();
                c1_state.add_mul(challenge, stmt.y1);
                let c1_point = c1_state.finalize();
                let Some(c1_nz) = reject_identity(c1_point) else {
                    return Err(VerifyError::InvalidProof);
                };
                rhs1_state.add_mul(alpha, c1_nz);

                let mut s2_state = EcStateTrait::init();
                s2_state.add_mul(proof.response, stmt.h);
                let s2_point = s2_state.finalize();
                if let Some(s2_nz) = reject_identity(s2_point) {
                    lhs2_state.add_mul(alpha, s2_nz);
                }
                rhs2_state.add_mul(alpha, proof.r2);
                let mut c2_state = EcStateTrait::init();
                c2_state.add_mul(challenge, stmt.y2);
                let c2_point = c2_state.finalize();
                let Some(c2_nz) = reject_identity(c2_point) else {
                    return Err(VerifyError::InvalidProof);
                };
                rhs2_state.add_mul(alpha, c2_nz);

                idx += 1;
            },
            None => { break; },
        }
    }

    let lhs1 = lhs1_state.finalize();
    let rhs1 = rhs1_state.finalize();
    if !points_equal(lhs1, rhs1) {
        return Err(VerifyError::InvalidProof);
    }
    let lhs2 = lhs2_state.finalize();
    let rhs2 = rhs2_state.finalize();
    if points_equal(lhs2, rhs2) { Ok(()) } else { Err(VerifyError::InvalidProof) }
}

pub fn batch_verify_okamoto(
    statements: Span<OkamotoStatement>,
    proofs: Span<OkamotoProof>,
    context: Span<felt252>,
) -> VerifyResult {
    if statements.len() == 0 {
        return Err(VerifyError::EmptyInstances);
    }
    if statements.len() != proofs.len() {
        return Err(VerifyError::MismatchedLength);
    }

    let mut challenges: Array<felt252> = ArrayTrait::new();
    let mut responses_material: Array<felt252> = ArrayTrait::new();
    let mut pre_stmt_iter = statements;
    let mut pre_proof_iter = proofs;
    loop {
        match pre_stmt_iter.pop_front() {
            Some(stmt_ref) => {
                let Some(proof_ref) = pre_proof_iter.pop_front() else {
                    return Err(VerifyError::MismatchedLength);
                };
                let stmt = *stmt_ref;
                let proof = *proof_ref;
                if stmt.bases.len() != proof.responses.len() {
                    return Err(VerifyError::MismatchedLength);
                }
                let n_u256: u256 = stmt.bases.len().into();
                let zero: u256 = 0;
                if n_u256 == zero || n_u256 > MAX_OKAMOTO_BASES_U256 {
                    return Err(VerifyError::InvalidStatement);
                }

                let transcript = build_okamoto_transcript(stmt.bases, stmt.y, proof.commitment, context);
                let Some(challenge) = transcript_challenge(@transcript) else {
                    return Err(VerifyError::ZeroChallenge);
                };
                challenges.append(challenge);

                let mut responses_iter = proof.responses;
                loop {
                    match responses_iter.pop_front() {
                        Some(s_ref) => {
                            let s_val = *s_ref;
                            if !is_canonical_scalar(s_val) {
                                return Err(VerifyError::NonCanonicalScalar);
                            }
                            responses_material.append(s_val);
                        },
                        None => { break; },
                    }
                }
            },
            None => { break; },
        }
    }

    let seed = derive_batch_seed(challenges.span(), responses_material.span())?;

    let mut lhs_state = EcStateTrait::init();
    let mut rhs_state = EcStateTrait::init();

    let mut idx: u32 = 0;
    let mut challenge_iter = challenges.span();
    let mut stmt_iter = statements;
    let mut proof_iter = proofs;
    loop {
        match stmt_iter.pop_front() {
            Some(stmt_ref) => {
                let Some(proof_ref) = proof_iter.pop_front() else {
                    return Err(VerifyError::MismatchedLength);
                };
                let Some(challenge_ref) = challenge_iter.pop_front() else {
                    return Err(VerifyError::MismatchedLength);
                };
                let stmt = *stmt_ref;
                let proof = *proof_ref;
                let challenge = *challenge_ref;
                let alpha = batch_alpha(seed, idx);

                let mut bases_iter2 = stmt.bases;
                let mut responses_iter2 = proof.responses;
                loop {
                    match bases_iter2.pop_front() {
                        Some(base) => {
                            let Some(s_ref) = responses_iter2.pop_front() else {
                                return Err(VerifyError::MismatchedLength);
                            };
                            let s_val = *s_ref;
                            if !is_canonical_scalar(s_val) {
                                return Err(VerifyError::NonCanonicalScalar);
                            }
                            let mut s_state = EcStateTrait::init();
                            s_state.add_mul(s_val, *base);
                            let s_point = s_state.finalize();
                            if let Some(s_nz) = reject_identity(s_point) {
                                lhs_state.add_mul(alpha, s_nz);
                            }
                        },
                        None => { break; },
                    }
                }

                rhs_state.add_mul(alpha, proof.commitment);
                let mut c_state = EcStateTrait::init();
                c_state.add_mul(challenge, stmt.y);
                let c_point = c_state.finalize();
                let Some(c_nz) = reject_identity(c_point) else {
                    return Err(VerifyError::InvalidProof);
                };
                rhs_state.add_mul(alpha, c_nz);
                idx += 1;
            },
            None => { break; },
        }
    }

    let lhs = lhs_state.finalize();
    let rhs = rhs_state.finalize();
    if points_equal(lhs, rhs) { Ok(()) } else { Err(VerifyError::InvalidProof) }
}

pub fn batch_verify_pedersen(
    statements: Span<PedersenStatement>,
    proofs: Span<PedersenProof>,
    context: Span<felt252>,
) -> VerifyResult {
    if statements.len() == 0 {
        return Err(VerifyError::EmptyInstances);
    }
    if statements.len() != proofs.len() {
        return Err(VerifyError::MismatchedLength);
    }

    let mut challenges: Array<felt252> = ArrayTrait::new();
    let mut responses_material: Array<felt252> = ArrayTrait::new();
    let mut pre_stmt_iter = statements;
    let mut pre_proof_iter = proofs;
    loop {
        match pre_stmt_iter.pop_front() {
            Some(stmt_ref) => {
                let Some(proof_ref) = pre_proof_iter.pop_front() else {
                    return Err(VerifyError::MismatchedLength);
                };
                let stmt = *stmt_ref;
                let proof = *proof_ref;
                if !is_canonical_scalar(proof.response_value) || !is_canonical_scalar(proof.response_blinding) {
                    return Err(VerifyError::NonCanonicalScalar);
                }

                let transcript = build_pedersen_transcript(
                    stmt.value_base,
                    stmt.blinding_base,
                    stmt.commitment,
                    proof.nonce_commitment,
                    context,
                );
                let Some(challenge) = transcript_challenge(@transcript) else {
                    return Err(VerifyError::ZeroChallenge);
                };
                challenges.append(challenge);
                responses_material.append(proof.response_value);
                responses_material.append(proof.response_blinding);
            },
            None => { break; },
        }
    }

    let seed = derive_batch_seed(challenges.span(), responses_material.span())?;

    let mut lhs_state = EcStateTrait::init();
    let mut rhs_state = EcStateTrait::init();

    let mut idx: u32 = 0;
    let mut challenge_iter = challenges.span();
    let mut stmt_iter = statements;
    let mut proof_iter = proofs;
    loop {
        match stmt_iter.pop_front() {
            Some(stmt_ref) => {
                let Some(proof_ref) = proof_iter.pop_front() else {
                    return Err(VerifyError::MismatchedLength);
                };
                let Some(challenge_ref) = challenge_iter.pop_front() else {
                    return Err(VerifyError::MismatchedLength);
                };
                let stmt = *stmt_ref;
                let proof = *proof_ref;
                let challenge = *challenge_ref;
                let alpha = batch_alpha(seed, idx);

                let mut sv_state = EcStateTrait::init();
                sv_state.add_mul(proof.response_value, stmt.value_base);
                let sv_point = sv_state.finalize();
                if let Some(sv_nz) = reject_identity(sv_point) {
                    lhs_state.add_mul(alpha, sv_nz);
                }
                let mut sr_state = EcStateTrait::init();
                sr_state.add_mul(proof.response_blinding, stmt.blinding_base);
                let sr_point = sr_state.finalize();
                if let Some(sr_nz) = reject_identity(sr_point) {
                    lhs_state.add_mul(alpha, sr_nz);
                }

                rhs_state.add_mul(alpha, proof.nonce_commitment);
                let mut c_state = EcStateTrait::init();
                c_state.add_mul(challenge, stmt.commitment);
                let c_point = c_state.finalize();
                let Some(c_nz) = reject_identity(c_point) else {
                    return Err(VerifyError::InvalidProof);
                };
                rhs_state.add_mul(alpha, c_nz);
                idx += 1;
            },
            None => { break; },
        }
    }

    let lhs = lhs_state.finalize();
    let rhs = rhs_state.finalize();
    if points_equal(lhs, rhs) { Ok(()) } else { Err(VerifyError::InvalidProof) }
}

pub fn batch_verify_pedersen_eq(
    statements: Span<PedersenEqStatement>,
    proofs: Span<PedersenEqProof>,
    context: Span<felt252>,
) -> VerifyResult {
    if statements.len() == 0 {
        return Err(VerifyError::EmptyInstances);
    }
    if statements.len() != proofs.len() {
        return Err(VerifyError::MismatchedLength);
    }

    let mut challenges: Array<felt252> = ArrayTrait::new();
    let mut responses_material: Array<felt252> = ArrayTrait::new();
    let mut pre_stmt_iter = statements;
    let mut pre_proof_iter = proofs;
    loop {
        match pre_stmt_iter.pop_front() {
            Some(stmt_ref) => {
                let Some(proof_ref) = pre_proof_iter.pop_front() else {
                    return Err(VerifyError::MismatchedLength);
                };
                let stmt = *stmt_ref;
                let proof = *proof_ref;
                if !is_canonical_scalar(proof.response_value)
                    || !is_canonical_scalar(proof.response_blinding1)
                    || !is_canonical_scalar(proof.response_blinding2)
                {
                    return Err(VerifyError::NonCanonicalScalar);
                }

                let transcript = build_pedersen_eq_transcript(
                    stmt.value_base1,
                    stmt.blinding_base1,
                    stmt.commitment1,
                    stmt.value_base2,
                    stmt.blinding_base2,
                    stmt.commitment2,
                    proof.nonce_commitment1,
                    proof.nonce_commitment2,
                    context,
                );
                let Some(challenge) = transcript_challenge(@transcript) else {
                    return Err(VerifyError::ZeroChallenge);
                };
                challenges.append(challenge);
                responses_material.append(proof.response_value);
                responses_material.append(proof.response_blinding1);
                responses_material.append(proof.response_blinding2);
            },
            None => { break; },
        }
    }

    let seed = derive_batch_seed(challenges.span(), responses_material.span())?;

    let mut lhs1_state = EcStateTrait::init();
    let mut rhs1_state = EcStateTrait::init();
    let mut lhs2_state = EcStateTrait::init();
    let mut rhs2_state = EcStateTrait::init();

    let mut idx: u32 = 0;
    let mut challenge_iter = challenges.span();
    let mut stmt_iter = statements;
    let mut proof_iter = proofs;
    loop {
        match stmt_iter.pop_front() {
            Some(stmt_ref) => {
                let Some(proof_ref) = proof_iter.pop_front() else {
                    return Err(VerifyError::MismatchedLength);
                };
                let Some(challenge_ref) = challenge_iter.pop_front() else {
                    return Err(VerifyError::MismatchedLength);
                };
                let stmt = *stmt_ref;
                let proof = *proof_ref;
                let challenge = *challenge_ref;
                let alpha = batch_alpha(seed, idx);

                let mut sv_state = EcStateTrait::init();
                sv_state.add_mul(proof.response_value, stmt.value_base1);
                let sv_point = sv_state.finalize();
                if let Some(sv_nz) = reject_identity(sv_point) {
                    lhs1_state.add_mul(alpha, sv_nz);
                }
                let mut sv2_state = EcStateTrait::init();
                sv2_state.add_mul(proof.response_value, stmt.value_base2);
                let sv2_point = sv2_state.finalize();
                if let Some(sv2_nz) = reject_identity(sv2_point) {
                    lhs2_state.add_mul(alpha, sv2_nz);
                }
                let mut sr1_state = EcStateTrait::init();
                sr1_state.add_mul(proof.response_blinding1, stmt.blinding_base1);
                let sr1_point = sr1_state.finalize();
                if let Some(sr1_nz) = reject_identity(sr1_point) {
                    lhs1_state.add_mul(alpha, sr1_nz);
                }
                let mut sr2_state = EcStateTrait::init();
                sr2_state.add_mul(proof.response_blinding2, stmt.blinding_base2);
                let sr2_point = sr2_state.finalize();
                if let Some(sr2_nz) = reject_identity(sr2_point) {
                    lhs2_state.add_mul(alpha, sr2_nz);
                }

                rhs1_state.add_mul(alpha, proof.nonce_commitment1);
                rhs2_state.add_mul(alpha, proof.nonce_commitment2);
                let mut c1_state = EcStateTrait::init();
                c1_state.add_mul(challenge, stmt.commitment1);
                let c1_point = c1_state.finalize();
                let Some(c1_nz) = reject_identity(c1_point) else {
                    return Err(VerifyError::InvalidProof);
                };
                rhs1_state.add_mul(alpha, c1_nz);
                let mut c2_state = EcStateTrait::init();
                c2_state.add_mul(challenge, stmt.commitment2);
                let c2_point = c2_state.finalize();
                let Some(c2_nz) = reject_identity(c2_point) else {
                    return Err(VerifyError::InvalidProof);
                };
                rhs2_state.add_mul(alpha, c2_nz);
                idx += 1;
            },
            None => { break; },
        }
    }

    let lhs1 = lhs1_state.finalize();
    let rhs1 = rhs1_state.finalize();
    if !points_equal(lhs1, rhs1) {
        return Err(VerifyError::InvalidProof);
    }
    let lhs2 = lhs2_state.finalize();
    let rhs2 = rhs2_state.finalize();
    if points_equal(lhs2, rhs2) { Ok(()) } else { Err(VerifyError::InvalidProof) }
}

pub fn batch_verify_pedersen_rerand(
    statements: Span<PedersenRerandStatement>,
    proofs: Span<PedersenRerandProof>,
    context: Span<felt252>,
) -> VerifyResult {
    if statements.len() == 0 {
        return Err(VerifyError::EmptyInstances);
    }
    if statements.len() != proofs.len() {
        return Err(VerifyError::MismatchedLength);
    }

    let mut challenges: Array<felt252> = ArrayTrait::new();
    let mut responses_material: Array<felt252> = ArrayTrait::new();
    let mut pre_stmt_iter = statements;
    let mut pre_proof_iter = proofs;
    loop {
        match pre_stmt_iter.pop_front() {
            Some(stmt_ref) => {
                let Some(proof_ref) = pre_proof_iter.pop_front() else {
                    return Err(VerifyError::MismatchedLength);
                };
                let stmt = *stmt_ref;
                let proof = *proof_ref;
                if !is_canonical_scalar(proof.response) {
                    return Err(VerifyError::NonCanonicalScalar);
                }

                let transcript = build_pedersen_rerand_transcript(
                    stmt.rerand_base,
                    stmt.commitment_from,
                    stmt.commitment_to,
                    proof.nonce_commitment,
                    context,
                );
                let Some(challenge) = transcript_challenge(@transcript) else {
                    return Err(VerifyError::ZeroChallenge);
                };
                challenges.append(challenge);
                responses_material.append(proof.response);
            },
            None => { break; },
        }
    }

    let seed = derive_batch_seed(challenges.span(), responses_material.span())?;

    let mut lhs_state = EcStateTrait::init();
    let mut rhs_state = EcStateTrait::init();

    let mut idx: u32 = 0;
    let mut challenge_iter = challenges.span();
    let mut stmt_iter = statements;
    let mut proof_iter = proofs;
    loop {
        match stmt_iter.pop_front() {
            Some(stmt_ref) => {
                let Some(proof_ref) = proof_iter.pop_front() else {
                    return Err(VerifyError::MismatchedLength);
                };
                let Some(challenge_ref) = challenge_iter.pop_front() else {
                    return Err(VerifyError::MismatchedLength);
                };
                let stmt = *stmt_ref;
                let proof = *proof_ref;
                let challenge = *challenge_ref;
                let alpha = batch_alpha(seed, idx);

                let mut delta_state = EcStateTrait::init();
                delta_state.add(stmt.commitment_to);
                delta_state.add(-stmt.commitment_from);
                let delta = delta_state.finalize();
                let Some(delta_nz) = reject_identity(delta) else {
                    return Err(VerifyError::InvalidStatement);
                };

                let mut s_state = EcStateTrait::init();
                s_state.add_mul(proof.response, stmt.rerand_base);
                let s_point = s_state.finalize();
                if let Some(s_nz) = reject_identity(s_point) {
                    lhs_state.add_mul(alpha, s_nz);
                }

                rhs_state.add_mul(alpha, proof.nonce_commitment);
                let mut c_state = EcStateTrait::init();
                c_state.add_mul(challenge, delta_nz);
                let c_point = c_state.finalize();
                let Some(c_nz) = reject_identity(c_point) else {
                    return Err(VerifyError::InvalidProof);
                };
                rhs_state.add_mul(alpha, c_nz);
                idx += 1;
            },
            None => { break; },
        }
    }

    let lhs = lhs_state.finalize();
    let rhs = rhs_state.finalize();
    if points_equal(lhs, rhs) { Ok(()) } else { Err(VerifyError::InvalidProof) }
}

pub fn batch_verify_schnorr_bytes(
    statements: Span<u8>,
    proofs: Span<u8>,
    context: Span<felt252>,
) -> VerifyResult {
    if statements.len() % SCHNORR_STATEMENT_BYTES != 0 {
        return Err(VerifyError::InvalidEncoding);
    }
    let count: u32 = statements.len() / SCHNORR_STATEMENT_BYTES;
    if count == 0 {
        return Err(VerifyError::EmptyInstances);
    }
    if proofs.len() != count * SCHNORR_PROOF_BYTES {
        return Err(VerifyError::InvalidEncoding);
    }

    let mut stmt_data = statements;
    let mut stmts: Array<SchnorrStatement> = ArrayTrait::new();
    let mut i: u32 = 0;
    loop {
        if i >= count {
            break;
        }
        let pk = pop_point_be64(ref stmt_data)?;
        stmts.append(SchnorrStatement { public_key: pk });
        i += 1;
    }
    if stmt_data.len() != 0 {
        return Err(VerifyError::InvalidEncoding);
    }

    let mut proof_data = proofs;
    let mut proofs_arr: Array<SchnorrProof> = ArrayTrait::new();
    i = 0;
    loop {
        if i >= count {
            break;
        }
        let commitment = pop_point_be64(ref proof_data)?;
        let response = pop_scalar_be32(ref proof_data)?;
        proofs_arr.append(SchnorrProof { commitment, response });
        i += 1;
    }
    if proof_data.len() != 0 {
        return Err(VerifyError::InvalidEncoding);
    }

    batch_verify_schnorr(stmts.span(), proofs_arr.span(), context)
}

pub fn batch_verify_dlog_bytes(
    statements: Span<u8>,
    proofs: Span<u8>,
    context: Span<felt252>,
) -> VerifyResult {
    if statements.len() % DLOG_STATEMENT_BYTES != 0 {
        return Err(VerifyError::InvalidEncoding);
    }
    let count: u32 = statements.len() / DLOG_STATEMENT_BYTES;
    if count == 0 {
        return Err(VerifyError::EmptyInstances);
    }
    if proofs.len() != count * DLOG_PROOF_BYTES {
        return Err(VerifyError::InvalidEncoding);
    }

    let mut stmt_data = statements;
    let mut stmts: Array<DLogStatement> = ArrayTrait::new();
    let mut i: u32 = 0;
    loop {
        if i >= count {
            break;
        }
        let base = pop_point_be64(ref stmt_data)?;
        let pk = pop_point_be64(ref stmt_data)?;
        stmts.append(DLogStatement { base, public_key: pk });
        i += 1;
    }
    if stmt_data.len() != 0 {
        return Err(VerifyError::InvalidEncoding);
    }

    let mut proof_data = proofs;
    let mut proofs_arr: Array<DLogProof> = ArrayTrait::new();
    i = 0;
    loop {
        if i >= count {
            break;
        }
        let commitment = pop_point_be64(ref proof_data)?;
        let response = pop_scalar_be32(ref proof_data)?;
        proofs_arr.append(DLogProof { commitment, response });
        i += 1;
    }
    if proof_data.len() != 0 {
        return Err(VerifyError::InvalidEncoding);
    }

    batch_verify_dlog(stmts.span(), proofs_arr.span(), context)
}

pub fn batch_verify_chaum_ped_bytes(
    statements: Span<u8>,
    proofs: Span<u8>,
    context: Span<felt252>,
) -> VerifyResult {
    if statements.len() % CHAUM_PED_STATEMENT_BYTES != 0 {
        return Err(VerifyError::InvalidEncoding);
    }
    let count: u32 = statements.len() / CHAUM_PED_STATEMENT_BYTES;
    if count == 0 {
        return Err(VerifyError::EmptyInstances);
    }
    if proofs.len() != count * CHAUM_PED_PROOF_BYTES {
        return Err(VerifyError::InvalidEncoding);
    }

    let mut stmt_data = statements;
    let mut stmts: Array<ChaumPedStatement> = ArrayTrait::new();
    let mut i: u32 = 0;
    loop {
        if i >= count {
            break;
        }
        let y1 = pop_point_be64(ref stmt_data)?;
        let y2 = pop_point_be64(ref stmt_data)?;
        let h = pop_point_be64(ref stmt_data)?;
        stmts.append(ChaumPedStatement { y1, y2, h });
        i += 1;
    }
    if stmt_data.len() != 0 {
        return Err(VerifyError::InvalidEncoding);
    }

    let mut proof_data = proofs;
    let mut proofs_arr: Array<ChaumPedProof> = ArrayTrait::new();
    i = 0;
    loop {
        if i >= count {
            break;
        }
        let r1 = pop_point_be64(ref proof_data)?;
        let r2 = pop_point_be64(ref proof_data)?;
        let response = pop_scalar_be32(ref proof_data)?;
        proofs_arr.append(ChaumPedProof { r1, r2, response });
        i += 1;
    }
    if proof_data.len() != 0 {
        return Err(VerifyError::InvalidEncoding);
    }

    batch_verify_chaum_ped(stmts.span(), proofs_arr.span(), context)
}

pub fn batch_verify_okamoto_bytes(
    statements: Span<u8>,
    proofs: Span<u8>,
    context: Span<felt252>,
) -> VerifyResult {
    if statements.len() == 0 {
        return Err(VerifyError::EmptyInstances);
    }

    let mut stmt_data = statements;
    let mut stmts: Array<OkamotoStatement> = ArrayTrait::new();
    let mut counts: Array<u32> = ArrayTrait::new();
    loop {
        if stmt_data.len() == 0 {
            break;
        }
        let n_felt = pop_scalar_be32(ref stmt_data)?;
        let n_u256: u256 = n_felt.into();
        let zero: u256 = 0;
        if n_u256 == zero || n_u256 > MAX_OKAMOTO_BASES_U256 {
            return Err(VerifyError::InvalidStatement);
        }
        let n: u32 = n_felt.try_into().ok_or(VerifyError::InvalidStatement)?;

        let mut bases: Array<NonZeroEcPoint> = ArrayTrait::new();
        let mut i: u32 = 0;
        loop {
            if i >= n {
                break;
            }
            let base = pop_point_be64(ref stmt_data)?;
            bases.append(base);
            i += 1;
        }
        let y = pop_point_be64(ref stmt_data)?;

        stmts.append(OkamotoStatement { bases: bases.span(), y });
        counts.append(n);
    }
    if stmts.len() == 0 {
        return Err(VerifyError::EmptyInstances);
    }

    let mut proof_data = proofs;
    let mut proofs_arr: Array<OkamotoProof> = ArrayTrait::new();
    let mut count_iter = counts.span();
    loop {
        match count_iter.pop_front() {
            Some(n_ref) => {
                let n = *n_ref;
                let commitment = pop_point_be64(ref proof_data)?;
                let mut responses: Array<felt252> = ArrayTrait::new();
                let mut i: u32 = 0;
                loop {
                    if i >= n {
                        break;
                    }
                    let s = pop_scalar_be32(ref proof_data)?;
                    responses.append(s);
                    i += 1;
                }
                proofs_arr.append(OkamotoProof { commitment, responses: responses.span() });
            },
            None => { break; },
        }
    }
    if proof_data.len() != 0 {
        return Err(VerifyError::InvalidEncoding);
    }

    batch_verify_okamoto(stmts.span(), proofs_arr.span(), context)
}

pub fn batch_verify_pedersen_bytes(
    statements: Span<u8>,
    proofs: Span<u8>,
    context: Span<felt252>,
) -> VerifyResult {
    if statements.len() % PEDERSEN_STATEMENT_BYTES != 0 {
        return Err(VerifyError::InvalidEncoding);
    }
    let count: u32 = statements.len() / PEDERSEN_STATEMENT_BYTES;
    if count == 0 {
        return Err(VerifyError::EmptyInstances);
    }
    if proofs.len() != count * PEDERSEN_PROOF_BYTES {
        return Err(VerifyError::InvalidEncoding);
    }

    let mut stmt_data = statements;
    let mut stmts: Array<PedersenStatement> = ArrayTrait::new();
    let mut i: u32 = 0;
    loop {
        if i >= count {
            break;
        }
        let value_base = pop_point_be64(ref stmt_data)?;
        let blinding_base = pop_point_be64(ref stmt_data)?;
        let commitment = pop_point_be64(ref stmt_data)?;
        stmts.append(PedersenStatement { value_base, blinding_base, commitment });
        i += 1;
    }
    if stmt_data.len() != 0 {
        return Err(VerifyError::InvalidEncoding);
    }

    let mut proof_data = proofs;
    let mut proofs_arr: Array<PedersenProof> = ArrayTrait::new();
    i = 0;
    loop {
        if i >= count {
            break;
        }
        let nonce_commitment = pop_point_be64(ref proof_data)?;
        let response_value = pop_scalar_be32(ref proof_data)?;
        let response_blinding = pop_scalar_be32(ref proof_data)?;
        proofs_arr.append(PedersenProof { nonce_commitment, response_value, response_blinding });
        i += 1;
    }
    if proof_data.len() != 0 {
        return Err(VerifyError::InvalidEncoding);
    }

    batch_verify_pedersen(stmts.span(), proofs_arr.span(), context)
}

pub fn batch_verify_pedersen_eq_bytes(
    statements: Span<u8>,
    proofs: Span<u8>,
    context: Span<felt252>,
) -> VerifyResult {
    if statements.len() % PEDERSEN_EQ_STATEMENT_BYTES != 0 {
        return Err(VerifyError::InvalidEncoding);
    }
    let count: u32 = statements.len() / PEDERSEN_EQ_STATEMENT_BYTES;
    if count == 0 {
        return Err(VerifyError::EmptyInstances);
    }
    if proofs.len() != count * PEDERSEN_EQ_PROOF_BYTES {
        return Err(VerifyError::InvalidEncoding);
    }

    let mut stmt_data = statements;
    let mut stmts: Array<PedersenEqStatement> = ArrayTrait::new();
    let mut i: u32 = 0;
    loop {
        if i >= count {
            break;
        }
        let value_base1 = pop_point_be64(ref stmt_data)?;
        let blinding_base1 = pop_point_be64(ref stmt_data)?;
        let commitment1 = pop_point_be64(ref stmt_data)?;
        let value_base2 = pop_point_be64(ref stmt_data)?;
        let blinding_base2 = pop_point_be64(ref stmt_data)?;
        let commitment2 = pop_point_be64(ref stmt_data)?;
        stmts.append(PedersenEqStatement {
            commitment1,
            commitment2,
            value_base1,
            blinding_base1,
            value_base2,
            blinding_base2,
        });
        i += 1;
    }
    if stmt_data.len() != 0 {
        return Err(VerifyError::InvalidEncoding);
    }

    let mut proof_data = proofs;
    let mut proofs_arr: Array<PedersenEqProof> = ArrayTrait::new();
    i = 0;
    loop {
        if i >= count {
            break;
        }
        let nonce_commitment1 = pop_point_be64(ref proof_data)?;
        let nonce_commitment2 = pop_point_be64(ref proof_data)?;
        let response_value = pop_scalar_be32(ref proof_data)?;
        let response_blinding1 = pop_scalar_be32(ref proof_data)?;
        let response_blinding2 = pop_scalar_be32(ref proof_data)?;
        proofs_arr.append(PedersenEqProof {
            nonce_commitment1,
            nonce_commitment2,
            response_value,
            response_blinding1,
            response_blinding2,
        });
        i += 1;
    }
    if proof_data.len() != 0 {
        return Err(VerifyError::InvalidEncoding);
    }

    batch_verify_pedersen_eq(stmts.span(), proofs_arr.span(), context)
}

pub fn batch_verify_pedersen_rerand_bytes(
    statements: Span<u8>,
    proofs: Span<u8>,
    context: Span<felt252>,
) -> VerifyResult {
    if statements.len() % PEDERSEN_RERAND_STATEMENT_BYTES != 0 {
        return Err(VerifyError::InvalidEncoding);
    }
    let count: u32 = statements.len() / PEDERSEN_RERAND_STATEMENT_BYTES;
    if count == 0 {
        return Err(VerifyError::EmptyInstances);
    }
    if proofs.len() != count * PEDERSEN_RERAND_PROOF_BYTES {
        return Err(VerifyError::InvalidEncoding);
    }

    let mut stmt_data = statements;
    let mut stmts: Array<PedersenRerandStatement> = ArrayTrait::new();
    let mut i: u32 = 0;
    loop {
        if i >= count {
            break;
        }
        let rerand_base = pop_point_be64(ref stmt_data)?;
        let commitment_from = pop_point_be64(ref stmt_data)?;
        let commitment_to = pop_point_be64(ref stmt_data)?;
        stmts.append(PedersenRerandStatement { rerand_base, commitment_from, commitment_to });
        i += 1;
    }
    if stmt_data.len() != 0 {
        return Err(VerifyError::InvalidEncoding);
    }

    let mut proof_data = proofs;
    let mut proofs_arr: Array<PedersenRerandProof> = ArrayTrait::new();
    i = 0;
    loop {
        if i >= count {
            break;
        }
        let nonce_commitment = pop_point_be64(ref proof_data)?;
        let response = pop_scalar_be32(ref proof_data)?;
        proofs_arr.append(PedersenRerandProof { nonce_commitment, response });
        i += 1;
    }
    if proof_data.len() != 0 {
        return Err(VerifyError::InvalidEncoding);
    }

    batch_verify_pedersen_rerand(stmts.span(), proofs_arr.span(), context)
}

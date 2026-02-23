use starknet_crypto::Felt;

use crate::core::challenge::validate_challenge;
use crate::core::constants::{
    TAG_CHAUM_PED, TAG_DLOG, TAG_OKAMOTO, TAG_PEDERSEN, TAG_PEDERSEN_EQ, TAG_PEDERSEN_RERAND,
    TAG_SCHNORR,
};
use crate::core::curve::{Point, add, ensure_non_identity, generator, mul};
use crate::core::errors::{ProverError, Result};
use crate::core::limits::MAX_OKAMOTO_BASES;
use crate::core::scalar::Scalar;
use crate::core::transcript::{
    Transcript, transcript_new_chaum_ped, transcript_new_dlog, transcript_new_okamoto,
    transcript_new_pedersen, transcript_new_pedersen_eq, transcript_new_pedersen_rerand,
    transcript_new_schnorr,
};
use crate::protocols::types::{
    ChaumPedProof, ChaumPedStatement, DLogProof, DLogStatement, OkamotoProof, OkamotoStatement,
    PedersenEqProof, PedersenEqStatement, PedersenProof, PedersenRerandProof,
    PedersenRerandStatement, PedersenStatement, SchnorrProof, SchnorrStatement, SigmaProof,
    SigmaStatement,
};

#[inline]
fn points_equal(a: &Point, b: &Point) -> bool {
    a == b
}

pub fn absorb_statement(t: &mut Transcript, stmt: &SigmaStatement) -> Result<()> {
    match stmt {
        SigmaStatement::Schnorr(s) => {
            t.append_felt(Felt::from(TAG_SCHNORR));
            ensure_non_identity(&s.public_key)?;
            t.append_point(&s.public_key);
        }
        SigmaStatement::DLog(s) => {
            t.append_felt(Felt::from(TAG_DLOG));
            ensure_non_identity(&s.base)?;
            ensure_non_identity(&s.public_key)?;
            t.append_point(&s.base);
            t.append_point(&s.public_key);
        }
        SigmaStatement::ChaumPed(s) => {
            t.append_felt(Felt::from(TAG_CHAUM_PED));
            ensure_non_identity(&s.y1)?;
            ensure_non_identity(&s.y2)?;
            ensure_non_identity(&s.h)?;
            t.append_point(&s.y1);
            t.append_point(&s.y2);
            t.append_point(&s.h);
        }
        SigmaStatement::Okamoto(s) => {
            t.append_felt(Felt::from(TAG_OKAMOTO));
            t.append_felt(Felt::from(s.bases.len() as u64));
            for base in &s.bases {
                ensure_non_identity(base)?;
                t.append_point(base);
            }
            ensure_non_identity(&s.y)?;
            t.append_point(&s.y);
        }
        SigmaStatement::Pedersen(s) => {
            t.append_felt(Felt::from(TAG_PEDERSEN));
            ensure_non_identity(&s.value_base)?;
            ensure_non_identity(&s.blinding_base)?;
            ensure_non_identity(&s.commitment)?;
            t.append_point(&s.value_base);
            t.append_point(&s.blinding_base);
            t.append_point(&s.commitment);
        }
        SigmaStatement::PedersenEq(s) => {
            t.append_felt(Felt::from(TAG_PEDERSEN_EQ));
            ensure_non_identity(&s.value_base1)?;
            ensure_non_identity(&s.blinding_base1)?;
            ensure_non_identity(&s.commitment1)?;
            ensure_non_identity(&s.value_base2)?;
            ensure_non_identity(&s.blinding_base2)?;
            ensure_non_identity(&s.commitment2)?;
            t.append_point(&s.value_base1);
            t.append_point(&s.blinding_base1);
            t.append_point(&s.commitment1);
            t.append_point(&s.value_base2);
            t.append_point(&s.blinding_base2);
            t.append_point(&s.commitment2);
        }
        SigmaStatement::PedersenRerand(s) => {
            t.append_felt(Felt::from(TAG_PEDERSEN_RERAND));
            ensure_non_identity(&s.rerand_base)?;
            ensure_non_identity(&s.commitment_from)?;
            ensure_non_identity(&s.commitment_to)?;
            t.append_point(&s.rerand_base);
            t.append_point(&s.commitment_from);
            t.append_point(&s.commitment_to);
        }
    }
    Ok(())
}

fn absorb_statement_protocol(t: &mut Transcript, stmt: &SigmaStatement) -> Result<()> {
    match stmt {
        SigmaStatement::Schnorr(s) => {
            ensure_non_identity(&s.public_key)?;
            t.append_point(&s.public_key);
        }
        SigmaStatement::DLog(s) => {
            ensure_non_identity(&s.base)?;
            ensure_non_identity(&s.public_key)?;
            t.append_point(&s.base);
            t.append_point(&s.public_key);
        }
        SigmaStatement::ChaumPed(s) => {
            ensure_non_identity(&s.y1)?;
            ensure_non_identity(&s.y2)?;
            ensure_non_identity(&s.h)?;
            t.append_point(&s.y1);
            t.append_point(&s.y2);
            t.append_point(&s.h);
        }
        SigmaStatement::Okamoto(s) => {
            if s.bases.is_empty() || s.bases.len() > MAX_OKAMOTO_BASES {
                return Err(ProverError::InvalidStatement);
            }
            t.append_felt(Felt::from(s.bases.len() as u64));
            for base in &s.bases {
                ensure_non_identity(base)?;
                t.append_point(base);
            }
            ensure_non_identity(&s.y)?;
            t.append_point(&s.y);
        }
        SigmaStatement::Pedersen(s) => {
            ensure_non_identity(&s.value_base)?;
            ensure_non_identity(&s.blinding_base)?;
            ensure_non_identity(&s.commitment)?;
            t.append_point(&s.value_base);
            t.append_point(&s.blinding_base);
            t.append_point(&s.commitment);
        }
        SigmaStatement::PedersenEq(s) => {
            ensure_non_identity(&s.value_base1)?;
            ensure_non_identity(&s.blinding_base1)?;
            ensure_non_identity(&s.commitment1)?;
            ensure_non_identity(&s.value_base2)?;
            ensure_non_identity(&s.blinding_base2)?;
            ensure_non_identity(&s.commitment2)?;
            t.append_point(&s.value_base1);
            t.append_point(&s.blinding_base1);
            t.append_point(&s.commitment1);
            t.append_point(&s.value_base2);
            t.append_point(&s.blinding_base2);
            t.append_point(&s.commitment2);
        }
        SigmaStatement::PedersenRerand(s) => {
            ensure_non_identity(&s.rerand_base)?;
            ensure_non_identity(&s.commitment_from)?;
            ensure_non_identity(&s.commitment_to)?;
            t.append_point(&s.rerand_base);
            t.append_point(&s.commitment_from);
            t.append_point(&s.commitment_to);
        }
    }
    Ok(())
}

fn transcript_for_statement(stmt: &SigmaStatement) -> Transcript {
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

pub fn absorb_commitment(
    t: &mut Transcript,
    stmt: &SigmaStatement,
    proof: &SigmaProof,
) -> Result<()> {
    match (stmt, proof) {
        (SigmaStatement::Schnorr(_), SigmaProof::Schnorr(p)) => {
            ensure_non_identity(&p.commitment)?;
            t.append_point(&p.commitment);
        }
        (SigmaStatement::DLog(_), SigmaProof::DLog(p)) => {
            ensure_non_identity(&p.commitment)?;
            t.append_point(&p.commitment);
        }
        (SigmaStatement::ChaumPed(_), SigmaProof::ChaumPed(p)) => {
            ensure_non_identity(&p.r1)?;
            ensure_non_identity(&p.r2)?;
            t.append_point(&p.r1);
            t.append_point(&p.r2);
        }
        (SigmaStatement::Okamoto(_), SigmaProof::Okamoto(p)) => {
            ensure_non_identity(&p.commitment)?;
            t.append_point(&p.commitment);
        }
        (SigmaStatement::Pedersen(_), SigmaProof::Pedersen(p)) => {
            ensure_non_identity(&p.nonce_commitment)?;
            t.append_point(&p.nonce_commitment);
        }
        (SigmaStatement::PedersenEq(_), SigmaProof::PedersenEq(p)) => {
            ensure_non_identity(&p.nonce_commitment1)?;
            ensure_non_identity(&p.nonce_commitment2)?;
            t.append_point(&p.nonce_commitment1);
            t.append_point(&p.nonce_commitment2);
        }
        (SigmaStatement::PedersenRerand(_), SigmaProof::PedersenRerand(p)) => {
            ensure_non_identity(&p.nonce_commitment)?;
            t.append_point(&p.nonce_commitment);
        }
        _ => return Err(ProverError::MismatchedProofType),
    }
    Ok(())
}

fn verify_schnorr_with_challenge(
    stmt: &SchnorrStatement,
    proof: &SchnorrProof,
    challenge: &Scalar,
) -> Result<()> {
    let g = generator();
    let lhs = mul(&g, &proof.response);
    let rhs = add(&proof.commitment, &mul(&stmt.public_key, challenge));
    if points_equal(&lhs, &rhs) {
        Ok(())
    } else {
        Err(ProverError::InvalidProof)
    }
}

fn verify_dlog_with_challenge(
    stmt: &DLogStatement,
    proof: &DLogProof,
    challenge: &Scalar,
) -> Result<()> {
    let lhs = mul(&stmt.base, &proof.response);
    let rhs = add(&proof.commitment, &mul(&stmt.public_key, challenge));
    if points_equal(&lhs, &rhs) {
        Ok(())
    } else {
        Err(ProverError::InvalidProof)
    }
}

fn verify_chaum_ped_with_challenge(
    stmt: &ChaumPedStatement,
    proof: &ChaumPedProof,
    challenge: &Scalar,
) -> Result<()> {
    let g = generator();
    let lhs1 = mul(&g, &proof.response);
    let rhs1 = add(&proof.r1, &mul(&stmt.y1, challenge));
    if !points_equal(&lhs1, &rhs1) {
        return Err(ProverError::InvalidProof);
    }
    let lhs2 = mul(&stmt.h, &proof.response);
    let rhs2 = add(&proof.r2, &mul(&stmt.y2, challenge));
    if points_equal(&lhs2, &rhs2) {
        Ok(())
    } else {
        Err(ProverError::InvalidProof)
    }
}

fn verify_okamoto_with_challenge(
    stmt: &OkamotoStatement,
    proof: &OkamotoProof,
    challenge: &Scalar,
) -> Result<()> {
    if stmt.bases.len() != proof.responses.len() {
        return Err(ProverError::MismatchedLength);
    }
    let mut acc = Point::identity();
    for (base, resp) in stmt.bases.iter().zip(proof.responses.iter()) {
        let term = mul(base, resp);
        acc = add(&acc, &term);
    }
    let rhs = add(&proof.commitment, &mul(&stmt.y, challenge));
    if points_equal(&acc, &rhs) {
        Ok(())
    } else {
        Err(ProverError::InvalidProof)
    }
}

fn verify_pedersen_with_challenge(
    stmt: &PedersenStatement,
    proof: &PedersenProof,
    challenge: &Scalar,
) -> Result<()> {
    let lhs = add(
        &mul(&stmt.value_base, &proof.response_value),
        &mul(&stmt.blinding_base, &proof.response_blinding),
    );
    let rhs = add(&proof.nonce_commitment, &mul(&stmt.commitment, challenge));
    if points_equal(&lhs, &rhs) {
        Ok(())
    } else {
        Err(ProverError::InvalidProof)
    }
}

fn verify_pedersen_eq_with_challenge(
    stmt: &PedersenEqStatement,
    proof: &PedersenEqProof,
    challenge: &Scalar,
) -> Result<()> {
    let lhs1 = add(
        &mul(&stmt.value_base1, &proof.response_value),
        &mul(&stmt.blinding_base1, &proof.response_blinding1),
    );
    let rhs1 = add(&proof.nonce_commitment1, &mul(&stmt.commitment1, challenge));
    if !points_equal(&lhs1, &rhs1) {
        return Err(ProverError::InvalidProof);
    }
    let lhs2 = add(
        &mul(&stmt.value_base2, &proof.response_value),
        &mul(&stmt.blinding_base2, &proof.response_blinding2),
    );
    let rhs2 = add(&proof.nonce_commitment2, &mul(&stmt.commitment2, challenge));
    if points_equal(&lhs2, &rhs2) {
        Ok(())
    } else {
        Err(ProverError::InvalidProof)
    }
}

fn verify_pedersen_rerand_with_challenge(
    stmt: &PedersenRerandStatement,
    proof: &PedersenRerandProof,
    challenge: &Scalar,
) -> Result<()> {
    let delta = add(&stmt.commitment_to, &(-&stmt.commitment_from));
    if delta.is_identity() {
        return Err(ProverError::InvalidStatement);
    }
    let lhs = mul(&stmt.rerand_base, &proof.response);
    let rhs = add(&proof.nonce_commitment, &mul(&delta, challenge));
    if points_equal(&lhs, &rhs) {
        Ok(())
    } else {
        Err(ProverError::InvalidProof)
    }
}

pub(crate) fn verify_with_challenge_allow_zero(
    stmt: &SigmaStatement,
    proof: &SigmaProof,
    challenge: &Scalar,
) -> Result<()> {
    challenge.ensure_canonical()?;
    validate_statement_and_proof(stmt, proof)?;
    match (stmt, proof) {
        (SigmaStatement::Schnorr(s), SigmaProof::Schnorr(p)) => {
            verify_schnorr_with_challenge(s, p, challenge)
        }
        (SigmaStatement::DLog(s), SigmaProof::DLog(p)) => {
            verify_dlog_with_challenge(s, p, challenge)
        }
        (SigmaStatement::ChaumPed(s), SigmaProof::ChaumPed(p)) => {
            verify_chaum_ped_with_challenge(s, p, challenge)
        }
        (SigmaStatement::Okamoto(s), SigmaProof::Okamoto(p)) => {
            verify_okamoto_with_challenge(s, p, challenge)
        }
        (SigmaStatement::Pedersen(s), SigmaProof::Pedersen(p)) => {
            verify_pedersen_with_challenge(s, p, challenge)
        }
        (SigmaStatement::PedersenEq(s), SigmaProof::PedersenEq(p)) => {
            verify_pedersen_eq_with_challenge(s, p, challenge)
        }
        (SigmaStatement::PedersenRerand(s), SigmaProof::PedersenRerand(p)) => {
            verify_pedersen_rerand_with_challenge(s, p, challenge)
        }
        _ => Err(ProverError::MismatchedProofType),
    }
}

pub fn verify_with_challenge(
    stmt: &SigmaStatement,
    proof: &SigmaProof,
    challenge: &Scalar,
) -> Result<()> {
    validate_challenge(challenge)?;
    verify_with_challenge_allow_zero(stmt, proof, challenge)
}

pub fn validate_statement_and_proof(stmt: &SigmaStatement, proof: &SigmaProof) -> Result<()> {
    match (stmt, proof) {
        (SigmaStatement::Schnorr(s), SigmaProof::Schnorr(p)) => {
            ensure_non_identity(&s.public_key)?;
            ensure_non_identity(&p.commitment)?;
            p.response.ensure_canonical()?;
            Ok(())
        }
        (SigmaStatement::DLog(s), SigmaProof::DLog(p)) => {
            ensure_non_identity(&s.base)?;
            ensure_non_identity(&s.public_key)?;
            ensure_non_identity(&p.commitment)?;
            p.response.ensure_canonical()?;
            Ok(())
        }
        (SigmaStatement::ChaumPed(s), SigmaProof::ChaumPed(p)) => {
            ensure_non_identity(&s.y1)?;
            ensure_non_identity(&s.y2)?;
            ensure_non_identity(&s.h)?;
            ensure_non_identity(&p.r1)?;
            ensure_non_identity(&p.r2)?;
            p.response.ensure_canonical()?;
            Ok(())
        }
        (SigmaStatement::Okamoto(s), SigmaProof::Okamoto(p)) => {
            if s.bases.is_empty() || s.bases.len() > MAX_OKAMOTO_BASES {
                return Err(ProverError::InvalidStatement);
            }
            if s.bases.len() != p.responses.len() {
                return Err(ProverError::MismatchedLength);
            }
            for base in &s.bases {
                ensure_non_identity(base)?;
            }
            for resp in &p.responses {
                resp.ensure_canonical()?;
            }
            ensure_non_identity(&s.y)?;
            ensure_non_identity(&p.commitment)?;
            Ok(())
        }
        (SigmaStatement::Pedersen(s), SigmaProof::Pedersen(p)) => {
            ensure_non_identity(&s.value_base)?;
            ensure_non_identity(&s.blinding_base)?;
            ensure_non_identity(&s.commitment)?;
            ensure_non_identity(&p.nonce_commitment)?;
            p.response_value.ensure_canonical()?;
            p.response_blinding.ensure_canonical()?;
            Ok(())
        }
        (SigmaStatement::PedersenEq(s), SigmaProof::PedersenEq(p)) => {
            ensure_non_identity(&s.value_base1)?;
            ensure_non_identity(&s.blinding_base1)?;
            ensure_non_identity(&s.commitment1)?;
            ensure_non_identity(&s.value_base2)?;
            ensure_non_identity(&s.blinding_base2)?;
            ensure_non_identity(&s.commitment2)?;
            ensure_non_identity(&p.nonce_commitment1)?;
            ensure_non_identity(&p.nonce_commitment2)?;
            p.response_value.ensure_canonical()?;
            p.response_blinding1.ensure_canonical()?;
            p.response_blinding2.ensure_canonical()?;
            Ok(())
        }
        (SigmaStatement::PedersenRerand(s), SigmaProof::PedersenRerand(p)) => {
            ensure_non_identity(&s.rerand_base)?;
            ensure_non_identity(&s.commitment_from)?;
            ensure_non_identity(&s.commitment_to)?;
            ensure_non_identity(&p.nonce_commitment)?;
            p.response.ensure_canonical()?;
            let delta = add(&s.commitment_to, &(-&s.commitment_from));
            if delta.is_identity() {
                return Err(ProverError::InvalidStatement);
            }
            Ok(())
        }
        _ => Err(ProverError::MismatchedProofType),
    }
}

pub fn derive_challenge(
    stmt: &SigmaStatement,
    proof: &SigmaProof,
    context: &[Felt],
) -> Result<Scalar> {
    validate_statement_and_proof(stmt, proof)?;
    let mut t = transcript_for_statement(stmt);
    absorb_statement_protocol(&mut t, stmt)?;
    absorb_commitment(&mut t, stmt, proof)?;
    t.append_span(context);
    t.challenge()
}

pub fn statement_label(stmt: &SigmaStatement) -> Result<Felt> {
    let mut t = transcript_for_statement(stmt);
    absorb_statement_protocol(&mut t, stmt)?;
    Ok(t.hash())
}

pub fn verify_batchable(stmt: &SigmaStatement, proof: &SigmaProof, context: &[Felt]) -> Result<()> {
    let challenge = derive_challenge(stmt, proof, context)?;
    verify_with_challenge(stmt, proof, &challenge)
}

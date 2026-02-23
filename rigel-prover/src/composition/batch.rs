use starknet_crypto::Felt;

use crate::core::curve::{Point, add, ensure_non_identity, generator, mul, sub};
use crate::core::errors::{ProverError, Result};
use crate::core::limits::MAX_OKAMOTO_BASES;
use crate::core::scalar::Scalar;
use crate::core::transcript::{
    build_chaum_ped_transcript, build_dlog_transcript, build_okamoto_transcript,
    build_pedersen_eq_transcript, build_pedersen_rerand_transcript, build_pedersen_transcript,
    build_schnorr_transcript, transcript_new_batch,
};
use crate::protocols::types::*;

fn derive_batch_seed(challenges: &[Scalar], responses: &[Scalar]) -> Felt {
    // spec 3.5 seeds coefficients from h(c, s)
    let mut t = transcript_new_batch();
    t.append_felt(Felt::from(challenges.len() as u64));
    for c in challenges {
        t.append_scalar(c);
    }
    t.append_felt(Felt::from(responses.len() as u64));
    for s in responses {
        t.append_scalar(s);
    }
    t.hash()
}

fn batch_alpha(seed: &Felt, index: usize) -> Scalar {
    if index == 0 {
        return Scalar::from_u64(1);
    }
    let mut t = transcript_new_batch();
    t.append_felt(*seed);
    t.append_felt(Felt::from(index as u64));
    let alpha = Scalar::from_felt_mod_order(&t.hash());
    if alpha == Scalar::from_u64(0) {
        Scalar::from_u64(1)
    } else {
        alpha
    }
}

pub fn batch_verify_schnorr(
    statements: &[SchnorrStatement],
    proofs: &[SchnorrProof],
    context: &[Felt],
) -> Result<()> {
    if statements.is_empty() {
        return Err(ProverError::EmptyInstances);
    }
    if statements.len() != proofs.len() {
        return Err(ProverError::MismatchedLength);
    }

    let mut challenges = Vec::with_capacity(statements.len());
    let mut responses = Vec::with_capacity(statements.len());
    for (stmt, proof) in statements.iter().zip(proofs.iter()) {
        ensure_non_identity(&stmt.public_key)?;
        ensure_non_identity(&proof.commitment)?;
        proof.response.ensure_canonical()?;
        let transcript = build_schnorr_transcript(&stmt.public_key, &proof.commitment, context);
        let challenge = transcript.challenge()?;
        challenges.push(challenge);
        responses.push(proof.response.clone());
    }
    let seed = derive_batch_seed(&challenges, &responses);

    let g = generator();
    let mut lhs = Point::identity();
    let mut rhs = Point::identity();

    for (idx, ((stmt, proof), challenge)) in statements
        .iter()
        .zip(proofs.iter())
        .zip(challenges.iter())
        .enumerate()
    {
        let alpha = batch_alpha(&seed, idx);

        let s_alpha = proof.response.mul_mod(&alpha);
        let c_alpha = challenge.mul_mod(&alpha);
        lhs = add(&lhs, &mul(&g, &s_alpha));
        rhs = add(&rhs, &mul(&proof.commitment, &alpha));
        rhs = add(&rhs, &mul(&stmt.public_key, &c_alpha));
    }

    if lhs == rhs {
        Ok(())
    } else {
        Err(ProverError::InvalidProof)
    }
}

pub fn batch_verify_dlog(
    statements: &[DLogStatement],
    proofs: &[DLogProof],
    context: &[Felt],
) -> Result<()> {
    if statements.is_empty() {
        return Err(ProverError::EmptyInstances);
    }
    if statements.len() != proofs.len() {
        return Err(ProverError::MismatchedLength);
    }

    let mut challenges = Vec::with_capacity(statements.len());
    let mut responses = Vec::with_capacity(statements.len());
    for (stmt, proof) in statements.iter().zip(proofs.iter()) {
        ensure_non_identity(&stmt.base)?;
        ensure_non_identity(&stmt.public_key)?;
        ensure_non_identity(&proof.commitment)?;
        proof.response.ensure_canonical()?;
        let transcript =
            build_dlog_transcript(&stmt.base, &stmt.public_key, &proof.commitment, context);
        let challenge = transcript.challenge()?;
        challenges.push(challenge);
        responses.push(proof.response.clone());
    }
    let seed = derive_batch_seed(&challenges, &responses);

    let mut lhs = Point::identity();
    let mut rhs = Point::identity();

    for (idx, ((stmt, proof), challenge)) in statements
        .iter()
        .zip(proofs.iter())
        .zip(challenges.iter())
        .enumerate()
    {
        let alpha = batch_alpha(&seed, idx);

        let s_alpha = proof.response.mul_mod(&alpha);
        let c_alpha = challenge.mul_mod(&alpha);
        lhs = add(&lhs, &mul(&stmt.base, &s_alpha));
        rhs = add(&rhs, &mul(&proof.commitment, &alpha));
        rhs = add(&rhs, &mul(&stmt.public_key, &c_alpha));
    }

    if lhs == rhs {
        Ok(())
    } else {
        Err(ProverError::InvalidProof)
    }
}

pub fn batch_verify_chaum_ped(
    statements: &[ChaumPedStatement],
    proofs: &[ChaumPedProof],
    context: &[Felt],
) -> Result<()> {
    if statements.is_empty() {
        return Err(ProverError::EmptyInstances);
    }
    if statements.len() != proofs.len() {
        return Err(ProverError::MismatchedLength);
    }

    let mut challenges = Vec::with_capacity(statements.len());
    let mut responses = Vec::with_capacity(statements.len());
    for (stmt, proof) in statements.iter().zip(proofs.iter()) {
        ensure_non_identity(&stmt.y1)?;
        ensure_non_identity(&stmt.y2)?;
        ensure_non_identity(&stmt.h)?;
        ensure_non_identity(&proof.r1)?;
        ensure_non_identity(&proof.r2)?;
        proof.response.ensure_canonical()?;
        let transcript =
            build_chaum_ped_transcript(&stmt.y1, &stmt.y2, &stmt.h, &proof.r1, &proof.r2, context);
        let challenge = transcript.challenge()?;
        challenges.push(challenge);
        responses.push(proof.response.clone());
    }
    let seed = derive_batch_seed(&challenges, &responses);

    let g = generator();
    let mut lhs1 = Point::identity();
    let mut rhs1 = Point::identity();
    let mut lhs2 = Point::identity();
    let mut rhs2 = Point::identity();

    for (idx, ((stmt, proof), challenge)) in statements
        .iter()
        .zip(proofs.iter())
        .zip(challenges.iter())
        .enumerate()
    {
        let alpha = batch_alpha(&seed, idx);

        let s_alpha = proof.response.mul_mod(&alpha);
        let c_alpha = challenge.mul_mod(&alpha);
        lhs1 = add(&lhs1, &mul(&g, &s_alpha));
        rhs1 = add(&rhs1, &mul(&proof.r1, &alpha));
        rhs1 = add(&rhs1, &mul(&stmt.y1, &c_alpha));

        lhs2 = add(&lhs2, &mul(&stmt.h, &s_alpha));
        rhs2 = add(&rhs2, &mul(&proof.r2, &alpha));
        rhs2 = add(&rhs2, &mul(&stmt.y2, &c_alpha));
    }

    if lhs1 != rhs1 {
        return Err(ProverError::InvalidProof);
    }
    if lhs2 != rhs2 {
        return Err(ProverError::InvalidProof);
    }
    Ok(())
}

pub fn batch_verify_okamoto(
    statements: &[OkamotoStatement],
    proofs: &[OkamotoProof],
    context: &[Felt],
) -> Result<()> {
    if statements.is_empty() {
        return Err(ProverError::EmptyInstances);
    }
    if statements.len() != proofs.len() {
        return Err(ProverError::MismatchedLength);
    }

    let mut challenges = Vec::with_capacity(statements.len());
    let mut responses = Vec::new();
    for (stmt, proof) in statements.iter().zip(proofs.iter()) {
        if stmt.bases.is_empty() || stmt.bases.len() > MAX_OKAMOTO_BASES {
            return Err(ProverError::InvalidStatement);
        }
        if stmt.bases.len() != proof.responses.len() {
            return Err(ProverError::MismatchedLength);
        }
        for base in &stmt.bases {
            ensure_non_identity(base)?;
        }
        for resp in &proof.responses {
            resp.ensure_canonical()?;
        }
        ensure_non_identity(&stmt.y)?;
        ensure_non_identity(&proof.commitment)?;

        let transcript = build_okamoto_transcript(&stmt.bases, &stmt.y, &proof.commitment, context);
        let challenge = transcript.challenge()?;
        challenges.push(challenge);
        for resp in &proof.responses {
            responses.push(resp.clone());
        }
    }
    let seed = derive_batch_seed(&challenges, &responses);

    let mut lhs = Point::identity();
    let mut rhs = Point::identity();

    for (idx, ((stmt, proof), challenge)) in statements
        .iter()
        .zip(proofs.iter())
        .zip(challenges.iter())
        .enumerate()
    {
        let alpha = batch_alpha(&seed, idx);

        for (base, resp) in stmt.bases.iter().zip(proof.responses.iter()) {
            let s_alpha = resp.mul_mod(&alpha);
            lhs = add(&lhs, &mul(base, &s_alpha));
        }
        rhs = add(&rhs, &mul(&proof.commitment, &alpha));
        let c_alpha = challenge.mul_mod(&alpha);
        rhs = add(&rhs, &mul(&stmt.y, &c_alpha));
    }

    if lhs == rhs {
        Ok(())
    } else {
        Err(ProverError::InvalidProof)
    }
}

pub fn batch_verify_pedersen(
    statements: &[PedersenStatement],
    proofs: &[PedersenProof],
    context: &[Felt],
) -> Result<()> {
    if statements.is_empty() {
        return Err(ProverError::EmptyInstances);
    }
    if statements.len() != proofs.len() {
        return Err(ProverError::MismatchedLength);
    }

    let mut challenges = Vec::with_capacity(statements.len());
    let mut responses = Vec::with_capacity(statements.len() * 2);
    for (stmt, proof) in statements.iter().zip(proofs.iter()) {
        ensure_non_identity(&stmt.value_base)?;
        ensure_non_identity(&stmt.blinding_base)?;
        ensure_non_identity(&stmt.commitment)?;
        ensure_non_identity(&proof.nonce_commitment)?;
        proof.response_value.ensure_canonical()?;
        proof.response_blinding.ensure_canonical()?;
        let transcript = build_pedersen_transcript(
            &stmt.value_base,
            &stmt.blinding_base,
            &stmt.commitment,
            &proof.nonce_commitment,
            context,
        );
        let challenge = transcript.challenge()?;
        challenges.push(challenge);
        responses.push(proof.response_value.clone());
        responses.push(proof.response_blinding.clone());
    }
    let seed = derive_batch_seed(&challenges, &responses);

    let mut lhs = Point::identity();
    let mut rhs = Point::identity();

    for (idx, ((stmt, proof), challenge)) in statements
        .iter()
        .zip(proofs.iter())
        .zip(challenges.iter())
        .enumerate()
    {
        let alpha = batch_alpha(&seed, idx);

        let sv_alpha = proof.response_value.mul_mod(&alpha);
        let sr_alpha = proof.response_blinding.mul_mod(&alpha);
        lhs = add(&lhs, &mul(&stmt.value_base, &sv_alpha));
        lhs = add(&lhs, &mul(&stmt.blinding_base, &sr_alpha));

        rhs = add(&rhs, &mul(&proof.nonce_commitment, &alpha));
        let c_alpha = challenge.mul_mod(&alpha);
        rhs = add(&rhs, &mul(&stmt.commitment, &c_alpha));
    }

    if lhs == rhs {
        Ok(())
    } else {
        Err(ProverError::InvalidProof)
    }
}

pub fn batch_verify_pedersen_eq(
    statements: &[PedersenEqStatement],
    proofs: &[PedersenEqProof],
    context: &[Felt],
) -> Result<()> {
    if statements.is_empty() {
        return Err(ProverError::EmptyInstances);
    }
    if statements.len() != proofs.len() {
        return Err(ProverError::MismatchedLength);
    }

    let mut challenges = Vec::with_capacity(statements.len());
    let mut responses = Vec::with_capacity(statements.len() * 3);
    for (stmt, proof) in statements.iter().zip(proofs.iter()) {
        ensure_non_identity(&stmt.value_base1)?;
        ensure_non_identity(&stmt.blinding_base1)?;
        ensure_non_identity(&stmt.commitment1)?;
        ensure_non_identity(&stmt.value_base2)?;
        ensure_non_identity(&stmt.blinding_base2)?;
        ensure_non_identity(&stmt.commitment2)?;
        ensure_non_identity(&proof.nonce_commitment1)?;
        ensure_non_identity(&proof.nonce_commitment2)?;
        proof.response_value.ensure_canonical()?;
        proof.response_blinding1.ensure_canonical()?;
        proof.response_blinding2.ensure_canonical()?;
        let transcript = build_pedersen_eq_transcript(
            &stmt.value_base1,
            &stmt.blinding_base1,
            &stmt.commitment1,
            &stmt.value_base2,
            &stmt.blinding_base2,
            &stmt.commitment2,
            &proof.nonce_commitment1,
            &proof.nonce_commitment2,
            context,
        );
        let challenge = transcript.challenge()?;
        challenges.push(challenge);
        responses.push(proof.response_value.clone());
        responses.push(proof.response_blinding1.clone());
        responses.push(proof.response_blinding2.clone());
    }
    let seed = derive_batch_seed(&challenges, &responses);

    let mut lhs1 = Point::identity();
    let mut rhs1 = Point::identity();
    let mut lhs2 = Point::identity();
    let mut rhs2 = Point::identity();

    for (idx, ((stmt, proof), challenge)) in statements
        .iter()
        .zip(proofs.iter())
        .zip(challenges.iter())
        .enumerate()
    {
        let alpha = batch_alpha(&seed, idx);

        let sv_alpha = proof.response_value.mul_mod(&alpha);
        lhs1 = add(&lhs1, &mul(&stmt.value_base1, &sv_alpha));
        lhs2 = add(&lhs2, &mul(&stmt.value_base2, &sv_alpha));

        let sr1_alpha = proof.response_blinding1.mul_mod(&alpha);
        let sr2_alpha = proof.response_blinding2.mul_mod(&alpha);
        lhs1 = add(&lhs1, &mul(&stmt.blinding_base1, &sr1_alpha));
        lhs2 = add(&lhs2, &mul(&stmt.blinding_base2, &sr2_alpha));

        rhs1 = add(&rhs1, &mul(&proof.nonce_commitment1, &alpha));
        rhs2 = add(&rhs2, &mul(&proof.nonce_commitment2, &alpha));

        let c_alpha = challenge.mul_mod(&alpha);
        rhs1 = add(&rhs1, &mul(&stmt.commitment1, &c_alpha));
        rhs2 = add(&rhs2, &mul(&stmt.commitment2, &c_alpha));
    }

    if lhs1 != rhs1 {
        return Err(ProverError::InvalidProof);
    }
    if lhs2 != rhs2 {
        return Err(ProverError::InvalidProof);
    }
    Ok(())
}

pub fn batch_verify_pedersen_rerand(
    statements: &[PedersenRerandStatement],
    proofs: &[PedersenRerandProof],
    context: &[Felt],
) -> Result<()> {
    if statements.is_empty() {
        return Err(ProverError::EmptyInstances);
    }
    if statements.len() != proofs.len() {
        return Err(ProverError::MismatchedLength);
    }

    let mut challenges = Vec::with_capacity(statements.len());
    let mut responses = Vec::with_capacity(statements.len());
    for (stmt, proof) in statements.iter().zip(proofs.iter()) {
        ensure_non_identity(&stmt.rerand_base)?;
        ensure_non_identity(&stmt.commitment_from)?;
        ensure_non_identity(&stmt.commitment_to)?;
        ensure_non_identity(&proof.nonce_commitment)?;
        proof.response.ensure_canonical()?;
        let transcript = build_pedersen_rerand_transcript(
            &stmt.rerand_base,
            &stmt.commitment_from,
            &stmt.commitment_to,
            &proof.nonce_commitment,
            context,
        );
        let challenge = transcript.challenge()?;
        challenges.push(challenge);
        responses.push(proof.response.clone());
    }
    let seed = derive_batch_seed(&challenges, &responses);

    let mut lhs = Point::identity();
    let mut rhs = Point::identity();

    for (idx, ((stmt, proof), challenge)) in statements
        .iter()
        .zip(proofs.iter())
        .zip(challenges.iter())
        .enumerate()
    {
        let alpha = batch_alpha(&seed, idx);

        let delta = sub(&stmt.commitment_to, &stmt.commitment_from);
        if delta.is_identity() {
            return Err(ProverError::InvalidStatement);
        }

        let s_alpha = proof.response.mul_mod(&alpha);
        lhs = add(&lhs, &mul(&stmt.rerand_base, &s_alpha));
        rhs = add(&rhs, &mul(&proof.nonce_commitment, &alpha));
        let c_alpha = challenge.mul_mod(&alpha);
        rhs = add(&rhs, &mul(&delta, &c_alpha));
    }

    if lhs == rhs {
        Ok(())
    } else {
        Err(ProverError::InvalidProof)
    }
}

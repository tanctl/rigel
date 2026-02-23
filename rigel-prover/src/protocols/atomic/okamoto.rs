use rand::RngCore;
use starknet_crypto::Felt;

use crate::core::challenge::validate_challenge;
use crate::core::curve::{Point, add, ensure_non_identity, mul, reject_identity, sub};
use crate::core::errors::{ProverError, Result};
use crate::core::limits::MAX_OKAMOTO_BASES;
use crate::core::scalar::Scalar;
use crate::core::sigma::{derive_challenge, verify_batchable, verify_with_challenge};
use crate::core::transcript::build_okamoto_transcript;
use crate::protocols::types::{
    OkamotoProof, OkamotoShortProof, OkamotoStatement, SigmaProof, SigmaStatement,
};

fn lincomb(bases: &[Point], scalars: &[Scalar]) -> Result<Point> {
    if bases.len() != scalars.len() {
        return Err(ProverError::MismatchedLength);
    }
    let mut acc = Point::identity();
    for (base, scalar) in bases.iter().zip(scalars.iter()) {
        let term = mul(base, scalar);
        acc = add(&acc, &term);
    }
    Ok(acc)
}

pub fn okamoto_statement(bases: &[Point], secrets: &[Scalar]) -> Result<OkamotoStatement> {
    if bases.is_empty() || bases.len() > MAX_OKAMOTO_BASES {
        return Err(ProverError::InvalidStatement);
    }
    for base in bases {
        ensure_non_identity(base)?;
    }
    let y = lincomb(bases, secrets)?;
    ensure_non_identity(&y)?;
    Ok(OkamotoStatement {
        bases: bases.to_vec(),
        y,
    })
}

pub fn prove_okamoto<R: RngCore>(
    statement: &OkamotoStatement,
    secrets: &[Scalar],
    context: &[Felt],
    rng: &mut R,
) -> Result<OkamotoProof> {
    if statement.bases.is_empty() || statement.bases.len() > MAX_OKAMOTO_BASES {
        return Err(ProverError::InvalidStatement);
    }
    if statement.bases.len() != secrets.len() {
        return Err(ProverError::MismatchedLength);
    }
    for base in &statement.bases {
        ensure_non_identity(base)?;
    }
    ensure_non_identity(&statement.y)?;
    let expected = lincomb(&statement.bases, secrets)?;
    if expected != statement.y {
        return Err(ProverError::InvalidWitness);
    }

    let mut k_vec = Vec::with_capacity(statement.bases.len());
    for _ in 0..statement.bases.len() {
        k_vec.push(Scalar::random_nonzero(rng)?);
    }
    let commitment = lincomb(&statement.bases, &k_vec)?;
    reject_identity(&commitment)?;

    let transcript = build_okamoto_transcript(&statement.bases, &statement.y, &commitment, context);
    let challenge = transcript.challenge()?;

    let responses: Vec<Scalar> = k_vec
        .iter()
        .zip(secrets.iter())
        .map(|(k, x)| k.add_mod(&challenge.mul_mod(x)))
        .collect();

    Ok(OkamotoProof {
        commitment,
        responses,
    })
}

pub fn verify_okamoto(
    statement: &OkamotoStatement,
    proof: &OkamotoProof,
    context: &[Felt],
) -> Result<()> {
    let stmt = SigmaStatement::Okamoto(statement.clone());
    let sigma_proof = SigmaProof::Okamoto(proof.clone());
    verify_batchable(&stmt, &sigma_proof, context)
}

pub fn verify_okamoto_with_challenge(
    bases: &[Point],
    y: &Point,
    commitment: &Point,
    responses: &[Scalar],
    challenge: &Scalar,
) -> Result<()> {
    validate_challenge(challenge)?;
    let stmt = SigmaStatement::Okamoto(OkamotoStatement {
        bases: bases.to_vec(),
        y: y.clone(),
    });
    let sigma_proof = SigmaProof::Okamoto(OkamotoProof {
        commitment: commitment.clone(),
        responses: responses.to_vec(),
    });
    verify_with_challenge(&stmt, &sigma_proof, challenge)
}

pub fn prove_okamoto_short<R: RngCore>(
    statement: &OkamotoStatement,
    secrets: &[Scalar],
    context: &[Felt],
    rng: &mut R,
) -> Result<OkamotoShortProof> {
    let proof = prove_okamoto(statement, secrets, context, rng)?;
    let transcript =
        build_okamoto_transcript(&statement.bases, &statement.y, &proof.commitment, context);
    let challenge = transcript.challenge()?;
    Ok(OkamotoShortProof {
        challenge,
        responses: proof.responses,
    })
}

pub fn verify_okamoto_short(
    statement: &OkamotoStatement,
    proof: &OkamotoShortProof,
    context: &[Felt],
) -> Result<()> {
    if statement.bases.is_empty() || statement.bases.len() > MAX_OKAMOTO_BASES {
        return Err(ProverError::InvalidStatement);
    }
    if statement.bases.len() != proof.responses.len() {
        return Err(ProverError::MismatchedLength);
    }
    for base in &statement.bases {
        ensure_non_identity(base)?;
    }
    ensure_non_identity(&statement.y)?;
    validate_challenge(&proof.challenge)?;
    for resp in &proof.responses {
        resp.ensure_canonical()?;
    }

    let mut acc = Point::identity();
    for (base, resp) in statement.bases.iter().zip(proof.responses.iter()) {
        acc = add(&acc, &mul(base, resp));
    }
    let simulated_commitment = sub(&acc, &mul(&statement.y, &proof.challenge));
    reject_identity(&simulated_commitment)?;

    let stmt = SigmaStatement::Okamoto(statement.clone());
    let sigma_proof = SigmaProof::Okamoto(OkamotoProof {
        commitment: simulated_commitment,
        responses: proof.responses.clone(),
    });
    verify_with_challenge(&stmt, &sigma_proof, &proof.challenge)?;
    let expected = derive_challenge(&stmt, &sigma_proof, context)?;
    if expected == proof.challenge {
        Ok(())
    } else {
        Err(ProverError::InvalidProof)
    }
}

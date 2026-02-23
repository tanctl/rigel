use rand::RngCore;
use starknet_crypto::Felt;

use crate::core::challenge::validate_challenge;
use crate::core::curve::{Point, ensure_non_identity, mul, reject_identity, sub};
use crate::core::errors::{ProverError, Result};
use crate::core::scalar::Scalar;
use crate::core::sigma::{derive_challenge, verify_batchable, verify_with_challenge};
use crate::core::transcript::build_dlog_transcript;
use crate::protocols::types::{
    DLogProof, DLogShortProof, DLogStatement, SigmaProof, SigmaStatement,
};

pub fn dlog_statement(base: &Point, secret: &Scalar) -> DLogStatement {
    let public_key = mul(base, secret);
    DLogStatement {
        base: base.clone(),
        public_key,
    }
}

pub fn prove_dlog<R: RngCore>(
    statement: &DLogStatement,
    secret: &Scalar,
    context: &[Felt],
    rng: &mut R,
) -> Result<DLogProof> {
    ensure_non_identity(&statement.base)?;
    ensure_non_identity(&statement.public_key)?;
    let expected = dlog_statement(&statement.base, secret);
    if expected.public_key != statement.public_key {
        return Err(ProverError::InvalidWitness);
    }
    let k = Scalar::random_nonzero(rng)?;
    let commitment = mul(&statement.base, &k);
    reject_identity(&commitment)?;

    let transcript =
        build_dlog_transcript(&statement.base, &statement.public_key, &commitment, context);
    let challenge = transcript.challenge()?;
    let response = k.add_mod(&challenge.mul_mod(secret));
    Ok(DLogProof {
        commitment,
        response,
    })
}

pub fn verify_dlog(statement: &DLogStatement, proof: &DLogProof, context: &[Felt]) -> Result<()> {
    let stmt = SigmaStatement::DLog(statement.clone());
    let sigma_proof = SigmaProof::DLog(proof.clone());
    verify_batchable(&stmt, &sigma_proof, context)
}

pub fn verify_dlog_with_challenge(
    base: &Point,
    public_key: &Point,
    commitment: &Point,
    response: &Scalar,
    challenge: &Scalar,
) -> Result<()> {
    validate_challenge(challenge)?;
    let stmt = SigmaStatement::DLog(DLogStatement {
        base: base.clone(),
        public_key: public_key.clone(),
    });
    let sigma_proof = SigmaProof::DLog(DLogProof {
        commitment: commitment.clone(),
        response: response.clone(),
    });
    verify_with_challenge(&stmt, &sigma_proof, challenge)
}

pub fn prove_dlog_short<R: RngCore>(
    statement: &DLogStatement,
    secret: &Scalar,
    context: &[Felt],
    rng: &mut R,
) -> Result<DLogShortProof> {
    let proof = prove_dlog(statement, secret, context, rng)?;
    let transcript = build_dlog_transcript(
        &statement.base,
        &statement.public_key,
        &proof.commitment,
        context,
    );
    let challenge = transcript.challenge()?;
    Ok(DLogShortProof {
        challenge,
        response: proof.response,
    })
}

pub fn verify_dlog_short(
    statement: &DLogStatement,
    proof: &DLogShortProof,
    context: &[Felt],
) -> Result<()> {
    ensure_non_identity(&statement.base)?;
    ensure_non_identity(&statement.public_key)?;
    validate_challenge(&proof.challenge)?;
    proof.response.ensure_canonical()?;

    let simulated_commitment = sub(
        &mul(&statement.base, &proof.response),
        &mul(&statement.public_key, &proof.challenge),
    );
    reject_identity(&simulated_commitment)?;

    let stmt = SigmaStatement::DLog(statement.clone());
    let sigma_proof = SigmaProof::DLog(DLogProof {
        commitment: simulated_commitment,
        response: proof.response.clone(),
    });
    verify_with_challenge(&stmt, &sigma_proof, &proof.challenge)?;
    let expected = derive_challenge(&stmt, &sigma_proof, context)?;
    if expected == proof.challenge {
        Ok(())
    } else {
        Err(ProverError::InvalidProof)
    }
}

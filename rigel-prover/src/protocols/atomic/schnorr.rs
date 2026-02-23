use rand::RngCore;
use starknet_crypto::Felt;

use crate::core::challenge::validate_challenge;
use crate::core::curve::{ensure_non_identity, generator, mul, reject_identity, sub};
use crate::core::errors::{ProverError, Result};
use crate::core::scalar::Scalar;
use crate::core::sigma::{derive_challenge, verify_batchable, verify_with_challenge};
use crate::core::transcript::build_schnorr_transcript;
use crate::protocols::types::{
    SchnorrProof, SchnorrShortProof, SchnorrStatement, SigmaProof, SigmaStatement,
};

pub fn schnorr_statement(secret: &Scalar) -> SchnorrStatement {
    let g = generator();
    let public_key = mul(&g, secret);
    SchnorrStatement { public_key }
}

pub fn prove_schnorr<R: RngCore>(
    statement: &SchnorrStatement,
    secret: &Scalar,
    context: &[Felt],
    rng: &mut R,
) -> Result<SchnorrProof> {
    ensure_non_identity(&statement.public_key)?;
    let expected = schnorr_statement(secret);
    if expected.public_key != statement.public_key {
        return Err(ProverError::InvalidWitness);
    }

    let k = Scalar::random_nonzero(rng)?;
    let g = generator();
    let commitment = mul(&g, &k);
    reject_identity(&commitment)?;

    let transcript = build_schnorr_transcript(&statement.public_key, &commitment, context);
    let challenge = transcript.challenge()?;

    let response = k.add_mod(&challenge.mul_mod(secret));
    Ok(SchnorrProof {
        commitment,
        response,
    })
}

pub fn verify_schnorr(
    statement: &SchnorrStatement,
    proof: &SchnorrProof,
    context: &[Felt],
) -> Result<()> {
    let stmt = SigmaStatement::Schnorr(statement.clone());
    let sigma_proof = SigmaProof::Schnorr(proof.clone());
    verify_batchable(&stmt, &sigma_proof, context)
}

pub fn prove_schnorr_short<R: RngCore>(
    statement: &SchnorrStatement,
    secret: &Scalar,
    context: &[Felt],
    rng: &mut R,
) -> Result<SchnorrShortProof> {
    let proof = prove_schnorr(statement, secret, context, rng)?;
    let transcript = build_schnorr_transcript(&statement.public_key, &proof.commitment, context);
    let challenge = transcript.challenge()?;
    Ok(SchnorrShortProof {
        challenge,
        response: proof.response,
    })
}

pub fn verify_schnorr_short(
    statement: &SchnorrStatement,
    proof: &SchnorrShortProof,
    context: &[Felt],
) -> Result<()> {
    ensure_non_identity(&statement.public_key)?;
    validate_challenge(&proof.challenge)?;
    proof.response.ensure_canonical()?;

    let g = generator();
    let simulated_commitment = sub(
        &mul(&g, &proof.response),
        &mul(&statement.public_key, &proof.challenge),
    );
    reject_identity(&simulated_commitment)?;

    let stmt = SigmaStatement::Schnorr(statement.clone());
    let sigma_proof = SigmaProof::Schnorr(SchnorrProof {
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

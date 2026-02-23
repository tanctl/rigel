use rand::RngCore;
use starknet_crypto::Felt;

use crate::core::challenge::validate_challenge;
use crate::core::curve::{Point, ensure_non_identity, generator, mul, reject_identity, sub};
use crate::core::errors::{ProverError, Result};
use crate::core::scalar::Scalar;
use crate::core::sigma::{derive_challenge, verify_batchable, verify_with_challenge};
use crate::core::transcript::build_chaum_ped_transcript;
use crate::protocols::types::{
    ChaumPedProof, ChaumPedShortProof, ChaumPedStatement, SigmaProof, SigmaStatement,
};

pub fn chaum_ped_statement(h: &Point, secret: &Scalar) -> ChaumPedStatement {
    let g = generator();
    let y1 = mul(&g, secret);
    let y2 = mul(h, secret);
    ChaumPedStatement {
        y1,
        y2,
        h: h.clone(),
    }
}

pub fn prove_chaum_ped<R: RngCore>(
    statement: &ChaumPedStatement,
    secret: &Scalar,
    context: &[Felt],
    rng: &mut R,
) -> Result<ChaumPedProof> {
    ensure_non_identity(&statement.y1)?;
    ensure_non_identity(&statement.y2)?;
    ensure_non_identity(&statement.h)?;
    let expected = chaum_ped_statement(&statement.h, secret);
    if expected.y1 != statement.y1 || expected.y2 != statement.y2 {
        return Err(ProverError::InvalidWitness);
    }

    let k = Scalar::random_nonzero(rng)?;
    let g = generator();
    let r1 = mul(&g, &k);
    let r2 = mul(&statement.h, &k);
    reject_identity(&r1)?;
    reject_identity(&r2)?;

    let transcript = build_chaum_ped_transcript(
        &statement.y1,
        &statement.y2,
        &statement.h,
        &r1,
        &r2,
        context,
    );
    let challenge = transcript.challenge()?;
    let response = k.add_mod(&challenge.mul_mod(secret));
    Ok(ChaumPedProof { r1, r2, response })
}

pub fn verify_chaum_ped(
    statement: &ChaumPedStatement,
    proof: &ChaumPedProof,
    context: &[Felt],
) -> Result<()> {
    let stmt = SigmaStatement::ChaumPed(statement.clone());
    let sigma_proof = SigmaProof::ChaumPed(proof.clone());
    verify_batchable(&stmt, &sigma_proof, context)
}

pub fn prove_chaum_ped_short<R: RngCore>(
    statement: &ChaumPedStatement,
    secret: &Scalar,
    context: &[Felt],
    rng: &mut R,
) -> Result<ChaumPedShortProof> {
    let proof = prove_chaum_ped(statement, secret, context, rng)?;
    let transcript = build_chaum_ped_transcript(
        &statement.y1,
        &statement.y2,
        &statement.h,
        &proof.r1,
        &proof.r2,
        context,
    );
    let challenge = transcript.challenge()?;
    Ok(ChaumPedShortProof {
        challenge,
        response: proof.response,
    })
}

pub fn verify_chaum_ped_short(
    statement: &ChaumPedStatement,
    proof: &ChaumPedShortProof,
    context: &[Felt],
) -> Result<()> {
    ensure_non_identity(&statement.y1)?;
    ensure_non_identity(&statement.y2)?;
    ensure_non_identity(&statement.h)?;
    validate_challenge(&proof.challenge)?;
    proof.response.ensure_canonical()?;

    let g = generator();
    let r1 = sub(
        &mul(&g, &proof.response),
        &mul(&statement.y1, &proof.challenge),
    );
    let r2 = sub(
        &mul(&statement.h, &proof.response),
        &mul(&statement.y2, &proof.challenge),
    );
    reject_identity(&r1)?;
    reject_identity(&r2)?;

    let stmt = SigmaStatement::ChaumPed(statement.clone());
    let sigma_proof = SigmaProof::ChaumPed(ChaumPedProof {
        r1,
        r2,
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

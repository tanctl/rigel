use rand::RngCore;
use starknet_crypto::Felt;

use crate::composition::prover::{commitment_from_nonce, prove_with_challenge, sample_nonce};
use crate::composition::shared::{
    append_commitment, fold_composition_labels, statement_label, validate_statement_and_proof,
    verify_with_challenge,
};
use crate::composition::types::AndInstance;
use crate::core::constants::PROTOCOL_AND;
use crate::core::errors::{ProverError, Result};
use crate::core::transcript::transcript_new_and;
use crate::protocols::types::{SigmaStatement, SigmaWitness};

pub fn verify_and(instances: &[AndInstance], context: &[Felt]) -> Result<()> {
    if instances.is_empty() {
        return Err(ProverError::EmptyInstances);
    }

    let mut labels = Vec::with_capacity(instances.len());
    for inst in instances {
        labels.push(statement_label(&inst.statement)?);
    }
    let composition_label =
        fold_composition_labels(&PROTOCOL_AND, &labels).ok_or(ProverError::EmptyInstances)?;

    let mut t = transcript_new_and();
    t.append_felt(composition_label);
    for inst in instances {
        append_commitment(&mut t, &inst.statement, &inst.proof)?;
    }
    t.append_span(context);
    let challenge = t.challenge()?;

    for inst in instances {
        validate_statement_and_proof(&inst.statement, &inst.proof)?;
    }

    for inst in instances {
        verify_with_challenge(&inst.statement, &inst.proof, &challenge)?;
    }
    Ok(())
}

pub fn prove_and<R: RngCore>(
    statements: &[SigmaStatement],
    witnesses: &[SigmaWitness],
    context: &[Felt],
    rng: &mut R,
) -> Result<Vec<AndInstance>> {
    if statements.is_empty() {
        return Err(ProverError::EmptyInstances);
    }
    if statements.len() != witnesses.len() {
        return Err(ProverError::MismatchedLength);
    }

    let mut nonces = Vec::with_capacity(statements.len());
    let mut commitments = Vec::with_capacity(statements.len());
    for stmt in statements {
        let nonce = sample_nonce(stmt, rng)?;
        let proof = commitment_from_nonce(stmt, &nonce)?;
        validate_statement_and_proof(stmt, &proof)?;
        nonces.push(nonce);
        commitments.push(proof);
    }

    let mut labels = Vec::with_capacity(statements.len());
    for stmt in statements {
        labels.push(statement_label(stmt)?);
    }
    let composition_label =
        fold_composition_labels(&PROTOCOL_AND, &labels).ok_or(ProverError::EmptyInstances)?;

    let mut t = transcript_new_and();
    t.append_felt(composition_label);
    for (stmt, proof) in statements.iter().zip(commitments.iter()) {
        append_commitment(&mut t, stmt, proof)?;
    }
    t.append_span(context);
    let challenge = t.challenge()?;

    let mut instances = Vec::with_capacity(statements.len());
    for ((stmt, witness), nonce) in statements.iter().zip(witnesses.iter()).zip(nonces.iter()) {
        let proof = prove_with_challenge(stmt, witness, nonce, &challenge)?;
        instances.push(AndInstance {
            statement: stmt.clone(),
            proof,
        });
    }
    Ok(instances)
}

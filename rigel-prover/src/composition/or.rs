use rand::RngCore;
use starknet_crypto::Felt;

use crate::composition::prover::{
    commitment_from_nonce, prove_with_challenge, sample_nonce, simulate_proof,
};
use crate::composition::shared::{
    append_commitment, fold_composition_labels, statement_label, validate_statement_and_proof,
    verify_with_challenge,
};
use crate::composition::types::OrInstance;
use crate::core::constants::PROTOCOL_OR;
use crate::core::errors::{ProverError, Result};
use crate::core::scalar::Scalar;
use crate::core::transcript::transcript_new_or;
use crate::protocols::types::{SigmaStatement, SigmaWitness};

#[inline]
fn sum_fold_challenges<'a, I>(iter: I) -> Scalar
where
    I: IntoIterator<Item = &'a Scalar>,
{
    let mut acc = Scalar::from_u64(0);
    for c in iter {
        acc = acc.add_mod(c);
    }
    acc
}

pub fn verify_or(instances: &[OrInstance], context: &[Felt]) -> Result<()> {
    // for n > 2, use the n-ary leaf form
    if instances.is_empty() {
        return Err(ProverError::EmptyInstances);
    }

    let mut labels = Vec::with_capacity(instances.len());
    for inst in instances {
        labels.push(statement_label(&inst.statement)?);
    }
    let composition_label =
        fold_composition_labels(&PROTOCOL_OR, &labels).ok_or(ProverError::EmptyInstances)?;

    let mut t = transcript_new_or();
    t.append_felt(composition_label);
    for inst in instances {
        append_commitment(&mut t, &inst.statement, &inst.proof)?;
    }
    t.append_span(context);
    let global_challenge = t.challenge()?;

    for inst in instances {
        validate_statement_and_proof(&inst.statement, &inst.proof)?;
    }

    let mut sum_acc = Scalar::from_u64(0);
    for inst in instances {
        inst.challenge.ensure_canonical()?;
        sum_acc = sum_acc.add_mod(&inst.challenge);
    }
    if sum_acc != global_challenge {
        return Err(ProverError::OrChallengeSumMismatch);
    }

    for inst in instances {
        verify_with_challenge(&inst.statement, &inst.proof, &inst.challenge)?;
    }
    Ok(())
}

pub fn prove_or<R: RngCore>(
    statements: &[SigmaStatement],
    real_index: usize,
    real_witness: &SigmaWitness,
    context: &[Felt],
    rng: &mut R,
) -> Result<Vec<OrInstance>> {
    if statements.is_empty() {
        return Err(ProverError::EmptyInstances);
    }
    if real_index >= statements.len() {
        return Err(ProverError::InvalidStatement);
    }

    let mut instances: Vec<OrInstance> = Vec::with_capacity(statements.len());
    let mut nonces: Vec<Option<crate::composition::prover::SigmaNonce>> =
        Vec::with_capacity(statements.len());

    for (i, stmt) in statements.iter().enumerate() {
        if i == real_index {
            let nonce = sample_nonce(stmt, rng)?;
            let proof = commitment_from_nonce(stmt, &nonce)?;
            validate_statement_and_proof(stmt, &proof)?;
            instances.push(OrInstance {
                statement: stmt.clone(),
                proof,
                challenge: Scalar::from_u64(0),
            });
            nonces.push(Some(nonce));
        } else {
            let challenge = Scalar::random(rng, true)?;
            let proof = simulate_proof(stmt, &challenge, rng)?;
            validate_statement_and_proof(stmt, &proof)?;
            instances.push(OrInstance {
                statement: stmt.clone(),
                proof,
                challenge,
            });
            nonces.push(None);
        }
    }

    let mut labels = Vec::with_capacity(instances.len());
    for inst in &instances {
        labels.push(statement_label(&inst.statement)?);
    }
    let composition_label =
        fold_composition_labels(&PROTOCOL_OR, &labels).ok_or(ProverError::EmptyInstances)?;

    let mut t = transcript_new_or();
    t.append_felt(composition_label);
    for inst in &instances {
        append_commitment(&mut t, &inst.statement, &inst.proof)?;
    }
    t.append_span(context);
    let global_challenge = t.challenge()?;

    let sum_sim = sum_fold_challenges(instances.iter().enumerate().filter_map(|(i, inst)| {
        if i == real_index {
            None
        } else {
            Some(&inst.challenge)
        }
    }));
    let real_challenge = global_challenge.sub_mod(&sum_sim);

    let real_nonce = nonces[real_index]
        .as_ref()
        .ok_or(ProverError::InvalidWitness)?;
    let real_proof = prove_with_challenge(
        &statements[real_index],
        real_witness,
        real_nonce,
        &real_challenge,
    )?;

    instances[real_index].proof = real_proof;
    instances[real_index].challenge = real_challenge;
    Ok(instances)
}

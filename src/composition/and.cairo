use core::array::{ArrayTrait, Span, SpanTrait};

use crate::composition::types::AndInstance;
use crate::composition::shared::{
    append_commitment,
    fold_composition_labels,
    statement_label,
    validate_statement_and_proof,
    verify_with_challenge,
};
use crate::composition::bytes::pop_instance;
use crate::core::errors::{VerifyError, VerifyResult};
use crate::core::transcript::{
    PROTOCOL_AND,
    transcript_new_and,
    transcript_append_felt,
    transcript_append_span,
    transcript_challenge,
};

/// transcript layout: domain_and, curve_id, composition_label, comm1, comm2, ..., context
pub fn verify_and(instances: Span<AndInstance>, context: Span<felt252>) -> VerifyResult {
    if instances.len() == 0 {
        return Err(VerifyError::EmptyInstances);
    }

    let mut labels: Array<felt252> = ArrayTrait::new();
    let mut label_iter = instances;
    loop {
        match label_iter.pop_front() {
            Some(inst_ref) => {
                let inst = *inst_ref;
                labels.append(statement_label(inst.statement));
            },
            None => { break; },
        }
    }
    let Some(composition_label) = fold_composition_labels(PROTOCOL_AND, labels.span()) else {
        return Err(VerifyError::EmptyInstances);
    };

    let mut t = transcript_new_and();
    transcript_append_felt(ref t, composition_label);

    let mut iter = instances;
    loop {
        match iter.pop_front() {
            Some(inst_ref) => {
                let inst = *inst_ref;
                append_commitment(ref t, inst.statement, inst.proof)?;
            },
            None => { break; },
        }
    }

    transcript_append_span(ref t, context);
    let Some(challenge) = transcript_challenge(@t) else {
        return Err(VerifyError::ZeroChallenge);
    };

    let mut validate_iter = instances;
    loop {
        match validate_iter.pop_front() {
            Some(inst_ref) => {
                let inst = *inst_ref;
                validate_statement_and_proof(inst.statement, inst.proof)?;
            },
            None => { break; },
        }
    }

    let mut verify_iter = instances;
    loop {
        match verify_iter.pop_front() {
            Some(inst_ref) => {
                let inst = *inst_ref;
                verify_with_challenge(inst.statement, inst.proof, challenge)?;
            },
            None => { break; },
        }
    }

    Ok(())
}

/// instance encoding: tag (32) || statement || proof
pub fn verify_and_bytes(instances: Span<u8>, context: Span<felt252>) -> VerifyResult {
    if instances.len() == 0 {
        return Err(VerifyError::EmptyInstances);
    }

    let mut labels: Array<felt252> = ArrayTrait::new();
    let mut label_iter = instances;
    loop {
        if label_iter.len() == 0 {
            break;
        }
        let (stmt, _proof) = pop_instance(ref label_iter)?;
        labels.append(statement_label(stmt));
    }
    let Some(composition_label) = fold_composition_labels(PROTOCOL_AND, labels.span()) else {
        return Err(VerifyError::EmptyInstances);
    };

    let mut t = transcript_new_and();
    transcript_append_felt(ref t, composition_label);
    let mut iter = instances;
    loop {
        if iter.len() == 0 {
            break;
        }
        let (stmt, proof) = pop_instance(ref iter)?;
        append_commitment(ref t, stmt, proof)?;
    }

    transcript_append_span(ref t, context);
    let Some(challenge) = transcript_challenge(@t) else {
        return Err(VerifyError::ZeroChallenge);
    };

    let mut validate_iter = instances;
    loop {
        if validate_iter.len() == 0 {
            break;
        }
        let (stmt, proof) = pop_instance(ref validate_iter)?;
        validate_statement_and_proof(stmt, proof)?;
    }

    let mut verify_iter = instances;
    loop {
        if verify_iter.len() == 0 {
            break;
        }
        let (stmt, proof) = pop_instance(ref verify_iter)?;
        verify_with_challenge(stmt, proof, challenge)?;
    }

    Ok(())
}

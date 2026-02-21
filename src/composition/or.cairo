use core::array::{ArrayTrait, Span, SpanTrait};
use core::integer::u256;
use core::traits::Into;

use crate::composition::types::OrInstance;
use crate::composition::shared::{
    append_commitment,
    fold_composition_labels,
    statement_label,
    validate_statement_and_proof,
    verify_with_challenge,
};
use crate::composition::bytes::pop_instance_with_challenge;
use crate::core::errors::{VerifyError, VerifyResult};
use crate::core::scalar::{is_canonical_scalar, order_u256};
use crate::core::transcript::{
    PROTOCOL_OR,
    transcript_new_or,
    transcript_append_felt,
    transcript_append_span,
    transcript_challenge,
};

#[inline]
fn add_mod_order_u256(sum: u256, add: u256, order: u256) -> u256 {
    let tmp = sum + add;
    if tmp >= order { tmp - order } else { tmp }
}

/// branch challenges are sum-composed modulo order and must match the global challenge for n > 2, n-ary leaf form transcript layout: domain_or, curve_id, composition_label, all commitments, context
pub fn verify_or(instances: Span<OrInstance>, context: Span<felt252>) -> VerifyResult {
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
    let Some(composition_label) = fold_composition_labels(PROTOCOL_OR, labels.span()) else {
        return Err(VerifyError::EmptyInstances);
    };

    let mut t = transcript_new_or();
    transcript_append_felt(ref t, composition_label);

    let mut comm_iter = instances;
    loop {
        match comm_iter.pop_front() {
            Some(inst_ref) => {
                let inst = *inst_ref;
                append_commitment(ref t, inst.statement, inst.proof)?;
            },
            None => { break; },
        }
    }

    transcript_append_span(ref t, context);
    let Some(global_challenge) = transcript_challenge(@t) else {
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

    let order = order_u256();
    let mut sum_acc: u256 = 0;
    let mut sum_iter = instances;
    loop {
        match sum_iter.pop_front() {
            Some(inst_ref) => {
                let inst = *inst_ref;
                if !is_canonical_scalar(inst.challenge) {
                    return Err(VerifyError::NonCanonicalScalar);
                }
                let c_u256: u256 = inst.challenge.into();
                sum_acc = add_mod_order_u256(sum_acc, c_u256, order);
            },
            None => { break; },
        }
    }

    let global_u256: u256 = global_challenge.into();
    if sum_acc != global_u256 {
        return Err(VerifyError::OrChallengeSumMismatch);
    }

    let mut verify_iter = instances;
    loop {
        match verify_iter.pop_front() {
            Some(inst_ref) => {
                let inst = *inst_ref;
                verify_with_challenge(inst.statement, inst.proof, inst.challenge)?;
            },
            None => { break; },
        }
    }

    Ok(())
}

/// instance encoding: tag (32) || statement || proof || challenge (32)
pub fn verify_or_bytes(instances: Span<u8>, context: Span<felt252>) -> VerifyResult {
    if instances.len() == 0 {
        return Err(VerifyError::EmptyInstances);
    }

    let mut labels: Array<felt252> = ArrayTrait::new();
    let mut label_iter = instances;
    loop {
        if label_iter.len() == 0 {
            break;
        }
        let (stmt, _proof, _challenge) = pop_instance_with_challenge(ref label_iter)?;
        labels.append(statement_label(stmt));
    }
    let Some(composition_label) = fold_composition_labels(PROTOCOL_OR, labels.span()) else {
        return Err(VerifyError::EmptyInstances);
    };

    let mut t = transcript_new_or();
    transcript_append_felt(ref t, composition_label);

    let mut comm_iter = instances;
    loop {
        if comm_iter.len() == 0 {
            break;
        }
        let (stmt, proof, _challenge) = pop_instance_with_challenge(ref comm_iter)?;
        append_commitment(ref t, stmt, proof)?;
    }

    transcript_append_span(ref t, context);
    let Some(global_challenge) = transcript_challenge(@t) else {
        return Err(VerifyError::ZeroChallenge);
    };

    let mut validate_iter = instances;
    loop {
        if validate_iter.len() == 0 {
            break;
        }
        let (stmt, proof, _challenge) = pop_instance_with_challenge(ref validate_iter)?;
        validate_statement_and_proof(stmt, proof)?;
    }

    let order = order_u256();
    let mut sum_acc: u256 = 0;
    let mut sum_iter = instances;
    loop {
        if sum_iter.len() == 0 {
            break;
        }
        let (_stmt, _proof, challenge) = pop_instance_with_challenge(ref sum_iter)?;
        if !is_canonical_scalar(challenge) {
            return Err(VerifyError::NonCanonicalScalar);
        }
        let c_u256: u256 = challenge.into();
        sum_acc = add_mod_order_u256(sum_acc, c_u256, order);
    }

    let global_u256: u256 = global_challenge.into();
    if sum_acc != global_u256 {
        return Err(VerifyError::OrChallengeSumMismatch);
    }

    let mut verify_iter = instances;
    loop {
        if verify_iter.len() == 0 {
            break;
        }
        let (stmt, proof, challenge) = pop_instance_with_challenge(ref verify_iter)?;
        verify_with_challenge(stmt, proof, challenge)?;
    }

    Ok(())
}

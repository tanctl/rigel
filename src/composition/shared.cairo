use core::array::{ArrayTrait, Span, SpanTrait};
use core::poseidon::poseidon_hash_span;

use crate::core::errors::VerifyResult;
use crate::core::transcript::Transcript;
use crate::protocols::types::{SigmaStatement, SigmaProof};

// composition helpers are thin delegates into the unified core pipeline

#[inline]
pub(crate) fn append_statement(ref t: Transcript, stmt: SigmaStatement) {
    crate::core::sigma::absorb_statement(ref t, stmt);
}

#[inline]
pub(crate) fn statement_label(stmt: SigmaStatement) -> felt252 {
    crate::core::sigma::statement_label(stmt)
}

#[inline]
pub(crate) fn composition_pair_label(protocol_tag: felt252, left: felt252, right: felt252) -> felt252 {
    let mut data = ArrayTrait::new();
    data.append(protocol_tag);
    data.append(left);
    data.append(right);
    poseidon_hash_span(data.span())
}

#[inline]
pub(crate) fn fold_composition_labels(
    protocol_tag: felt252,
    mut labels: Span<felt252>,
) -> Option<felt252> {
    let Some(first_ref) = labels.pop_front() else {
        return None;
    };
    let mut acc = *first_ref;
    loop {
        match labels.pop_front() {
            Some(next_ref) => {
                acc = composition_pair_label(protocol_tag, acc, *next_ref);
            },
            None => {
                break;
            },
        }
    }
    Some(acc)
}

#[inline]
pub(crate) fn append_commitment(
    ref t: Transcript,
    stmt: SigmaStatement,
    proof: SigmaProof,
) -> VerifyResult {
    crate::core::sigma::absorb_commitment(ref t, stmt, proof)
}

#[inline]
pub(crate) fn validate_statement_and_proof(stmt: SigmaStatement, proof: SigmaProof) -> VerifyResult {
    crate::core::sigma::validate_statement_and_proof(stmt, proof)
}

#[inline]
pub(crate) fn verify_with_challenge(stmt: SigmaStatement, proof: SigmaProof, challenge: felt252) -> VerifyResult {
    crate::core::sigma::verify_with_challenge_allow_zero(stmt, proof, challenge)
}

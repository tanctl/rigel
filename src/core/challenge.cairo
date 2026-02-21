use core::array::{ArrayTrait, Span, SpanTrait};
use core::ec::NonZeroEcPoint;
use core::poseidon::poseidon_hash_span;

use crate::core::curve::point_coordinates;
use crate::core::errors::{VerifyError, VerifyResult};
use crate::core::scalar::{is_canonical_scalar, is_nonzero_scalar, reduce_mod_order};
use crate::core::transcript::CURVE_ID_STARK;

/// computes a fiat-shamir challenge from protocol/domain inputs and commitments
/// input domain: protocol_tag, curve_id, statement_label, commitments, context
pub fn compute_challenge(
    protocol_tag: felt252,
    statement_label: felt252,
    commitments: Span<NonZeroEcPoint>,
    context: Span<felt252>,
) -> felt252 {
    let mut data = ArrayTrait::new();
    data.append(protocol_tag);
    data.append(CURVE_ID_STARK);
    data.append(statement_label);
    let mut iter = commitments;
    loop {
        match iter.pop_front() {
            Some(p_ref) => {
                let (x, y) = point_coordinates(*p_ref);
                data.append(x);
                data.append(y);
            },
            None => { break; },
        }
    }
    data.append_span(context);
    reduce_mod_order(poseidon_hash_span(data.span()))
}

pub fn compute_challenge_checked(
    protocol_tag: felt252,
    statement_label: felt252,
    commitments: Span<NonZeroEcPoint>,
    context: Span<felt252>,
) -> Result<felt252, VerifyError> {
    let challenge = compute_challenge(protocol_tag, statement_label, commitments, context);
    validate_challenge(challenge)?;
    Ok(challenge)
}

pub fn validate_challenge(challenge: felt252) -> VerifyResult {
    if !is_canonical_scalar(challenge) {
        return Err(VerifyError::NonCanonicalScalar);
    }
    if !is_nonzero_scalar(challenge) {
        return Err(VerifyError::ZeroChallenge);
    }
    Ok(())
}

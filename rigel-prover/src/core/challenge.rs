use starknet_crypto::{Felt, poseidon_hash_many};

use crate::core::constants::CURVE_ID_STARK;
use crate::core::curve::{Point, point_coordinates};
use crate::core::errors::{ProverError, Result};
use crate::core::scalar::Scalar;

pub fn compute_challenge(
    protocol_tag: Felt,
    statement_label: Felt,
    commitments: &[Point],
    context: &[Felt],
) -> Scalar {
    let mut data = Vec::with_capacity(3 + commitments.len() * 2 + context.len());
    data.push(protocol_tag);
    data.push(*CURVE_ID_STARK);
    data.push(statement_label);
    for p in commitments {
        let (x, y) = point_coordinates(p);
        data.push(x);
        data.push(y);
    }
    data.extend_from_slice(context);
    let h = poseidon_hash_many(data.iter());
    Scalar::from_felt_mod_order(&h)
}

pub fn compute_challenge_checked(
    protocol_tag: Felt,
    statement_label: Felt,
    commitments: &[Point],
    context: &[Felt],
) -> Result<Scalar> {
    let challenge = compute_challenge(protocol_tag, statement_label, commitments, context);
    validate_challenge(&challenge)?;
    Ok(challenge)
}

pub fn validate_challenge(c: &Scalar) -> Result<()> {
    c.ensure_canonical()?;
    if c.is_zero() {
        Err(ProverError::ZeroChallenge)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{compute_challenge, compute_challenge_checked};
    use crate::core::constants::{CURVE_ID_STARK, PROTOCOL_OR};
    use crate::core::curve::{generator, pedersen_h, point_coordinates};
    use crate::core::scalar::Scalar;
    use starknet_crypto::{Felt, poseidon_hash_many};

    #[test]
    fn compute_challenge_matches_formula_and_checked() {
        let commitments = vec![generator(), pedersen_h()];
        let context = vec![Felt::from(20260223u64), Felt::from(71u64)];

        let mut label = Felt::from(1u64);
        let mut challenge = compute_challenge(*PROTOCOL_OR, label, &commitments, &context);
        let mut idx = 1u64;
        while challenge.is_zero() && idx < 64 {
            idx += 1;
            label = Felt::from(idx);
            challenge = compute_challenge(*PROTOCOL_OR, label, &commitments, &context);
        }
        assert!(!challenge.is_zero(), "failed to find non-zero deterministic challenge");

        let mut manual = Vec::with_capacity(3 + commitments.len() * 2 + context.len());
        manual.push(*PROTOCOL_OR);
        manual.push(*CURVE_ID_STARK);
        manual.push(label);
        for point in &commitments {
            let (x, y) = point_coordinates(point);
            manual.push(x);
            manual.push(y);
        }
        manual.extend_from_slice(&context);
        let expected = Scalar::from_felt_mod_order(&poseidon_hash_many(manual.iter()));
        assert_eq!(challenge, expected);

        let checked = compute_challenge_checked(*PROTOCOL_OR, label, &commitments, &context)
            .expect("checked challenge");
        assert_eq!(checked, challenge);
    }
}

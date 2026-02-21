use core::array::Span;
use core::ec::{EcStateTrait, NonZeroEcPoint};
use core::traits::TryInto;

use crate::core::challenge::validate_challenge;
use crate::core::errors::{VerifyError, VerifyResult};
use crate::core::scalar::is_canonical_scalar;
use crate::core::sigma::{derive_challenge, verify_batchable, verify_with_challenge};
use crate::protocols::types::{PedersenEqProof, PedersenEqStatement, SigmaProof, SigmaStatement};
use crate::utils::bytes::{decode_point_be64, decode_scalar_be32};

/// verifies equality of committed values for two (possibly different) pedersen-style representations: c1 = v*g1 + r1*h1 and c2 = v*g2 + r2*h2
pub fn verify_pedersen_eq(
    value_base1: NonZeroEcPoint,
    blinding_base1: NonZeroEcPoint,
    commitment1: NonZeroEcPoint,
    value_base2: NonZeroEcPoint,
    blinding_base2: NonZeroEcPoint,
    commitment2: NonZeroEcPoint,
    nonce_commitment1: NonZeroEcPoint,
    nonce_commitment2: NonZeroEcPoint,
    response_value: felt252,
    response_blinding1: felt252,
    response_blinding2: felt252,
    context: Span<felt252>,
) -> VerifyResult {
    let stmt = SigmaStatement::PedersenEq(PedersenEqStatement {
        commitment1,
        commitment2,
        value_base1,
        blinding_base1,
        value_base2,
        blinding_base2,
    });
    let proof = SigmaProof::PedersenEq(PedersenEqProof {
        nonce_commitment1,
        nonce_commitment2,
        response_value,
        response_blinding1,
        response_blinding2,
    });
    verify_batchable(stmt, proof, context)
}

pub fn verify_pedersen_eq_bytes(
    value_base1: Span<u8>,
    blinding_base1: Span<u8>,
    commitment1: Span<u8>,
    value_base2: Span<u8>,
    blinding_base2: Span<u8>,
    commitment2: Span<u8>,
    nonce_commitment1: Span<u8>,
    nonce_commitment2: Span<u8>,
    response_value: Span<u8>,
    response_blinding1: Span<u8>,
    response_blinding2: Span<u8>,
    context: Span<felt252>,
) -> VerifyResult {
    let gv1 = decode_point_be64(value_base1)?;
    let hb1 = decode_point_be64(blinding_base1)?;
    let c1 = decode_point_be64(commitment1)?;
    let gv2 = decode_point_be64(value_base2)?;
    let hb2 = decode_point_be64(blinding_base2)?;
    let c2 = decode_point_be64(commitment2)?;
    let r1 = decode_point_be64(nonce_commitment1)?;
    let r2 = decode_point_be64(nonce_commitment2)?;
    let s_v = decode_scalar_be32(response_value)?;
    let s_r1 = decode_scalar_be32(response_blinding1)?;
    let s_r2 = decode_scalar_be32(response_blinding2)?;
    verify_pedersen_eq(gv1, hb1, c1, gv2, hb2, c2, r1, r2, s_v, s_r1, s_r2, context)
}

pub fn verify_pedersen_eq_short(
    value_base1: NonZeroEcPoint,
    blinding_base1: NonZeroEcPoint,
    commitment1: NonZeroEcPoint,
    value_base2: NonZeroEcPoint,
    blinding_base2: NonZeroEcPoint,
    commitment2: NonZeroEcPoint,
    challenge: felt252,
    response_value: felt252,
    response_blinding1: felt252,
    response_blinding2: felt252,
    context: Span<felt252>,
) -> VerifyResult {
    validate_challenge(challenge)?;
    if !is_canonical_scalar(response_value)
        || !is_canonical_scalar(response_blinding1)
        || !is_canonical_scalar(response_blinding2)
    {
        return Err(VerifyError::NonCanonicalScalar);
    }

    let mut lhs1_state = EcStateTrait::init();
    lhs1_state.add_mul(response_value, value_base1);
    lhs1_state.add_mul(response_blinding1, blinding_base1);
    let lhs1 = lhs1_state.finalize();
    let mut rhs1_state = EcStateTrait::init();
    rhs1_state.add_mul(challenge, commitment1);
    let rhs1 = rhs1_state.finalize();
    let sim1 = lhs1 + (-rhs1);
    let Some(nonce_commitment1) = sim1.try_into() else {
        return Err(VerifyError::InvalidProof);
    };

    let mut lhs2_state = EcStateTrait::init();
    lhs2_state.add_mul(response_value, value_base2);
    lhs2_state.add_mul(response_blinding2, blinding_base2);
    let lhs2 = lhs2_state.finalize();
    let mut rhs2_state = EcStateTrait::init();
    rhs2_state.add_mul(challenge, commitment2);
    let rhs2 = rhs2_state.finalize();
    let sim2 = lhs2 + (-rhs2);
    let Some(nonce_commitment2) = sim2.try_into() else {
        return Err(VerifyError::InvalidProof);
    };

    let stmt = SigmaStatement::PedersenEq(PedersenEqStatement {
        commitment1,
        commitment2,
        value_base1,
        blinding_base1,
        value_base2,
        blinding_base2,
    });
    let proof = SigmaProof::PedersenEq(PedersenEqProof {
        nonce_commitment1,
        nonce_commitment2,
        response_value,
        response_blinding1,
        response_blinding2,
    });
    verify_with_challenge(stmt, proof, challenge)?;
    let expected = derive_challenge(stmt, proof, context)?;
    if expected == challenge {
        Ok(())
    } else {
        Err(VerifyError::InvalidProof)
    }
}

pub fn verify_pedersen_eq_short_bytes(
    value_base1: Span<u8>,
    blinding_base1: Span<u8>,
    commitment1: Span<u8>,
    value_base2: Span<u8>,
    blinding_base2: Span<u8>,
    commitment2: Span<u8>,
    challenge: Span<u8>,
    response_value: Span<u8>,
    response_blinding1: Span<u8>,
    response_blinding2: Span<u8>,
    context: Span<felt252>,
) -> VerifyResult {
    let gv1 = decode_point_be64(value_base1)?;
    let hb1 = decode_point_be64(blinding_base1)?;
    let c1 = decode_point_be64(commitment1)?;
    let gv2 = decode_point_be64(value_base2)?;
    let hb2 = decode_point_be64(blinding_base2)?;
    let c2 = decode_point_be64(commitment2)?;
    let ch = decode_scalar_be32(challenge)?;
    let s_v = decode_scalar_be32(response_value)?;
    let s_r1 = decode_scalar_be32(response_blinding1)?;
    let s_r2 = decode_scalar_be32(response_blinding2)?;
    verify_pedersen_eq_short(gv1, hb1, c1, gv2, hb2, c2, ch, s_v, s_r1, s_r2, context)
}

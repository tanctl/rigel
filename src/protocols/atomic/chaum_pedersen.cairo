use core::array::Span;
use core::ec::{EcStateTrait, NonZeroEcPoint};
use core::traits::TryInto;

use crate::core::challenge::validate_challenge;
use crate::core::curve::generator;
use crate::core::errors::{VerifyError, VerifyResult};
use crate::core::scalar::is_canonical_scalar;
use crate::core::sigma::{derive_challenge, verify_batchable, verify_with_challenge};
use crate::protocols::types::{ChaumPedProof, ChaumPedStatement, SigmaProof, SigmaStatement};
use crate::utils::bytes::{decode_point_be64, decode_scalar_be32};

pub fn verify_chaum_ped(
    y1: NonZeroEcPoint,
    y2: NonZeroEcPoint,
    h: NonZeroEcPoint,
    r1: NonZeroEcPoint,
    r2: NonZeroEcPoint,
    response: felt252,
    context: Span<felt252>,
) -> VerifyResult {
    let stmt = SigmaStatement::ChaumPed(ChaumPedStatement { y1, y2, h });
    let proof = SigmaProof::ChaumPed(ChaumPedProof { r1, r2, response });
    verify_batchable(stmt, proof, context)
}

pub fn verify_chaum_ped_bytes(
    y1: Span<u8>,
    y2: Span<u8>,
    h: Span<u8>,
    r1: Span<u8>,
    r2: Span<u8>,
    response: Span<u8>,
    context: Span<felt252>,
) -> VerifyResult {
    let y1_p = decode_point_be64(y1)?;
    let y2_p = decode_point_be64(y2)?;
    let h_p = decode_point_be64(h)?;
    let r1_p = decode_point_be64(r1)?;
    let r2_p = decode_point_be64(r2)?;
    let s = decode_scalar_be32(response)?;
    verify_chaum_ped(y1_p, y2_p, h_p, r1_p, r2_p, s, context)
}

pub fn verify_chaum_ped_short(
    y1: NonZeroEcPoint,
    y2: NonZeroEcPoint,
    h: NonZeroEcPoint,
    challenge: felt252,
    response: felt252,
    context: Span<felt252>,
) -> VerifyResult {
    validate_challenge(challenge)?;
    if !is_canonical_scalar(response) {
        return Err(VerifyError::NonCanonicalScalar);
    }

    let Some(g) = generator() else {
        return Err(VerifyError::InvalidPoint);
    };
    let mut lhs1_state = EcStateTrait::init();
    lhs1_state.add_mul(response, g);
    let lhs1 = lhs1_state.finalize();
    let mut rhs1_state = EcStateTrait::init();
    rhs1_state.add_mul(challenge, y1);
    let rhs1 = rhs1_state.finalize();
    let sim1 = lhs1 + (-rhs1);
    let Some(r1) = sim1.try_into() else {
        return Err(VerifyError::InvalidProof);
    };

    let mut lhs2_state = EcStateTrait::init();
    lhs2_state.add_mul(response, h);
    let lhs2 = lhs2_state.finalize();
    let mut rhs2_state = EcStateTrait::init();
    rhs2_state.add_mul(challenge, y2);
    let rhs2 = rhs2_state.finalize();
    let sim2 = lhs2 + (-rhs2);
    let Some(r2) = sim2.try_into() else {
        return Err(VerifyError::InvalidProof);
    };

    let stmt = SigmaStatement::ChaumPed(ChaumPedStatement { y1, y2, h });
    let proof = SigmaProof::ChaumPed(ChaumPedProof { r1, r2, response });
    verify_with_challenge(stmt, proof, challenge)?;
    let expected = derive_challenge(stmt, proof, context)?;
    if expected == challenge {
        Ok(())
    } else {
        Err(VerifyError::InvalidProof)
    }
}

pub fn verify_chaum_ped_short_bytes(
    y1: Span<u8>,
    y2: Span<u8>,
    h: Span<u8>,
    challenge: Span<u8>,
    response: Span<u8>,
    context: Span<felt252>,
) -> VerifyResult {
    let y1_p = decode_point_be64(y1)?;
    let y2_p = decode_point_be64(y2)?;
    let h_p = decode_point_be64(h)?;
    let c = decode_scalar_be32(challenge)?;
    let s = decode_scalar_be32(response)?;
    verify_chaum_ped_short(y1_p, y2_p, h_p, c, s, context)
}

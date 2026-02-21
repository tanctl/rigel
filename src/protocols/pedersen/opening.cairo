use core::array::Span;
use core::ec::{EcStateTrait, NonZeroEcPoint};
use core::traits::TryInto;

use crate::core::challenge::validate_challenge;
use crate::core::errors::{VerifyError, VerifyResult};
use crate::core::scalar::is_canonical_scalar;
use crate::core::sigma::{derive_challenge, verify_batchable, verify_with_challenge};
use crate::protocols::types::{PedersenProof, PedersenStatement, SigmaProof, SigmaStatement};
use crate::utils::bytes::{decode_point_be64, decode_scalar_be32};

pub fn verify_pedersen_opening(
    value_base: NonZeroEcPoint,
    blinding_base: NonZeroEcPoint,
    commitment: NonZeroEcPoint,
    nonce_commitment: NonZeroEcPoint,
    response_value: felt252,
    response_blinding: felt252,
    context: Span<felt252>,
) -> VerifyResult {
    let stmt = SigmaStatement::Pedersen(PedersenStatement {
        value_base,
        blinding_base,
        commitment,
    });
    let proof = SigmaProof::Pedersen(PedersenProof {
        nonce_commitment,
        response_value,
        response_blinding,
    });
    verify_batchable(stmt, proof, context)
}

pub fn verify_pedersen_opening_bytes(
    value_base: Span<u8>,
    blinding_base: Span<u8>,
    commitment: Span<u8>,
    nonce_commitment: Span<u8>,
    response_value: Span<u8>,
    response_blinding: Span<u8>,
    context: Span<felt252>,
) -> VerifyResult {
    let gv = decode_point_be64(value_base)?;
    let hb = decode_point_be64(blinding_base)?;
    let c = decode_point_be64(commitment)?;
    let r = decode_point_be64(nonce_commitment)?;
    let s_v = decode_scalar_be32(response_value)?;
    let s_r = decode_scalar_be32(response_blinding)?;
    verify_pedersen_opening(gv, hb, c, r, s_v, s_r, context)
}

pub fn verify_pedersen_opening_short(
    value_base: NonZeroEcPoint,
    blinding_base: NonZeroEcPoint,
    commitment: NonZeroEcPoint,
    challenge: felt252,
    response_value: felt252,
    response_blinding: felt252,
    context: Span<felt252>,
) -> VerifyResult {
    validate_challenge(challenge)?;
    if !is_canonical_scalar(response_value) || !is_canonical_scalar(response_blinding) {
        return Err(VerifyError::NonCanonicalScalar);
    }

    let mut lhs_state = EcStateTrait::init();
    lhs_state.add_mul(response_value, value_base);
    lhs_state.add_mul(response_blinding, blinding_base);
    let lhs = lhs_state.finalize();
    let mut rhs_state = EcStateTrait::init();
    rhs_state.add_mul(challenge, commitment);
    let rhs = rhs_state.finalize();
    let simulated = lhs + (-rhs);
    let Some(nonce_commitment) = simulated.try_into() else {
        return Err(VerifyError::InvalidProof);
    };

    let stmt = SigmaStatement::Pedersen(PedersenStatement {
        value_base,
        blinding_base,
        commitment,
    });
    let proof = SigmaProof::Pedersen(PedersenProof {
        nonce_commitment,
        response_value,
        response_blinding,
    });
    verify_with_challenge(stmt, proof, challenge)?;
    let expected = derive_challenge(stmt, proof, context)?;
    if expected == challenge {
        Ok(())
    } else {
        Err(VerifyError::InvalidProof)
    }
}

pub fn verify_pedersen_opening_short_bytes(
    value_base: Span<u8>,
    blinding_base: Span<u8>,
    commitment: Span<u8>,
    challenge: Span<u8>,
    response_value: Span<u8>,
    response_blinding: Span<u8>,
    context: Span<felt252>,
) -> VerifyResult {
    let gv = decode_point_be64(value_base)?;
    let hb = decode_point_be64(blinding_base)?;
    let c = decode_point_be64(commitment)?;
    let ch = decode_scalar_be32(challenge)?;
    let s_v = decode_scalar_be32(response_value)?;
    let s_r = decode_scalar_be32(response_blinding)?;
    verify_pedersen_opening_short(gv, hb, c, ch, s_v, s_r, context)
}

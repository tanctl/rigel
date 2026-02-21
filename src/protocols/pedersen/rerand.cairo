use core::array::Span;
use core::ec::{EcStateTrait, NonZeroEcPoint};
use core::traits::TryInto;

use crate::core::challenge::validate_challenge;
use crate::core::errors::{VerifyError, VerifyResult};
use crate::core::scalar::is_canonical_scalar;
use crate::core::sigma::{derive_challenge, verify_batchable, verify_with_challenge};
use crate::protocols::types::{PedersenRerandProof, PedersenRerandStatement, SigmaProof, SigmaStatement};
use crate::utils::bytes::{decode_point_be64, decode_scalar_be32};

/// verifies generalized pedersen commitment rerandomization: c2 = c1 + r*hr, without revealing r
pub fn verify_pedersen_rerand(
    rerand_base: NonZeroEcPoint,
    commitment_from: NonZeroEcPoint,
    commitment_to: NonZeroEcPoint,
    nonce_commitment: NonZeroEcPoint,
    response: felt252,
    context: Span<felt252>,
) -> VerifyResult {
    let stmt = SigmaStatement::PedersenRerand(PedersenRerandStatement {
        rerand_base,
        commitment_from,
        commitment_to,
    });
    let proof = SigmaProof::PedersenRerand(PedersenRerandProof {
        nonce_commitment,
        response,
    });
    verify_batchable(stmt, proof, context)
}

pub fn verify_pedersen_rerand_bytes(
    rerand_base: Span<u8>,
    commitment_from: Span<u8>,
    commitment_to: Span<u8>,
    nonce_commitment: Span<u8>,
    response: Span<u8>,
    context: Span<felt252>,
) -> VerifyResult {
    let hr = decode_point_be64(rerand_base)?;
    let c1 = decode_point_be64(commitment_from)?;
    let c2 = decode_point_be64(commitment_to)?;
    let r = decode_point_be64(nonce_commitment)?;
    let s = decode_scalar_be32(response)?;
    verify_pedersen_rerand(hr, c1, c2, r, s, context)
}

pub fn verify_pedersen_rerand_short(
    rerand_base: NonZeroEcPoint,
    commitment_from: NonZeroEcPoint,
    commitment_to: NonZeroEcPoint,
    challenge: felt252,
    response: felt252,
    context: Span<felt252>,
) -> VerifyResult {
    validate_challenge(challenge)?;
    if !is_canonical_scalar(response) {
        return Err(VerifyError::NonCanonicalScalar);
    }

    let mut delta_state = EcStateTrait::init();
    delta_state.add(commitment_to);
    delta_state.add(-commitment_from);
    let delta = delta_state.finalize();
    let Some(delta_nz) = delta.try_into() else {
        return Err(VerifyError::InvalidStatement);
    };

    let mut lhs_state = EcStateTrait::init();
    lhs_state.add_mul(response, rerand_base);
    let lhs = lhs_state.finalize();
    let mut rhs_state = EcStateTrait::init();
    rhs_state.add_mul(challenge, delta_nz);
    let rhs = rhs_state.finalize();
    let simulated = lhs + (-rhs);
    let Some(nonce_commitment) = simulated.try_into() else {
        return Err(VerifyError::InvalidProof);
    };

    let stmt = SigmaStatement::PedersenRerand(PedersenRerandStatement {
        rerand_base,
        commitment_from,
        commitment_to,
    });
    let proof = SigmaProof::PedersenRerand(PedersenRerandProof {
        nonce_commitment,
        response,
    });
    verify_with_challenge(stmt, proof, challenge)?;
    let expected = derive_challenge(stmt, proof, context)?;
    if expected == challenge {
        Ok(())
    } else {
        Err(VerifyError::InvalidProof)
    }
}

pub fn verify_pedersen_rerand_short_bytes(
    rerand_base: Span<u8>,
    commitment_from: Span<u8>,
    commitment_to: Span<u8>,
    challenge: Span<u8>,
    response: Span<u8>,
    context: Span<felt252>,
) -> VerifyResult {
    let hr = decode_point_be64(rerand_base)?;
    let c1 = decode_point_be64(commitment_from)?;
    let c2 = decode_point_be64(commitment_to)?;
    let ch = decode_scalar_be32(challenge)?;
    let s = decode_scalar_be32(response)?;
    verify_pedersen_rerand_short(hr, c1, c2, ch, s, context)
}

use core::array::Span;
use core::ec::{EcStateTrait, NonZeroEcPoint};
use core::traits::TryInto;

use crate::core::challenge::validate_challenge;
use crate::core::errors::{VerifyError, VerifyResult};
use crate::core::scalar::is_canonical_scalar;
use crate::core::sigma::{derive_challenge, verify_batchable, verify_with_challenge};
use crate::protocols::types::{DLogProof, DLogStatement, SigmaProof, SigmaStatement};
use crate::utils::bytes::{decode_point_be64, decode_scalar_be32};

pub fn verify_dlog(
    base: NonZeroEcPoint,
    public_key: NonZeroEcPoint,
    commitment: NonZeroEcPoint,
    response: felt252,
    context: Span<felt252>,
) -> VerifyResult {
    let stmt = SigmaStatement::DLog(DLogStatement { base, public_key });
    let proof = SigmaProof::DLog(DLogProof { commitment, response });
    verify_batchable(stmt, proof, context)
}

pub fn verify_dlog_with_challenge(
    base: NonZeroEcPoint,
    public_key: NonZeroEcPoint,
    commitment: NonZeroEcPoint,
    response: felt252,
    challenge: felt252,
) -> VerifyResult {
    validate_challenge(challenge)?;
    let stmt = SigmaStatement::DLog(DLogStatement { base, public_key });
    let proof = SigmaProof::DLog(DLogProof { commitment, response });
    verify_with_challenge(stmt, proof, challenge)
}

pub fn verify_dlog_bytes(
    base: Span<u8>,
    public_key: Span<u8>,
    commitment: Span<u8>,
    response: Span<u8>,
    context: Span<felt252>,
) -> VerifyResult {
    let base_p = decode_point_be64(base)?;
    let pk = decode_point_be64(public_key)?;
    let r = decode_point_be64(commitment)?;
    let s = decode_scalar_be32(response)?;
    verify_dlog(base_p, pk, r, s, context)
}

pub fn verify_dlog_short(
    base: NonZeroEcPoint,
    public_key: NonZeroEcPoint,
    challenge: felt252,
    response: felt252,
    context: Span<felt252>,
) -> VerifyResult {
    validate_challenge(challenge)?;
    if !is_canonical_scalar(response) {
        return Err(VerifyError::NonCanonicalScalar);
    }

    let mut lhs_state = EcStateTrait::init();
    lhs_state.add_mul(response, base);
    let lhs = lhs_state.finalize();

    let mut rhs_state = EcStateTrait::init();
    rhs_state.add_mul(challenge, public_key);
    let rhs = rhs_state.finalize();

    let simulated = lhs + (-rhs);
    let Some(commitment) = simulated.try_into() else {
        return Err(VerifyError::InvalidProof);
    };

    let stmt = SigmaStatement::DLog(DLogStatement { base, public_key });
    let proof = SigmaProof::DLog(DLogProof { commitment, response });
    verify_with_challenge(stmt, proof, challenge)?;
    let expected = derive_challenge(stmt, proof, context)?;
    if expected == challenge {
        Ok(())
    } else {
        Err(VerifyError::InvalidProof)
    }
}

pub fn verify_dlog_short_bytes(
    base: Span<u8>,
    public_key: Span<u8>,
    challenge: Span<u8>,
    response: Span<u8>,
    context: Span<felt252>,
) -> VerifyResult {
    let base_p = decode_point_be64(base)?;
    let pk = decode_point_be64(public_key)?;
    let c = decode_scalar_be32(challenge)?;
    let s = decode_scalar_be32(response)?;
    verify_dlog_short(base_p, pk, c, s, context)
}

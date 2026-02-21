use core::array::{Span, SpanTrait};
use core::ec::{EcStateTrait, NonZeroEcPoint};
use core::integer::u256;
use core::traits::TryInto;

use crate::core::challenge::validate_challenge;
use crate::core::errors::{VerifyError, VerifyResult};
use crate::core::limits::MAX_OKAMOTO_BASES_U256;
use crate::core::scalar::is_canonical_scalar;
use crate::core::sigma::{derive_challenge, verify_batchable, verify_with_challenge};
use crate::protocols::types::{OkamotoProof, OkamotoStatement, SigmaProof, SigmaStatement};
use crate::utils::bytes::{
    decode_point_be64,
    decode_points_be64,
    decode_scalar_be32,
    decode_scalars_be32,
    POINT_BYTES,
    SCALAR_BYTES,
};

pub fn verify_okamoto(
    bases: Span<NonZeroEcPoint>,
    statement: NonZeroEcPoint,
    commitment: NonZeroEcPoint,
    responses: Span<felt252>,
    context: Span<felt252>,
) -> VerifyResult {
    let stmt = SigmaStatement::Okamoto(OkamotoStatement { bases, y: statement });
    let proof = SigmaProof::Okamoto(OkamotoProof { commitment, responses });
    verify_batchable(stmt, proof, context)
}

pub fn verify_okamoto_with_challenge(
    bases: Span<NonZeroEcPoint>,
    statement: NonZeroEcPoint,
    commitment: NonZeroEcPoint,
    responses: Span<felt252>,
    challenge: felt252,
) -> VerifyResult {
    validate_challenge(challenge)?;
    let stmt = SigmaStatement::Okamoto(OkamotoStatement { bases, y: statement });
    let proof = SigmaProof::Okamoto(OkamotoProof { commitment, responses });
    verify_with_challenge(stmt, proof, challenge)
}

pub fn verify_okamoto_bytes(
    bases: Span<u8>,
    statement: Span<u8>,
    commitment: Span<u8>,
    responses: Span<u8>,
    context: Span<felt252>,
) -> VerifyResult {
    if bases.len() % POINT_BYTES != 0 {
        return Err(VerifyError::InvalidEncoding);
    }
    let n: u32 = bases.len() / POINT_BYTES;
    let n_u256: u256 = n.into();
    let zero: u256 = 0;
    if n_u256 == zero || n_u256 > MAX_OKAMOTO_BASES_U256 {
        return Err(VerifyError::InvalidStatement);
    }
    if responses.len() != n * SCALAR_BYTES {
        return Err(VerifyError::InvalidEncoding);
    }
    let bases_arr = decode_points_be64(bases)?;
    let stmt = decode_point_be64(statement)?;
    let comm = decode_point_be64(commitment)?;
    let responses_arr = decode_scalars_be32(responses)?;
    verify_okamoto(bases_arr.span(), stmt, comm, responses_arr.span(), context)
}

pub fn verify_okamoto_short(
    bases: Span<NonZeroEcPoint>,
    statement: NonZeroEcPoint,
    challenge: felt252,
    responses: Span<felt252>,
    context: Span<felt252>,
) -> VerifyResult {
    validate_challenge(challenge)?;
    if bases.len() != responses.len() {
        return Err(VerifyError::MismatchedLength);
    }
    let n_u256: u256 = bases.len().into();
    let zero: u256 = 0;
    if n_u256 == zero || n_u256 > MAX_OKAMOTO_BASES_U256 {
        return Err(VerifyError::InvalidStatement);
    }

    let mut sim_state = EcStateTrait::init();
    let mut bases_iter = bases;
    let mut responses_iter = responses;
    loop {
        match bases_iter.pop_front() {
            Some(base) => {
                let Some(s_ref) = responses_iter.pop_front() else {
                    return Err(VerifyError::MismatchedLength);
                };
                if !is_canonical_scalar(*s_ref) {
                    return Err(VerifyError::NonCanonicalScalar);
                }
                sim_state.add_mul(*s_ref, *base);
            },
            None => { break; },
        }
    }

    let lhs = sim_state.finalize();
    let mut rhs_state = EcStateTrait::init();
    rhs_state.add_mul(challenge, statement);
    let rhs = rhs_state.finalize();
    let simulated = lhs + (-rhs);
    let Some(commitment) = simulated.try_into() else {
        return Err(VerifyError::InvalidProof);
    };

    let stmt = SigmaStatement::Okamoto(OkamotoStatement { bases, y: statement });
    let proof = SigmaProof::Okamoto(OkamotoProof { commitment, responses });
    verify_with_challenge(stmt, proof, challenge)?;
    let expected = derive_challenge(stmt, proof, context)?;
    if expected == challenge {
        Ok(())
    } else {
        Err(VerifyError::InvalidProof)
    }
}

pub fn verify_okamoto_short_bytes(
    bases: Span<u8>,
    statement: Span<u8>,
    challenge: Span<u8>,
    responses: Span<u8>,
    context: Span<felt252>,
) -> VerifyResult {
    if bases.len() % POINT_BYTES != 0 {
        return Err(VerifyError::InvalidEncoding);
    }
    let n: u32 = bases.len() / POINT_BYTES;
    let n_u256: u256 = n.into();
    let zero: u256 = 0;
    if n_u256 == zero || n_u256 > MAX_OKAMOTO_BASES_U256 {
        return Err(VerifyError::InvalidStatement);
    }
    if responses.len() != n * SCALAR_BYTES {
        return Err(VerifyError::InvalidEncoding);
    }
    let bases_arr = decode_points_be64(bases)?;
    let stmt = decode_point_be64(statement)?;
    let c = decode_scalar_be32(challenge)?;
    let responses_arr = decode_scalars_be32(responses)?;
    verify_okamoto_short(bases_arr.span(), stmt, c, responses_arr.span(), context)
}

use core::array::{Span, SpanTrait};
use core::integer::u256;
use core::traits::Into;
use core::ec::NonZeroEcPoint;

use crate::core::sigma::verify_with_challenge_allow_zero;
use crate::core::errors::{VerifyError, VerifyResult};
use crate::core::limits::MAX_RING_SIZE_U256;
use crate::core::scalar::{is_canonical_scalar, order_u256};
use crate::core::transcript::{build_ring_transcript, transcript_challenge};
use crate::protocols::types::{SchnorrProof, SchnorrStatement, SigmaProof, SigmaStatement};
use crate::utils::bytes::{decode_points_be64, decode_scalars_be32, POINT_BYTES, SCALAR_BYTES};

#[derive(Copy, Drop)]
pub struct RingStatement {
    pub public_keys: Span<NonZeroEcPoint>,
}

#[derive(Copy, Drop)]
pub struct RingProof {
    pub commitments: Span<NonZeroEcPoint>,
    pub challenges: Span<felt252>,
    pub responses: Span<felt252>,
}

/// ring membership proof where branch challenges sum to the global challenge modulo order
pub fn verify_ring(stmt: RingStatement, proof: RingProof, context: Span<felt252>) -> VerifyResult {
    let n = stmt.public_keys.len();
    if n == 0 {
        return Err(VerifyError::EmptyInstances);
    }
    if n != proof.commitments.len() || n != proof.challenges.len() || n != proof.responses.len() {
        return Err(VerifyError::MismatchedLength);
    }
    let n_u256: u256 = n.into();
    if n_u256 > MAX_RING_SIZE_U256 {
        return Err(VerifyError::InvalidStatement);
    }

    let transcript = build_ring_transcript(stmt.public_keys, proof.commitments, context);
    let Some(global_challenge) = transcript_challenge(@transcript) else {
        return Err(VerifyError::ZeroChallenge);
    };

    let order = order_u256();
    let mut sum_acc: u256 = 0;
    let mut challenges_iter = proof.challenges;
    loop {
        match challenges_iter.pop_front() {
            Some(c_ref) => {
                let c = *c_ref;
                if !is_canonical_scalar(c) {
                    return Err(VerifyError::NonCanonicalScalar);
                }
                let c_u256: u256 = c.into();
                let tmp = sum_acc + c_u256;
                sum_acc = if tmp >= order { tmp - order } else { tmp };
            },
            None => { break; },
        }
    }
    let global_u256: u256 = global_challenge.into();
    if sum_acc != global_u256 {
        return Err(VerifyError::OrChallengeSumMismatch);
    }

    let mut keys_iter = stmt.public_keys;
    let mut comm_iter = proof.commitments;
    let mut chall_iter = proof.challenges;
    let mut resp_iter = proof.responses;

    loop {
        match keys_iter.pop_front() {
            Some(pk_ref) => {
                let Some(r_ref) = comm_iter.pop_front() else {
                    return Err(VerifyError::MismatchedLength);
                };
                let Some(c_ref) = chall_iter.pop_front() else {
                    return Err(VerifyError::MismatchedLength);
                };
                let Some(s_ref) = resp_iter.pop_front() else {
                    return Err(VerifyError::MismatchedLength);
                };

                let stmt_leaf = SigmaStatement::Schnorr(SchnorrStatement { public_key: *pk_ref });
                let proof_leaf = SigmaProof::Schnorr(SchnorrProof { commitment: *r_ref, response: *s_ref });
                verify_with_challenge_allow_zero(stmt_leaf, proof_leaf, *c_ref)?;
            },
            None => { break; },
        }
    }

    Ok(())
}

pub fn verify_ring_bytes(
    public_keys: Span<u8>,
    commitments: Span<u8>,
    challenges: Span<u8>,
    responses: Span<u8>,
    context: Span<felt252>,
) -> VerifyResult {
    if public_keys.len() % POINT_BYTES != 0 {
        return Err(VerifyError::InvalidEncoding);
    }
    let n: u32 = public_keys.len() / POINT_BYTES;
    if n == 0 {
        return Err(VerifyError::EmptyInstances);
    }
    let n_u256: u256 = n.into();
    if n_u256 > MAX_RING_SIZE_U256 {
        return Err(VerifyError::InvalidStatement);
    }
    if commitments.len() != n * POINT_BYTES {
        return Err(VerifyError::InvalidEncoding);
    }
    if challenges.len() != n * SCALAR_BYTES || responses.len() != n * SCALAR_BYTES {
        return Err(VerifyError::InvalidEncoding);
    }
    let keys = decode_points_be64(public_keys)?;
    let comms = decode_points_be64(commitments)?;
    let challs = decode_scalars_be32(challenges)?;
    let resps = decode_scalars_be32(responses)?;
    let stmt = RingStatement { public_keys: keys.span() };
    let proof = RingProof { commitments: comms.span(), challenges: challs.span(), responses: resps.span() };
    verify_ring(stmt, proof, context)
}

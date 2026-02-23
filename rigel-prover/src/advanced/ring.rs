use rand::RngCore;
use starknet_crypto::Felt;

use crate::core::curve::{Point, ensure_non_identity, generator, mul, reject_identity, sub};
use crate::core::errors::{ProverError, Result};
use crate::core::limits::MAX_RING_SIZE;
use crate::core::scalar::Scalar;
use crate::core::sigma::verify_with_challenge_allow_zero;
use crate::core::transcript::build_ring_transcript;
use crate::protocols::types::{SchnorrProof, SchnorrStatement, SigmaProof, SigmaStatement};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RingStatement {
    pub public_keys: Vec<Point>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RingProof {
    pub commitments: Vec<Point>,
    pub challenges: Vec<Scalar>,
    pub responses: Vec<Scalar>,
}

const MAX_SIM_ATTEMPTS: usize = 128;
const MAX_RING_ATTEMPTS: usize = 128;

#[inline]
fn sum_fold_challenges<'a, I>(iter: I) -> Scalar
where
    I: IntoIterator<Item = &'a Scalar>,
{
    let mut acc = Scalar::from_u64(0);
    for c in iter {
        acc = acc.add_mod(c);
    }
    acc
}

pub fn prove_ring<R: RngCore>(
    statement: &RingStatement,
    real_index: usize,
    secret: &Scalar,
    context: &[Felt],
    rng: &mut R,
) -> Result<RingProof> {
    let n = statement.public_keys.len();
    if n == 0 || n > MAX_RING_SIZE {
        return Err(ProverError::InvalidStatement);
    }
    if real_index >= n {
        return Err(ProverError::InvalidStatement);
    }
    for pk in &statement.public_keys {
        ensure_non_identity(pk)?;
    }

    let g = generator();
    let expected_pk = mul(&g, secret);
    if expected_pk != statement.public_keys[real_index] {
        return Err(ProverError::InvalidWitness);
    }

    for _ in 0..MAX_RING_ATTEMPTS {
        let k = Scalar::random_nonzero(rng)?;
        let r_real = mul(&g, &k);
        if reject_identity(&r_real).is_err() {
            continue;
        }

        let mut commitments = Vec::with_capacity(n);
        let mut challenges = Vec::with_capacity(n);
        let mut responses = Vec::with_capacity(n);

        for (i, pk) in statement.public_keys.iter().enumerate() {
            if i == real_index {
                commitments.push(r_real.clone());
                challenges.push(Scalar::from_u64(0));
                responses.push(Scalar::from_u64(0));
            } else {
                let mut found = false;
                for _ in 0..MAX_SIM_ATTEMPTS {
                    let c_i = Scalar::random(rng, true)?;
                    let s_i = Scalar::random(rng, true)?;
                    let r_i = sub(&mul(&g, &s_i), &mul(pk, &c_i));
                    if reject_identity(&r_i).is_ok() {
                        commitments.push(r_i);
                        challenges.push(c_i);
                        responses.push(s_i);
                        found = true;
                        break;
                    }
                }
                if !found {
                    return Err(ProverError::InvalidWitness);
                }
            }
        }

        let transcript = build_ring_transcript(&statement.public_keys, &commitments, context);
        let global_challenge = transcript.challenge()?;

        let sum_sim = sum_fold_challenges(
            challenges
                .iter()
                .enumerate()
                .filter_map(|(i, c)| if i == real_index { None } else { Some(c) }),
        );
        let c_real = global_challenge.sub_mod(&sum_sim);
        let s_real = k.add_mod(&c_real.mul_mod(secret));

        challenges[real_index] = c_real;
        responses[real_index] = s_real;

        return Ok(RingProof {
            commitments,
            challenges,
            responses,
        });
    }
    Err(ProverError::InvalidWitness)
}

pub fn verify_ring(statement: &RingStatement, proof: &RingProof, context: &[Felt]) -> Result<()> {
    let n = statement.public_keys.len();
    if n == 0 || n > MAX_RING_SIZE {
        return Err(ProverError::InvalidStatement);
    }
    if proof.commitments.len() != n || proof.challenges.len() != n || proof.responses.len() != n {
        return Err(ProverError::MismatchedLength);
    }
    for pk in &statement.public_keys {
        ensure_non_identity(pk)?;
    }
    for r_i in &proof.commitments {
        ensure_non_identity(r_i)?;
    }

    let transcript = build_ring_transcript(&statement.public_keys, &proof.commitments, context);
    let global_challenge = transcript.challenge()?;

    let mut sum_acc = Scalar::from_u64(0);
    for c in proof.challenges.iter() {
        c.ensure_canonical()?;
        sum_acc = sum_acc.add_mod(c);
    }
    if sum_acc != global_challenge {
        return Err(ProverError::OrChallengeSumMismatch);
    }

    for ((pk, r_i), (c_i, s_i)) in statement
        .public_keys
        .iter()
        .zip(proof.commitments.iter())
        .zip(proof.challenges.iter().zip(proof.responses.iter()))
    {
        let stmt_leaf = SigmaStatement::Schnorr(SchnorrStatement {
            public_key: pk.clone(),
        });
        let proof_leaf = SigmaProof::Schnorr(SchnorrProof {
            commitment: r_i.clone(),
            response: s_i.clone(),
        });
        verify_with_challenge_allow_zero(&stmt_leaf, &proof_leaf, c_i)?;
    }
    Ok(())
}

use rand::RngCore;

use crate::core::curve::{Point, add, generator, mul, reject_identity, sub};
use crate::core::errors::{ProverError, Result};
use crate::core::limits::MAX_OKAMOTO_BASES;
use crate::core::scalar::Scalar;
use crate::protocols::types::{
    ChaumPedProof, DLogProof, OkamotoProof, PedersenEqProof, PedersenProof, PedersenRerandProof,
    SchnorrProof, SigmaProof, SigmaStatement, SigmaWitness,
};

#[derive(Clone, Debug)]
pub enum SigmaNonce {
    Schnorr {
        k: Scalar,
    },
    DLog {
        k: Scalar,
    },
    ChaumPed {
        k: Scalar,
    },
    Okamoto {
        ks: Vec<Scalar>,
    },
    Pedersen {
        k_v: Scalar,
        k_r: Scalar,
    },
    PedersenEq {
        k_v: Scalar,
        k_r1: Scalar,
        k_r2: Scalar,
    },
    PedersenRerand {
        k: Scalar,
    },
}

const MAX_SIM_ATTEMPTS: usize = 128;

pub fn sample_nonce<R: RngCore>(stmt: &SigmaStatement, rng: &mut R) -> Result<SigmaNonce> {
    Ok(match stmt {
        SigmaStatement::Schnorr(_) => SigmaNonce::Schnorr {
            k: Scalar::random_nonzero(rng)?,
        },
        SigmaStatement::DLog(_) => SigmaNonce::DLog {
            k: Scalar::random_nonzero(rng)?,
        },
        SigmaStatement::ChaumPed(_) => SigmaNonce::ChaumPed {
            k: Scalar::random_nonzero(rng)?,
        },
        SigmaStatement::Okamoto(s) => {
            if s.bases.is_empty() || s.bases.len() > MAX_OKAMOTO_BASES {
                return Err(ProverError::InvalidStatement);
            }
            let mut ks = Vec::with_capacity(s.bases.len());
            for _ in 0..s.bases.len() {
                ks.push(Scalar::random_nonzero(rng)?);
            }
            SigmaNonce::Okamoto { ks }
        }
        SigmaStatement::Pedersen(_) => SigmaNonce::Pedersen {
            k_v: Scalar::random_nonzero(rng)?,
            k_r: Scalar::random_nonzero(rng)?,
        },
        SigmaStatement::PedersenEq(_) => SigmaNonce::PedersenEq {
            k_v: Scalar::random_nonzero(rng)?,
            k_r1: Scalar::random_nonzero(rng)?,
            k_r2: Scalar::random_nonzero(rng)?,
        },
        SigmaStatement::PedersenRerand(_) => SigmaNonce::PedersenRerand {
            k: Scalar::random_nonzero(rng)?,
        },
    })
}

pub fn commitment_from_nonce(stmt: &SigmaStatement, nonce: &SigmaNonce) -> Result<SigmaProof> {
    match (stmt, nonce) {
        (SigmaStatement::Schnorr(_), SigmaNonce::Schnorr { k }) => {
            let g = generator();
            let commitment = mul(&g, k);
            reject_identity(&commitment)?;
            Ok(SigmaProof::Schnorr(SchnorrProof {
                commitment,
                response: Scalar::from_u64(0),
            }))
        }
        (SigmaStatement::DLog(s), SigmaNonce::DLog { k }) => {
            let commitment = mul(&s.base, k);
            reject_identity(&commitment)?;
            Ok(SigmaProof::DLog(DLogProof {
                commitment,
                response: Scalar::from_u64(0),
            }))
        }
        (SigmaStatement::ChaumPed(s), SigmaNonce::ChaumPed { k }) => {
            let g = generator();
            let r1 = mul(&g, k);
            let r2 = mul(&s.h, k);
            reject_identity(&r1)?;
            reject_identity(&r2)?;
            Ok(SigmaProof::ChaumPed(ChaumPedProof {
                r1,
                r2,
                response: Scalar::from_u64(0),
            }))
        }
        (SigmaStatement::Okamoto(s), SigmaNonce::Okamoto { ks }) => {
            if s.bases.is_empty() || s.bases.len() > MAX_OKAMOTO_BASES {
                return Err(ProverError::InvalidStatement);
            }
            if s.bases.len() != ks.len() {
                return Err(ProverError::MismatchedLength);
            }
            let mut acc = Point::identity();
            for (base, k) in s.bases.iter().zip(ks.iter()) {
                acc = add(&acc, &mul(base, k));
            }
            reject_identity(&acc)?;
            Ok(SigmaProof::Okamoto(OkamotoProof {
                commitment: acc,
                responses: vec![Scalar::from_u64(0); ks.len()],
            }))
        }
        (SigmaStatement::Pedersen(s), SigmaNonce::Pedersen { k_v, k_r }) => {
            let commitment = add(&mul(&s.value_base, k_v), &mul(&s.blinding_base, k_r));
            reject_identity(&commitment)?;
            Ok(SigmaProof::Pedersen(PedersenProof {
                nonce_commitment: commitment,
                response_value: Scalar::from_u64(0),
                response_blinding: Scalar::from_u64(0),
            }))
        }
        (SigmaStatement::PedersenEq(s), SigmaNonce::PedersenEq { k_v, k_r1, k_r2 }) => {
            let nonce_commitment1 = add(&mul(&s.value_base1, k_v), &mul(&s.blinding_base1, k_r1));
            let nonce_commitment2 = add(&mul(&s.value_base2, k_v), &mul(&s.blinding_base2, k_r2));
            reject_identity(&nonce_commitment1)?;
            reject_identity(&nonce_commitment2)?;
            Ok(SigmaProof::PedersenEq(PedersenEqProof {
                nonce_commitment1,
                nonce_commitment2,
                response_value: Scalar::from_u64(0),
                response_blinding1: Scalar::from_u64(0),
                response_blinding2: Scalar::from_u64(0),
            }))
        }
        (SigmaStatement::PedersenRerand(s), SigmaNonce::PedersenRerand { k }) => {
            let commitment = mul(&s.rerand_base, k);
            reject_identity(&commitment)?;
            Ok(SigmaProof::PedersenRerand(PedersenRerandProof {
                nonce_commitment: commitment,
                response: Scalar::from_u64(0),
            }))
        }
        _ => Err(ProverError::MismatchedProofType),
    }
}

pub fn prove_with_challenge(
    stmt: &SigmaStatement,
    witness: &SigmaWitness,
    nonce: &SigmaNonce,
    challenge: &Scalar,
) -> Result<SigmaProof> {
    match (stmt, witness, nonce) {
        (
            SigmaStatement::Schnorr(s),
            SigmaWitness::Schnorr { secret },
            SigmaNonce::Schnorr { k },
        ) => {
            let g = generator();
            let expected = mul(&g, secret);
            if expected != s.public_key {
                return Err(ProverError::InvalidWitness);
            }
            let commitment = mul(&g, k);
            reject_identity(&commitment)?;
            let response = k.add_mod(&challenge.mul_mod(secret));
            Ok(SigmaProof::Schnorr(SchnorrProof {
                commitment,
                response,
            }))
        }
        (SigmaStatement::DLog(s), SigmaWitness::DLog { secret }, SigmaNonce::DLog { k }) => {
            let expected = mul(&s.base, secret);
            if expected != s.public_key {
                return Err(ProverError::InvalidWitness);
            }
            let commitment = mul(&s.base, k);
            reject_identity(&commitment)?;
            let response = k.add_mod(&challenge.mul_mod(secret));
            Ok(SigmaProof::DLog(DLogProof {
                commitment,
                response,
            }))
        }
        (
            SigmaStatement::ChaumPed(s),
            SigmaWitness::ChaumPed { secret },
            SigmaNonce::ChaumPed { k },
        ) => {
            let g = generator();
            let expected_y1 = mul(&g, secret);
            let expected_y2 = mul(&s.h, secret);
            if expected_y1 != s.y1 || expected_y2 != s.y2 {
                return Err(ProverError::InvalidWitness);
            }
            let r1 = mul(&g, k);
            let r2 = mul(&s.h, k);
            reject_identity(&r1)?;
            reject_identity(&r2)?;
            let response = k.add_mod(&challenge.mul_mod(secret));
            Ok(SigmaProof::ChaumPed(ChaumPedProof { r1, r2, response }))
        }
        (
            SigmaStatement::Okamoto(s),
            SigmaWitness::Okamoto { secrets },
            SigmaNonce::Okamoto { ks },
        ) => {
            if s.bases.is_empty() || s.bases.len() > MAX_OKAMOTO_BASES {
                return Err(ProverError::InvalidStatement);
            }
            if s.bases.len() != secrets.len() || s.bases.len() != ks.len() {
                return Err(ProverError::MismatchedLength);
            }
            let mut expected = Point::identity();
            for (base, x) in s.bases.iter().zip(secrets.iter()) {
                expected = add(&expected, &mul(base, x));
            }
            if expected != s.y {
                return Err(ProverError::InvalidWitness);
            }
            let mut commitment = Point::identity();
            for (base, k) in s.bases.iter().zip(ks.iter()) {
                commitment = add(&commitment, &mul(base, k));
            }
            reject_identity(&commitment)?;
            let responses = ks
                .iter()
                .zip(secrets.iter())
                .map(|(k_i, x_i)| k_i.add_mod(&challenge.mul_mod(x_i)))
                .collect();
            Ok(SigmaProof::Okamoto(OkamotoProof {
                commitment,
                responses,
            }))
        }
        (
            SigmaStatement::Pedersen(s),
            SigmaWitness::Pedersen { value, blinding },
            SigmaNonce::Pedersen { k_v, k_r },
        ) => {
            let expected = add(&mul(&s.value_base, value), &mul(&s.blinding_base, blinding));
            if expected != s.commitment {
                return Err(ProverError::InvalidWitness);
            }
            let nonce_commitment = add(&mul(&s.value_base, k_v), &mul(&s.blinding_base, k_r));
            reject_identity(&nonce_commitment)?;
            let response_value = k_v.add_mod(&challenge.mul_mod(value));
            let response_blinding = k_r.add_mod(&challenge.mul_mod(blinding));
            Ok(SigmaProof::Pedersen(PedersenProof {
                nonce_commitment,
                response_value,
                response_blinding,
            }))
        }
        (
            SigmaStatement::PedersenEq(s),
            SigmaWitness::PedersenEq {
                value,
                blinding1,
                blinding2,
            },
            SigmaNonce::PedersenEq { k_v, k_r1, k_r2 },
        ) => {
            let expected1 = add(
                &mul(&s.value_base1, value),
                &mul(&s.blinding_base1, blinding1),
            );
            let expected2 = add(
                &mul(&s.value_base2, value),
                &mul(&s.blinding_base2, blinding2),
            );
            if expected1 != s.commitment1 || expected2 != s.commitment2 {
                return Err(ProverError::InvalidWitness);
            }
            let nonce_commitment1 = add(&mul(&s.value_base1, k_v), &mul(&s.blinding_base1, k_r1));
            let nonce_commitment2 = add(&mul(&s.value_base2, k_v), &mul(&s.blinding_base2, k_r2));
            reject_identity(&nonce_commitment1)?;
            reject_identity(&nonce_commitment2)?;
            let response_value = k_v.add_mod(&challenge.mul_mod(value));
            let response_blinding1 = k_r1.add_mod(&challenge.mul_mod(blinding1));
            let response_blinding2 = k_r2.add_mod(&challenge.mul_mod(blinding2));
            Ok(SigmaProof::PedersenEq(PedersenEqProof {
                nonce_commitment1,
                nonce_commitment2,
                response_value,
                response_blinding1,
                response_blinding2,
            }))
        }
        (
            SigmaStatement::PedersenRerand(s),
            SigmaWitness::PedersenRerand { rerand },
            SigmaNonce::PedersenRerand { k },
        ) => {
            if rerand.is_zero() {
                return Err(ProverError::InvalidWitness);
            }
            let expected = add(&s.commitment_from, &mul(&s.rerand_base, rerand));
            if expected != s.commitment_to {
                return Err(ProverError::InvalidWitness);
            }
            let delta = sub(&s.commitment_to, &s.commitment_from);
            reject_identity(&delta)?;
            let nonce_commitment = mul(&s.rerand_base, k);
            reject_identity(&nonce_commitment)?;
            let response = k.add_mod(&challenge.mul_mod(rerand));
            Ok(SigmaProof::PedersenRerand(PedersenRerandProof {
                nonce_commitment,
                response,
            }))
        }
        _ => Err(ProverError::MismatchedProofType),
    }
}

pub fn simulate_proof<R: RngCore>(
    stmt: &SigmaStatement,
    challenge: &Scalar,
    rng: &mut R,
) -> Result<SigmaProof> {
    match stmt {
        SigmaStatement::Schnorr(s) => {
            let g = generator();
            for _ in 0..MAX_SIM_ATTEMPTS {
                let response = Scalar::random(rng, true)?;
                let commitment = sub(&mul(&g, &response), &mul(&s.public_key, challenge));
                if reject_identity(&commitment).is_ok() {
                    return Ok(SigmaProof::Schnorr(SchnorrProof {
                        commitment,
                        response,
                    }));
                }
            }
            Err(ProverError::IdentityPoint)
        }
        SigmaStatement::DLog(s) => {
            for _ in 0..MAX_SIM_ATTEMPTS {
                let response = Scalar::random(rng, true)?;
                let commitment = sub(&mul(&s.base, &response), &mul(&s.public_key, challenge));
                if reject_identity(&commitment).is_ok() {
                    return Ok(SigmaProof::DLog(DLogProof {
                        commitment,
                        response,
                    }));
                }
            }
            Err(ProverError::IdentityPoint)
        }
        SigmaStatement::ChaumPed(s) => {
            let g = generator();
            for _ in 0..MAX_SIM_ATTEMPTS {
                let response = Scalar::random(rng, true)?;
                let r1 = sub(&mul(&g, &response), &mul(&s.y1, challenge));
                let r2 = sub(&mul(&s.h, &response), &mul(&s.y2, challenge));
                if reject_identity(&r1).is_ok() && reject_identity(&r2).is_ok() {
                    return Ok(SigmaProof::ChaumPed(ChaumPedProof { r1, r2, response }));
                }
            }
            Err(ProverError::IdentityPoint)
        }
        SigmaStatement::Okamoto(s) => {
            if s.bases.is_empty() || s.bases.len() > MAX_OKAMOTO_BASES {
                return Err(ProverError::InvalidStatement);
            }
            for _ in 0..MAX_SIM_ATTEMPTS {
                let mut responses = Vec::with_capacity(s.bases.len());
                for _ in 0..s.bases.len() {
                    responses.push(Scalar::random(rng, true)?);
                }
                let mut acc = Point::identity();
                for (base, resp) in s.bases.iter().zip(responses.iter()) {
                    acc = add(&acc, &mul(base, resp));
                }
                let commitment = sub(&acc, &mul(&s.y, challenge));
                if reject_identity(&commitment).is_ok() {
                    return Ok(SigmaProof::Okamoto(OkamotoProof {
                        commitment,
                        responses,
                    }));
                }
            }
            Err(ProverError::IdentityPoint)
        }
        SigmaStatement::Pedersen(s) => {
            for _ in 0..MAX_SIM_ATTEMPTS {
                let response_value = Scalar::random(rng, true)?;
                let response_blinding = Scalar::random(rng, true)?;
                let acc = add(
                    &mul(&s.value_base, &response_value),
                    &mul(&s.blinding_base, &response_blinding),
                );
                let nonce_commitment = sub(&acc, &mul(&s.commitment, challenge));
                if reject_identity(&nonce_commitment).is_ok() {
                    return Ok(SigmaProof::Pedersen(PedersenProof {
                        nonce_commitment,
                        response_value,
                        response_blinding,
                    }));
                }
            }
            Err(ProverError::IdentityPoint)
        }
        SigmaStatement::PedersenEq(s) => {
            for _ in 0..MAX_SIM_ATTEMPTS {
                let response_value = Scalar::random(rng, true)?;
                let response_blinding1 = Scalar::random(rng, true)?;
                let response_blinding2 = Scalar::random(rng, true)?;
                let acc1 = add(
                    &mul(&s.value_base1, &response_value),
                    &mul(&s.blinding_base1, &response_blinding1),
                );
                let acc2 = add(
                    &mul(&s.value_base2, &response_value),
                    &mul(&s.blinding_base2, &response_blinding2),
                );
                let nonce_commitment1 = sub(&acc1, &mul(&s.commitment1, challenge));
                let nonce_commitment2 = sub(&acc2, &mul(&s.commitment2, challenge));
                if reject_identity(&nonce_commitment1).is_ok()
                    && reject_identity(&nonce_commitment2).is_ok()
                {
                    return Ok(SigmaProof::PedersenEq(PedersenEqProof {
                        nonce_commitment1,
                        nonce_commitment2,
                        response_value,
                        response_blinding1,
                        response_blinding2,
                    }));
                }
            }
            Err(ProverError::IdentityPoint)
        }
        SigmaStatement::PedersenRerand(s) => {
            let delta = sub(&s.commitment_to, &s.commitment_from);
            reject_identity(&delta)?;
            for _ in 0..MAX_SIM_ATTEMPTS {
                let response = Scalar::random(rng, true)?;
                let acc = mul(&s.rerand_base, &response);
                let nonce_commitment = sub(&acc, &mul(&delta, challenge));
                if reject_identity(&nonce_commitment).is_ok() {
                    return Ok(SigmaProof::PedersenRerand(PedersenRerandProof {
                        nonce_commitment,
                        response,
                    }));
                }
            }
            Err(ProverError::IdentityPoint)
        }
    }
}

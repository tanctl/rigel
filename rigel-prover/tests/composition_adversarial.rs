use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use starknet_crypto::Felt;

use rigel_prover::advanced::ring::{RingStatement, prove_ring, verify_ring};
use rigel_prover::composition::or::{prove_or, verify_or};
use rigel_prover::core::curve::{generator, mul, pedersen_h};
use rigel_prover::core::errors::ProverError;
use rigel_prover::core::scalar::Scalar;
use rigel_prover::protocols::atomic::chaum_pedersen::chaum_ped_statement;
use rigel_prover::protocols::atomic::dlog::dlog_statement;
use rigel_prover::protocols::atomic::schnorr::schnorr_statement;
use rigel_prover::protocols::types::{SigmaStatement, SigmaWitness};

fn ctx(tag: u64) -> Vec<Felt> {
    vec![Felt::from(20260223u64), Felt::from(tag)]
}

fn rand_nonzero_scalar(rng: &mut ChaCha20Rng) -> Scalar {
    Scalar::random_nonzero(rng).expect("nonzero scalar")
}

#[test]
fn or_composition_rejects_challenge_tampering() {
    let mut rng = ChaCha20Rng::seed_from_u64(4401);

    let schnorr_secret = rand_nonzero_scalar(&mut rng);
    let schnorr_stmt = SigmaStatement::Schnorr(schnorr_statement(&schnorr_secret));

    let dlog_base = pedersen_h();
    let dlog_secret = rand_nonzero_scalar(&mut rng);
    let dlog_stmt = SigmaStatement::DLog(dlog_statement(&dlog_base, &dlog_secret));

    let cp_h = mul(&generator(), &rand_nonzero_scalar(&mut rng));
    let cp_secret = rand_nonzero_scalar(&mut rng);
    let cp_stmt = SigmaStatement::ChaumPed(chaum_ped_statement(&cp_h, &cp_secret));

    let statements = vec![schnorr_stmt, dlog_stmt, cp_stmt];
    let proof = prove_or(
        &statements,
        1,
        &SigmaWitness::DLog {
            secret: dlog_secret.clone(),
        },
        &ctx(70),
        &mut rng,
    )
    .unwrap();
    verify_or(&proof, &ctx(70)).unwrap();

    let mut sum_mismatch = proof.clone();
    sum_mismatch[0].challenge = sum_mismatch[0].challenge.add_mod(&Scalar::from_u64(1));
    assert!(matches!(
        verify_or(&sum_mismatch, &ctx(70)),
        Err(ProverError::OrChallengeSumMismatch)
    ));

    let mut balanced_tamper = proof.clone();
    balanced_tamper[0].challenge = balanced_tamper[0].challenge.add_mod(&Scalar::from_u64(1));
    balanced_tamper[1].challenge = balanced_tamper[1].challenge.sub_mod(&Scalar::from_u64(1));
    assert!(matches!(
        verify_or(&balanced_tamper, &ctx(70)),
        Err(ProverError::InvalidProof)
    ));
}

#[test]
fn ring_rejects_challenge_tampering() {
    let mut rng = ChaCha20Rng::seed_from_u64(4402);
    let real_secret = rand_nonzero_scalar(&mut rng);
    let statement = RingStatement {
        public_keys: vec![
            mul(&generator(), &rand_nonzero_scalar(&mut rng)),
            mul(&generator(), &rand_nonzero_scalar(&mut rng)),
            mul(&generator(), &real_secret),
            mul(&generator(), &rand_nonzero_scalar(&mut rng)),
        ],
    };
    let proof = prove_ring(&statement, 2, &real_secret, &ctx(71), &mut rng).unwrap();
    verify_ring(&statement, &proof, &ctx(71)).unwrap();

    let mut sum_mismatch = proof.clone();
    sum_mismatch.challenges[0] = sum_mismatch.challenges[0].add_mod(&Scalar::from_u64(1));
    assert!(matches!(
        verify_ring(&statement, &sum_mismatch, &ctx(71)),
        Err(ProverError::OrChallengeSumMismatch)
    ));

    let mut balanced_tamper = proof.clone();
    balanced_tamper.challenges[0] = balanced_tamper.challenges[0].add_mod(&Scalar::from_u64(1));
    balanced_tamper.challenges[1] = balanced_tamper.challenges[1].sub_mod(&Scalar::from_u64(1));
    assert!(matches!(
        verify_ring(&statement, &balanced_tamper, &ctx(71)),
        Err(ProverError::InvalidProof)
    ));
}

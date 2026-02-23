use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use starknet_crypto::Felt;

use rigel_prover::advanced::{
    one_out_of_many::{
        PedersenOneOutOfManyStatement, prove_pedersen_one_out_of_many,
        verify_pedersen_one_out_of_many,
    },
    ring::{RingStatement, prove_ring, verify_ring},
};
use rigel_prover::core::curve::{generator, mul, pedersen_h};
use rigel_prover::core::errors::ProverError;
use rigel_prover::core::scalar::Scalar;
use rigel_prover::core::sigma::derive_challenge;
use rigel_prover::protocols::{
    atomic::{
        chaum_pedersen::{chaum_ped_statement, prove_chaum_ped, verify_chaum_ped},
        dlog::{dlog_statement, prove_dlog, verify_dlog},
        okamoto::{okamoto_statement, prove_okamoto, verify_okamoto},
        schnorr::{prove_schnorr, schnorr_statement, verify_schnorr},
    },
    pedersen::{
        commit_default_bases, pedersen_eq_statement_with_bases,
        pedersen_rerand_statement_with_base, pedersen_statement_with_bases, prove_pedersen_eq,
        prove_pedersen_opening, prove_pedersen_rerand, verify_pedersen_eq, verify_pedersen_opening,
        verify_pedersen_rerand,
    },
};
use rigel_prover::protocols::types::{
    PedersenRerandProof, PedersenRerandStatement, SigmaProof, SigmaStatement,
};

fn ctx(tag: u64) -> Vec<Felt> {
    vec![Felt::from(20260222u64), Felt::from(tag)]
}

fn rand_nonzero_scalar(rng: &mut ChaCha20Rng) -> Scalar {
    Scalar::random_nonzero(rng).expect("nonzero scalar")
}

#[test]
fn roundtrip_atomic_and_pedersen() {
    let mut rng = ChaCha20Rng::seed_from_u64(4201);

    let secret = rand_nonzero_scalar(&mut rng);
    let schnorr_stmt = schnorr_statement(&secret);
    let schnorr_proof = prove_schnorr(&schnorr_stmt, &secret, &ctx(1), &mut rng).unwrap();
    verify_schnorr(&schnorr_stmt, &schnorr_proof, &ctx(1)).unwrap();

    let base = mul(&generator(), &rand_nonzero_scalar(&mut rng));
    let dlog_secret = rand_nonzero_scalar(&mut rng);
    let dlog_stmt = dlog_statement(&base, &dlog_secret);
    let dlog_proof = prove_dlog(&dlog_stmt, &dlog_secret, &ctx(2), &mut rng).unwrap();
    verify_dlog(&dlog_stmt, &dlog_proof, &ctx(2)).unwrap();

    let h = mul(&generator(), &rand_nonzero_scalar(&mut rng));
    let cp_secret = rand_nonzero_scalar(&mut rng);
    let cp_stmt = chaum_ped_statement(&h, &cp_secret);
    let cp_proof = prove_chaum_ped(&cp_stmt, &cp_secret, &ctx(3), &mut rng).unwrap();
    verify_chaum_ped(&cp_stmt, &cp_proof, &ctx(3)).unwrap();

    let ok_bases = vec![
        mul(&generator(), &rand_nonzero_scalar(&mut rng)),
        mul(&generator(), &rand_nonzero_scalar(&mut rng)),
    ];
    let ok_secrets = vec![rand_nonzero_scalar(&mut rng), rand_nonzero_scalar(&mut rng)];
    let ok_stmt = okamoto_statement(&ok_bases, &ok_secrets).unwrap();
    let ok_proof = prove_okamoto(&ok_stmt, &ok_secrets, &ctx(4), &mut rng).unwrap();
    verify_okamoto(&ok_stmt, &ok_proof, &ctx(4)).unwrap();

    let g = generator();
    let ped_h = pedersen_h();

    let value = rand_nonzero_scalar(&mut rng);
    let blind = rand_nonzero_scalar(&mut rng);
    let ped_stmt = pedersen_statement_with_bases(&g, &ped_h, &value, &blind);
    let ped_proof = prove_pedersen_opening(&ped_stmt, &value, &blind, &ctx(5), &mut rng).unwrap();
    verify_pedersen_opening(&ped_stmt, &ped_proof, &ctx(5)).unwrap();

    let eq_value = rand_nonzero_scalar(&mut rng);
    let blind1 = rand_nonzero_scalar(&mut rng);
    let blind2 = rand_nonzero_scalar(&mut rng);
    let eq_stmt =
        pedersen_eq_statement_with_bases(&g, &ped_h, &g, &ped_h, &eq_value, &blind1, &blind2);
    let eq_proof =
        prove_pedersen_eq(&eq_stmt, &eq_value, &blind1, &blind2, &ctx(6), &mut rng).unwrap();
    verify_pedersen_eq(&eq_stmt, &eq_proof, &ctx(6)).unwrap();

    let from_value = rand_nonzero_scalar(&mut rng);
    let from_blind = rand_nonzero_scalar(&mut rng);
    let commitment_from = commit_default_bases(&from_value, &from_blind);
    let rerand = rand_nonzero_scalar(&mut rng);
    let rerand_stmt = pedersen_rerand_statement_with_base(&ped_h, &commitment_from, &rerand);
    let rerand_proof = prove_pedersen_rerand(&rerand_stmt, &rerand, &ctx(7), &mut rng).unwrap();
    verify_pedersen_rerand(&rerand_stmt, &rerand_proof, &ctx(7)).unwrap();
}

#[test]
fn roundtrip_ring_and_one_out_of_many() {
    let mut rng = ChaCha20Rng::seed_from_u64(4202);

    let ring_secret = rand_nonzero_scalar(&mut rng);
    let ring_stmt = RingStatement {
        public_keys: vec![
            mul(&generator(), &rand_nonzero_scalar(&mut rng)),
            mul(&generator(), &ring_secret),
            mul(&generator(), &rand_nonzero_scalar(&mut rng)),
        ],
    };
    let ring_proof = prove_ring(&ring_stmt, 1, &ring_secret, &ctx(8), &mut rng).unwrap();
    verify_ring(&ring_stmt, &ring_proof, &ctx(8)).unwrap();

    let value = Scalar::from_u64(11);
    let blind_commitment = rand_nonzero_scalar(&mut rng);
    let blind_real = rand_nonzero_scalar(&mut rng);
    let commitment = commit_default_bases(&value, &blind_commitment);
    let candidates = vec![
        commit_default_bases(&Scalar::from_u64(1), &rand_nonzero_scalar(&mut rng)),
        commit_default_bases(&Scalar::from_u64(7), &rand_nonzero_scalar(&mut rng)),
        commit_default_bases(&value, &blind_real),
        commit_default_bases(&Scalar::from_u64(21), &rand_nonzero_scalar(&mut rng)),
    ];
    let stmt = PedersenOneOutOfManyStatement {
        commitment,
        candidates,
    };
    let proof = prove_pedersen_one_out_of_many(
        &stmt,
        2,
        &value,
        &blind_commitment,
        &blind_real,
        &ctx(9),
        &mut rng,
    )
    .unwrap();
    verify_pedersen_one_out_of_many(&stmt, &proof, &ctx(9)).unwrap();
}

#[test]
fn ring_rejects_invalid_witness() {
    let mut rng = ChaCha20Rng::seed_from_u64(4203);
    let secret = rand_nonzero_scalar(&mut rng);
    let wrong_secret = rand_nonzero_scalar(&mut rng);
    let stmt = RingStatement {
        public_keys: vec![
            mul(&generator(), &secret),
            mul(&generator(), &rand_nonzero_scalar(&mut rng)),
        ],
    };
    assert!(prove_ring(&stmt, 0, &wrong_secret, &ctx(10), &mut rng).is_err());
}

#[test]
fn derive_challenge_rejects_invalid_rerand_statement() {
    let rerand_base = pedersen_h();
    let commitment = mul(&generator(), &Scalar::from_u64(17));
    let nonce_commitment = mul(&rerand_base, &Scalar::from_u64(9));

    let stmt = SigmaStatement::PedersenRerand(PedersenRerandStatement {
        rerand_base: rerand_base.clone(),
        commitment_from: commitment.clone(),
        commitment_to: commitment,
    });
    let proof = SigmaProof::PedersenRerand(PedersenRerandProof {
        nonce_commitment,
        response: Scalar::from_u64(5),
    });

    let err = derive_challenge(&stmt, &proof, &ctx(15)).expect_err("invalid statement must fail");
    assert!(matches!(err, ProverError::InvalidStatement));
}

#[test]
fn one_out_of_many_rejects_non_power_of_two_candidate_sets() {
    let mut rng = ChaCha20Rng::seed_from_u64(4204);
    let value = Scalar::from_u64(19);
    let blind_commitment = rand_nonzero_scalar(&mut rng);
    let blind_real = rand_nonzero_scalar(&mut rng);

    let commitment = commit_default_bases(&value, &blind_commitment);
    let candidates = vec![
        commit_default_bases(&Scalar::from_u64(1), &rand_nonzero_scalar(&mut rng)),
        commit_default_bases(&Scalar::from_u64(7), &rand_nonzero_scalar(&mut rng)),
        commit_default_bases(&value, &blind_real),
    ];
    let stmt = PedersenOneOutOfManyStatement {
        commitment,
        candidates,
    };
    let prove_result = prove_pedersen_one_out_of_many(
        &stmt,
        2,
        &value,
        &blind_commitment,
        &blind_real,
        &ctx(11),
        &mut rng,
    );
    assert!(matches!(
        prove_result,
        Err(ProverError::RingSizeMustBePowerOfTwo)
    ));

    let empty_proof = rigel_prover::advanced::one_out_of_many::PedersenOneOutOfManyProof {
        cl: vec![],
        ca: vec![],
        cb: vec![],
        cd: vec![],
        f: vec![],
        za: vec![],
        zb: vec![],
        zd: Scalar::from_u64(0),
    };
    let verify_result = verify_pedersen_one_out_of_many(&stmt, &empty_proof, &ctx(11));
    assert!(matches!(
        verify_result,
        Err(ProverError::RingSizeMustBePowerOfTwo)
    ));
}

#[test]
fn one_out_of_many_supports_single_candidate_sets() {
    let mut rng = ChaCha20Rng::seed_from_u64(4207);
    let value = Scalar::from_u64(29);
    let blind_commitment = rand_nonzero_scalar(&mut rng);
    let blind_real = rand_nonzero_scalar(&mut rng);

    let commitment = commit_default_bases(&value, &blind_commitment);
    let stmt = PedersenOneOutOfManyStatement {
        commitment,
        candidates: vec![commit_default_bases(&value, &blind_real)],
    };

    let proof = prove_pedersen_one_out_of_many(
        &stmt,
        0,
        &value,
        &blind_commitment,
        &blind_real,
        &ctx(14),
        &mut rng,
    )
    .unwrap();

    assert!(proof.cl.is_empty());
    assert!(proof.ca.is_empty());
    assert!(proof.cb.is_empty());
    assert!(proof.cd.is_empty());
    assert!(proof.f.is_empty());
    assert!(proof.za.is_empty());
    assert!(proof.zb.is_empty());
    verify_pedersen_one_out_of_many(&stmt, &proof, &ctx(14)).unwrap();

    let mut tampered = proof.clone();
    tampered.zd = tampered.zd.add_mod(&Scalar::from_u64(1));
    assert!(verify_pedersen_one_out_of_many(&stmt, &tampered, &ctx(14)).is_err());
}

#[test]
fn one_out_of_many_rejects_invalid_witness() {
    let mut rng = ChaCha20Rng::seed_from_u64(4205);
    let value = Scalar::from_u64(9);
    let blind_commitment = rand_nonzero_scalar(&mut rng);
    let blind_real = rand_nonzero_scalar(&mut rng);
    let wrong_blind = rand_nonzero_scalar(&mut rng);
    let commitment = commit_default_bases(&value, &blind_commitment);

    let stmt = PedersenOneOutOfManyStatement {
        commitment,
        candidates: vec![
            commit_default_bases(&Scalar::from_u64(3), &rand_nonzero_scalar(&mut rng)),
            commit_default_bases(&value, &blind_real),
            commit_default_bases(&Scalar::from_u64(15), &rand_nonzero_scalar(&mut rng)),
            commit_default_bases(&Scalar::from_u64(29), &rand_nonzero_scalar(&mut rng)),
        ],
    };

    assert!(
        prove_pedersen_one_out_of_many(
            &stmt,
            1,
            &value,
            &blind_commitment,
            &wrong_blind,
            &ctx(12),
            &mut rng,
        )
        .is_err()
    );
}

#[test]
fn one_out_of_many_rejects_tampered_proof_and_malformed_shape() {
    let mut rng = ChaCha20Rng::seed_from_u64(4206);
    let value = Scalar::from_u64(13);
    let blind_commitment = rand_nonzero_scalar(&mut rng);
    let blind_real = rand_nonzero_scalar(&mut rng);
    let commitment = commit_default_bases(&value, &blind_commitment);
    let stmt = PedersenOneOutOfManyStatement {
        commitment,
        candidates: vec![
            commit_default_bases(&Scalar::from_u64(2), &rand_nonzero_scalar(&mut rng)),
            commit_default_bases(&value, &blind_real),
            commit_default_bases(&Scalar::from_u64(27), &rand_nonzero_scalar(&mut rng)),
            commit_default_bases(&Scalar::from_u64(35), &rand_nonzero_scalar(&mut rng)),
        ],
    };

    let proof = prove_pedersen_one_out_of_many(
        &stmt,
        1,
        &value,
        &blind_commitment,
        &blind_real,
        &ctx(13),
        &mut rng,
    )
    .unwrap();

    let mut tampered = proof.clone();
    tampered.f[0] = tampered.f[0].add_mod(&Scalar::from_u64(1));
    assert!(verify_pedersen_one_out_of_many(&stmt, &tampered, &ctx(13)).is_err());

    let mut malformed = proof.clone();
    malformed.cd.pop();
    assert!(verify_pedersen_one_out_of_many(&stmt, &malformed, &ctx(13)).is_err());
}

#[test]
fn one_out_of_many_large_power_of_two_roundtrip() {
    for (case_idx, n) in [8usize, 16, 32, 64].iter().enumerate() {
        let mut rng = ChaCha20Rng::seed_from_u64(4300 + *n as u64);
        let value = Scalar::from_u64(37 + case_idx as u64);
        let blind_commitment = rand_nonzero_scalar(&mut rng);
        let blind_real = rand_nonzero_scalar(&mut rng);
        let commitment = commit_default_bases(&value, &blind_commitment);
        let real_index = *n / 2;

        let mut candidates = Vec::with_capacity(*n);
        for i in 0..*n {
            if i == real_index {
                candidates.push(commit_default_bases(&value, &blind_real));
            } else {
                candidates.push(commit_default_bases(
                    &Scalar::from_u64(i as u64 + 1),
                    &rand_nonzero_scalar(&mut rng),
                ));
            }
        }

        let stmt = PedersenOneOutOfManyStatement {
            commitment,
            candidates,
        };
        let proof = prove_pedersen_one_out_of_many(
            &stmt,
            real_index,
            &value,
            &blind_commitment,
            &blind_real,
            &ctx(100 + case_idx as u64),
            &mut rng,
        )
        .unwrap();

        let expected_bits = n.trailing_zeros() as usize;
        assert_eq!(proof.cl.len(), expected_bits);
        assert_eq!(proof.ca.len(), expected_bits);
        assert_eq!(proof.cb.len(), expected_bits);
        assert_eq!(proof.cd.len(), expected_bits);
        assert_eq!(proof.f.len(), expected_bits);
        assert_eq!(proof.za.len(), expected_bits);
        assert_eq!(proof.zb.len(), expected_bits);

        verify_pedersen_one_out_of_many(&stmt, &proof, &ctx(100 + case_idx as u64)).unwrap();
    }
}

#[test]
fn one_out_of_many_n64_rejects_tampered_scalar() {
    let mut rng = ChaCha20Rng::seed_from_u64(4301);
    let n = 64usize;
    let value = Scalar::from_u64(51);
    let blind_commitment = rand_nonzero_scalar(&mut rng);
    let blind_real = rand_nonzero_scalar(&mut rng);
    let commitment = commit_default_bases(&value, &blind_commitment);
    let real_index = 23usize;

    let mut candidates = Vec::with_capacity(n);
    for i in 0..n {
        if i == real_index {
            candidates.push(commit_default_bases(&value, &blind_real));
        } else {
            candidates.push(commit_default_bases(
                &Scalar::from_u64(i as u64 + 1),
                &rand_nonzero_scalar(&mut rng),
            ));
        }
    }
    let stmt = PedersenOneOutOfManyStatement {
        commitment,
        candidates,
    };
    let proof = prove_pedersen_one_out_of_many(
        &stmt,
        real_index,
        &value,
        &blind_commitment,
        &blind_real,
        &ctx(104),
        &mut rng,
    )
    .unwrap();

    let mut tampered = proof.clone();
    tampered.za[0] = tampered.za[0].add_mod(&Scalar::from_u64(1));
    assert!(verify_pedersen_one_out_of_many(&stmt, &tampered, &ctx(104)).is_err());
}

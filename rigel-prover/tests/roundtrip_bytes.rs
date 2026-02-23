use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use starknet_crypto::Felt;

use rigel_prover::advanced::one_out_of_many::{
    PedersenOneOutOfManyStatement, prove_pedersen_one_out_of_many,
};
use rigel_prover::core::bytes::{
    POINT_BYTES, SCALAR_BYTES, decode_point_be64, decode_points_be64, decode_scalar_be32,
    decode_scalars_be32, encode_chaum_ped_proof_bytes, encode_dlog_proof_bytes,
    encode_one_out_of_many_proof_bytes, encode_pedersen_eq_proof_bytes,
    encode_pedersen_proof_bytes, encode_pedersen_rerand_proof_bytes, encode_point_be64,
    encode_scalar_be32, encode_schnorr_proof_bytes,
};
use rigel_prover::core::curve::{generator, mul};
use rigel_prover::core::decode::decode_one_out_of_many_proof;
use rigel_prover::core::errors::ProverError;
use rigel_prover::core::scalar::Scalar;
use rigel_prover::protocols::{
    atomic::{
        chaum_pedersen::{chaum_ped_statement, prove_chaum_ped},
        dlog::{dlog_statement, prove_dlog},
        schnorr::{prove_schnorr, schnorr_statement},
    },
    pedersen::{
        commit_default_bases, pedersen_eq_statement_with_bases,
        pedersen_rerand_statement_with_base, pedersen_statement_with_bases, prove_pedersen_eq,
        prove_pedersen_opening, prove_pedersen_rerand,
    },
};

fn ctx(tag: u64) -> Vec<Felt> {
    vec![Felt::from(20260222u64), Felt::from(tag)]
}

fn rand_nonzero_scalar(rng: &mut ChaCha20Rng) -> Scalar {
    Scalar::random_nonzero(rng).expect("nonzero scalar")
}

#[test]
fn scalar_and_point_byte_roundtrip() {
    let mut rng = ChaCha20Rng::seed_from_u64(5201);
    let s = rand_nonzero_scalar(&mut rng);
    let p = mul(&generator(), &s);

    let sb = encode_scalar_be32(&s).unwrap();
    let pb = encode_point_be64(&p).unwrap();

    assert_eq!(decode_scalar_be32(&sb).unwrap(), s);
    assert_eq!(decode_point_be64(&pb).unwrap(), p);
}

#[test]
fn proof_byte_roundtrip_core_protocols() {
    let mut rng = ChaCha20Rng::seed_from_u64(5202);

    let secret = rand_nonzero_scalar(&mut rng);
    let schnorr_stmt = schnorr_statement(&secret);
    let schnorr_proof = prove_schnorr(&schnorr_stmt, &secret, &ctx(1), &mut rng).unwrap();
    let schnorr_bytes = encode_schnorr_proof_bytes(&schnorr_proof).unwrap();
    assert_eq!(
        decode_point_be64(&schnorr_bytes[..POINT_BYTES]).unwrap(),
        schnorr_proof.commitment
    );
    assert_eq!(
        decode_scalar_be32(&schnorr_bytes[POINT_BYTES..POINT_BYTES + SCALAR_BYTES]).unwrap(),
        schnorr_proof.response
    );

    let base = mul(&generator(), &rand_nonzero_scalar(&mut rng));
    let dlog_secret = rand_nonzero_scalar(&mut rng);
    let dlog_stmt = dlog_statement(&base, &dlog_secret);
    let dlog_proof = prove_dlog(&dlog_stmt, &dlog_secret, &ctx(2), &mut rng).unwrap();
    let dlog_bytes = encode_dlog_proof_bytes(&dlog_proof).unwrap();
    assert_eq!(
        decode_point_be64(&dlog_bytes[..POINT_BYTES]).unwrap(),
        dlog_proof.commitment
    );
    assert_eq!(
        decode_scalar_be32(&dlog_bytes[POINT_BYTES..POINT_BYTES + SCALAR_BYTES]).unwrap(),
        dlog_proof.response
    );

    let h = mul(&generator(), &rand_nonzero_scalar(&mut rng));
    let cp_secret = rand_nonzero_scalar(&mut rng);
    let cp_stmt = chaum_ped_statement(&h, &cp_secret);
    let cp_proof = prove_chaum_ped(&cp_stmt, &cp_secret, &ctx(3), &mut rng).unwrap();
    let cp_bytes = encode_chaum_ped_proof_bytes(&cp_proof).unwrap();
    assert_eq!(
        decode_point_be64(&cp_bytes[..POINT_BYTES]).unwrap(),
        cp_proof.r1
    );
    assert_eq!(
        decode_point_be64(&cp_bytes[POINT_BYTES..POINT_BYTES * 2]).unwrap(),
        cp_proof.r2
    );
    assert_eq!(
        decode_scalar_be32(&cp_bytes[POINT_BYTES * 2..POINT_BYTES * 2 + SCALAR_BYTES]).unwrap(),
        cp_proof.response
    );
}

#[test]
fn proof_byte_roundtrip_pedersen_family_and_oom() {
    let mut rng = ChaCha20Rng::seed_from_u64(5203);
    let g = generator();
    let h = mul(&generator(), &rand_nonzero_scalar(&mut rng));

    let value = rand_nonzero_scalar(&mut rng);
    let blind = rand_nonzero_scalar(&mut rng);
    let ped_stmt = pedersen_statement_with_bases(&g, &h, &value, &blind);
    let ped_proof = prove_pedersen_opening(&ped_stmt, &value, &blind, &ctx(4), &mut rng).unwrap();
    let ped_bytes = encode_pedersen_proof_bytes(&ped_proof).unwrap();
    assert_eq!(ped_bytes.len(), POINT_BYTES + SCALAR_BYTES * 2);

    let eq_value = rand_nonzero_scalar(&mut rng);
    let blind1 = rand_nonzero_scalar(&mut rng);
    let blind2 = rand_nonzero_scalar(&mut rng);
    let eq_stmt = pedersen_eq_statement_with_bases(&g, &h, &g, &h, &eq_value, &blind1, &blind2);
    let eq_proof =
        prove_pedersen_eq(&eq_stmt, &eq_value, &blind1, &blind2, &ctx(5), &mut rng).unwrap();
    let eq_bytes = encode_pedersen_eq_proof_bytes(&eq_proof).unwrap();
    assert_eq!(eq_bytes.len(), POINT_BYTES * 2 + SCALAR_BYTES * 3);

    let from_value = rand_nonzero_scalar(&mut rng);
    let from_blind = rand_nonzero_scalar(&mut rng);
    let commitment_from = commit_default_bases(&from_value, &from_blind);
    let rerand = rand_nonzero_scalar(&mut rng);
    let rerand_stmt = pedersen_rerand_statement_with_base(&h, &commitment_from, &rerand);
    let rerand_proof = prove_pedersen_rerand(&rerand_stmt, &rerand, &ctx(6), &mut rng).unwrap();
    let rerand_bytes = encode_pedersen_rerand_proof_bytes(&rerand_proof).unwrap();
    assert_eq!(rerand_bytes.len(), POINT_BYTES + SCALAR_BYTES);

    let oo_value = Scalar::from_u64(5);
    let blind_commitment = rand_nonzero_scalar(&mut rng);
    let blind_real = rand_nonzero_scalar(&mut rng);
    let commitment = commit_default_bases(&oo_value, &blind_commitment);
    let stmt = PedersenOneOutOfManyStatement {
        commitment,
        candidates: vec![
            commit_default_bases(&Scalar::from_u64(1), &rand_nonzero_scalar(&mut rng)),
            commit_default_bases(&Scalar::from_u64(3), &rand_nonzero_scalar(&mut rng)),
            commit_default_bases(&oo_value, &blind_real),
            commit_default_bases(&Scalar::from_u64(9), &rand_nonzero_scalar(&mut rng)),
        ],
    };
    let proof = prove_pedersen_one_out_of_many(
        &stmt,
        2,
        &oo_value,
        &blind_commitment,
        &blind_real,
        &ctx(7),
        &mut rng,
    )
    .unwrap();
    let (commitments_bytes, scalars_bytes) = encode_one_out_of_many_proof_bytes(&proof).unwrap();

    let parsed_scalars = decode_scalars_be32(&scalars_bytes).unwrap();
    let mut expected_scalars = Vec::new();
    expected_scalars.extend_from_slice(&proof.f);
    expected_scalars.extend_from_slice(&proof.za);
    expected_scalars.extend_from_slice(&proof.zb);
    expected_scalars.push(proof.zd.clone());
    assert_eq!(parsed_scalars, expected_scalars);

    let parsed_points = decode_points_be64(&commitments_bytes).unwrap();
    let expected_points_len = proof.cl.len() + proof.ca.len() + proof.cb.len() + proof.cd.len();
    assert_eq!(parsed_points.len(), expected_points_len);
}

#[test]
fn one_out_of_many_n1_byte_encoding_shape() {
    let mut rng = ChaCha20Rng::seed_from_u64(5204);
    let value = Scalar::from_u64(17);
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
        &ctx(8),
        &mut rng,
    )
    .unwrap();

    let (commitments_bytes, scalars_bytes) = encode_one_out_of_many_proof_bytes(&proof).unwrap();
    assert!(commitments_bytes.is_empty());
    assert_eq!(scalars_bytes.len(), SCALAR_BYTES);
    assert_eq!(
        decode_scalars_be32(&scalars_bytes).unwrap(),
        vec![proof.zd.clone()]
    );
}

#[test]
fn decode_one_out_of_many_proof_rejects_oversized_bit_length_tag() {
    let encoded = vec![Felt::from(7u64)];
    let err = decode_one_out_of_many_proof(&encoded).unwrap_err();
    assert!(matches!(err, ProverError::InvalidStatement));
}

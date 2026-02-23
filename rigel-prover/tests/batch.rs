use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use starknet_crypto::Felt;

use rigel_prover::composition::batch::{
    batch_verify_chaum_ped, batch_verify_dlog, batch_verify_okamoto, batch_verify_pedersen,
    batch_verify_pedersen_eq, batch_verify_pedersen_rerand,
};
use rigel_prover::core::curve::{generator, mul, pedersen_h};
use rigel_prover::core::scalar::Scalar;
use rigel_prover::protocols::{
    atomic::{
        chaum_pedersen::{chaum_ped_statement, prove_chaum_ped},
        dlog::{dlog_statement, prove_dlog},
        okamoto::{okamoto_statement, prove_okamoto},
    },
    pedersen::{
        commit_default_bases, pedersen_eq_statement_with_bases,
        pedersen_rerand_statement_with_base, pedersen_statement_with_bases, prove_pedersen_eq,
        prove_pedersen_opening, prove_pedersen_rerand,
    },
};

fn scalar(v: u64) -> Scalar {
    Scalar::from_u64(v)
}

fn ctx(tag: u64) -> Vec<Felt> {
    vec![Felt::from(20260212u64), Felt::from(tag)]
}

fn g_mul(v: u64) -> rigel_prover::core::curve::Point {
    let g = generator();
    mul(&g, &scalar(v))
}

#[test]
fn batch_dlog_two_proofs_and_corruption() {
    let ctx = ctx(1);

    let base1 = g_mul(2);
    let secret1 = scalar(7);
    let stmt1 = dlog_statement(&base1, &secret1);
    let mut rng1 = ChaCha20Rng::seed_from_u64(1001);
    let proof1 = prove_dlog(&stmt1, &secret1, &ctx, &mut rng1).unwrap();

    let base2 = g_mul(5);
    let secret2 = scalar(11);
    let stmt2 = dlog_statement(&base2, &secret2);
    let mut rng2 = ChaCha20Rng::seed_from_u64(1002);
    let proof2 = prove_dlog(&stmt2, &secret2, &ctx, &mut rng2).unwrap();

    let statements = vec![stmt1.clone(), stmt2.clone()];
    let proofs = vec![proof1.clone(), proof2.clone()];
    assert!(batch_verify_dlog(&statements, &proofs, &ctx).is_ok());

    let mut bad_proofs = proofs;
    bad_proofs[0].response = bad_proofs[0].response.add_mod(&scalar(1));
    assert!(batch_verify_dlog(&statements, &bad_proofs, &ctx).is_err());
}

#[test]
fn batch_chaum_ped_two_proofs_and_corruption() {
    let ctx = ctx(2);

    let h1 = g_mul(3);
    let secret1 = scalar(5);
    let stmt1 = chaum_ped_statement(&h1, &secret1);
    let mut rng1 = ChaCha20Rng::seed_from_u64(2001);
    let proof1 = prove_chaum_ped(&stmt1, &secret1, &ctx, &mut rng1).unwrap();

    let h2 = g_mul(9);
    let secret2 = scalar(11);
    let stmt2 = chaum_ped_statement(&h2, &secret2);
    let mut rng2 = ChaCha20Rng::seed_from_u64(2002);
    let proof2 = prove_chaum_ped(&stmt2, &secret2, &ctx, &mut rng2).unwrap();

    let statements = vec![stmt1.clone(), stmt2.clone()];
    let proofs = vec![proof1.clone(), proof2.clone()];
    assert!(batch_verify_chaum_ped(&statements, &proofs, &ctx).is_ok());

    let mut bad_proofs = proofs;
    bad_proofs[0].response = bad_proofs[0].response.add_mod(&scalar(1));
    assert!(batch_verify_chaum_ped(&statements, &bad_proofs, &ctx).is_err());
}

#[test]
fn batch_okamoto_two_proofs_and_corruption() {
    let ctx = ctx(3);

    let bases1 = vec![g_mul(2), g_mul(5)];
    let secrets1 = vec![scalar(7), scalar(11)];
    let stmt1 = okamoto_statement(&bases1, &secrets1).unwrap();
    let mut rng1 = ChaCha20Rng::seed_from_u64(3001);
    let proof1 = prove_okamoto(&stmt1, &secrets1, &ctx, &mut rng1).unwrap();

    let bases2 = vec![g_mul(6), g_mul(10)];
    let secrets2 = vec![scalar(13), scalar(17)];
    let stmt2 = okamoto_statement(&bases2, &secrets2).unwrap();
    let mut rng2 = ChaCha20Rng::seed_from_u64(3002);
    let proof2 = prove_okamoto(&stmt2, &secrets2, &ctx, &mut rng2).unwrap();

    let statements = vec![stmt1.clone(), stmt2.clone()];
    let proofs = vec![proof1.clone(), proof2.clone()];
    assert!(batch_verify_okamoto(&statements, &proofs, &ctx).is_ok());

    let mut bad_proofs = proofs;
    bad_proofs[0].responses[0] = bad_proofs[0].responses[0].add_mod(&scalar(1));
    assert!(batch_verify_okamoto(&statements, &bad_proofs, &ctx).is_err());
}

#[test]
fn batch_pedersen_two_proofs_and_corruption() {
    let ctx = ctx(4);
    let g = generator();
    let h = pedersen_h();

    let value1 = scalar(21);
    let blind1 = scalar(34);
    let stmt1 = pedersen_statement_with_bases(&g, &h, &value1, &blind1);
    let mut rng1 = ChaCha20Rng::seed_from_u64(4001);
    let proof1 = prove_pedersen_opening(&stmt1, &value1, &blind1, &ctx, &mut rng1).unwrap();

    let value2 = scalar(55);
    let blind2 = scalar(89);
    let stmt2 = pedersen_statement_with_bases(&g, &h, &value2, &blind2);
    let mut rng2 = ChaCha20Rng::seed_from_u64(4002);
    let proof2 = prove_pedersen_opening(&stmt2, &value2, &blind2, &ctx, &mut rng2).unwrap();

    let statements = vec![stmt1.clone(), stmt2.clone()];
    let proofs = vec![proof1.clone(), proof2.clone()];
    assert!(batch_verify_pedersen(&statements, &proofs, &ctx).is_ok());

    let mut bad_proofs = proofs;
    bad_proofs[0].response_value = bad_proofs[0].response_value.add_mod(&scalar(1));
    assert!(batch_verify_pedersen(&statements, &bad_proofs, &ctx).is_err());
}

#[test]
fn batch_pedersen_eq_two_proofs_and_corruption() {
    let ctx = ctx(5);
    let g = generator();
    let h = pedersen_h();

    let value1 = scalar(7);
    let blind1a = scalar(11);
    let blind1b = scalar(13);
    let stmt1 = pedersen_eq_statement_with_bases(&g, &h, &g, &h, &value1, &blind1a, &blind1b);
    let mut rng1 = ChaCha20Rng::seed_from_u64(5001);
    let proof1 = prove_pedersen_eq(&stmt1, &value1, &blind1a, &blind1b, &ctx, &mut rng1).unwrap();

    let value2 = scalar(19);
    let blind2a = scalar(23);
    let blind2b = scalar(29);
    let stmt2 = pedersen_eq_statement_with_bases(&g, &h, &g, &h, &value2, &blind2a, &blind2b);
    let mut rng2 = ChaCha20Rng::seed_from_u64(5002);
    let proof2 = prove_pedersen_eq(&stmt2, &value2, &blind2a, &blind2b, &ctx, &mut rng2).unwrap();

    let statements = vec![stmt1.clone(), stmt2.clone()];
    let proofs = vec![proof1.clone(), proof2.clone()];
    assert!(batch_verify_pedersen_eq(&statements, &proofs, &ctx).is_ok());

    let mut bad_proofs = proofs;
    bad_proofs[0].response_value = bad_proofs[0].response_value.add_mod(&scalar(1));
    assert!(batch_verify_pedersen_eq(&statements, &bad_proofs, &ctx).is_err());
}

#[test]
fn batch_pedersen_rerand_two_proofs_and_corruption() {
    let ctx = ctx(6);
    let h = pedersen_h();

    let value1 = scalar(5);
    let blind1 = scalar(9);
    let commitment_from1 = commit_default_bases(&value1, &blind1);
    let rerand1 = scalar(7);
    let stmt1 = pedersen_rerand_statement_with_base(&h, &commitment_from1, &rerand1);
    let mut rng1 = ChaCha20Rng::seed_from_u64(6001);
    let proof1 = prove_pedersen_rerand(&stmt1, &rerand1, &ctx, &mut rng1).unwrap();

    let value2 = scalar(12);
    let blind2 = scalar(17);
    let commitment_from2 = commit_default_bases(&value2, &blind2);
    let rerand2 = scalar(19);
    let stmt2 = pedersen_rerand_statement_with_base(&h, &commitment_from2, &rerand2);
    let mut rng2 = ChaCha20Rng::seed_from_u64(6002);
    let proof2 = prove_pedersen_rerand(&stmt2, &rerand2, &ctx, &mut rng2).unwrap();

    let statements = vec![stmt1.clone(), stmt2.clone()];
    let proofs = vec![proof1.clone(), proof2.clone()];
    assert!(batch_verify_pedersen_rerand(&statements, &proofs, &ctx).is_ok());

    let mut bad_proofs = proofs;
    bad_proofs[0].response = bad_proofs[0].response.add_mod(&scalar(1));
    assert!(batch_verify_pedersen_rerand(&statements, &bad_proofs, &ctx).is_err());
}

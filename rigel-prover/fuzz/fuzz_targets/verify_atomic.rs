#![no_main]

use arbitrary::Unstructured;
use libfuzzer_sys::fuzz_target;
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
use rigel_prover::core::curve::{generator, mul, pedersen_h, Point};
use rigel_prover::core::scalar::Scalar;
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

fn nonzero_scalar(v: u64) -> Scalar {
    let s = Scalar::from_u64(v);
    if s.is_zero() {
        Scalar::from_u64(1)
    } else {
        s
    }
}

fn rand_point(v: u64) -> Point {
    let g = generator();
    mul(&g, &nonzero_scalar(v))
}

fn ctx(u: &mut Unstructured<'_>, tag: u64) -> Option<Vec<Felt>> {
    let len = u.arbitrary::<u8>().ok()? % 4;
    let mut out = Vec::with_capacity(len as usize + 2);
    out.push(Felt::from(20260212u64));
    out.push(Felt::from(tag));
    for _ in 0..len {
        let v = u.arbitrary::<u64>().ok()?;
        out.push(Felt::from(v));
    }
    Some(out)
}

fn run_once(data: &[u8]) -> Option<()> {
    if data.len() < 33 {
        return None;
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&data[..32]);
    let mut rng = ChaCha20Rng::from_seed(seed);
    let mut u = Unstructured::new(&data[32..]);

    let tag = u.arbitrary::<u8>().ok()? % 9;

    match tag {
        0 => {
            let secret = nonzero_scalar(u.arbitrary::<u64>().ok()?);
            let ctx = ctx(&mut u, 1)?;
            let stmt = schnorr_statement(&secret);
            let proof = prove_schnorr(&stmt, &secret, &ctx, &mut rng).ok()?;
            let _ = verify_schnorr(&stmt, &proof, &ctx);

            let mut bad = proof.clone();
            bad.response = bad.response.add_mod(&Scalar::from_u64(1));
            assert!(verify_schnorr(&stmt, &bad, &ctx).is_err());
        }
        1 => {
            let base = rand_point(u.arbitrary::<u64>().ok()?);
            let secret = nonzero_scalar(u.arbitrary::<u64>().ok()?);
            let ctx = ctx(&mut u, 2)?;
            let stmt = dlog_statement(&base, &secret);
            let proof = prove_dlog(&stmt, &secret, &ctx, &mut rng).ok()?;
            let _ = verify_dlog(&stmt, &proof, &ctx);

            let mut bad = proof.clone();
            bad.response = bad.response.add_mod(&Scalar::from_u64(1));
            assert!(verify_dlog(&stmt, &bad, &ctx).is_err());
        }
        2 => {
            let h = rand_point(u.arbitrary::<u64>().ok()?);
            let secret = nonzero_scalar(u.arbitrary::<u64>().ok()?);
            let ctx = ctx(&mut u, 3)?;
            let stmt = chaum_ped_statement(&h, &secret);
            let proof = prove_chaum_ped(&stmt, &secret, &ctx, &mut rng).ok()?;
            let _ = verify_chaum_ped(&stmt, &proof, &ctx);

            let mut bad = proof.clone();
            bad.response = bad.response.add_mod(&Scalar::from_u64(1));
            assert!(verify_chaum_ped(&stmt, &bad, &ctx).is_err());
        }
        3 => {
            let n = (u.arbitrary::<u8>().ok()? % 3 + 2) as usize;
            let mut bases = Vec::with_capacity(n);
            let mut secrets = Vec::with_capacity(n);
            for _ in 0..n {
                bases.push(rand_point(u.arbitrary::<u64>().ok()?));
                secrets.push(nonzero_scalar(u.arbitrary::<u64>().ok()?));
            }
            let ctx = ctx(&mut u, 4)?;
            let stmt = okamoto_statement(&bases, &secrets).ok()?;
            let proof = prove_okamoto(&stmt, &secrets, &ctx, &mut rng).ok()?;
            let _ = verify_okamoto(&stmt, &proof, &ctx);

            let mut bad = proof.clone();
            bad.responses[0] = bad.responses[0].add_mod(&Scalar::from_u64(1));
            assert!(verify_okamoto(&stmt, &bad, &ctx).is_err());
        }
        4 => {
            let value = nonzero_scalar(u.arbitrary::<u64>().ok()?);
            let blinding = nonzero_scalar(u.arbitrary::<u64>().ok()?);
            let ctx = ctx(&mut u, 5)?;
            let g = generator();
            let h = pedersen_h();
            let stmt = pedersen_statement_with_bases(&g, &h, &value, &blinding);
            let proof = prove_pedersen_opening(&stmt, &value, &blinding, &ctx, &mut rng).ok()?;
            let _ = verify_pedersen_opening(&stmt, &proof, &ctx);

            let mut bad = proof.clone();
            bad.response_value = bad.response_value.add_mod(&Scalar::from_u64(1));
            assert!(verify_pedersen_opening(&stmt, &bad, &ctx).is_err());
        }
        5 => {
            let value = nonzero_scalar(u.arbitrary::<u64>().ok()?);
            let blinding1 = nonzero_scalar(u.arbitrary::<u64>().ok()?);
            let blinding2 = nonzero_scalar(u.arbitrary::<u64>().ok()?);
            let ctx = ctx(&mut u, 6)?;
            let g = generator();
            let h = pedersen_h();
            let stmt =
                pedersen_eq_statement_with_bases(&g, &h, &g, &h, &value, &blinding1, &blinding2);
            let proof =
                prove_pedersen_eq(&stmt, &value, &blinding1, &blinding2, &ctx, &mut rng).ok()?;
            let _ = verify_pedersen_eq(&stmt, &proof, &ctx);

            let mut bad = proof.clone();
            bad.response_value = bad.response_value.add_mod(&Scalar::from_u64(1));
            assert!(verify_pedersen_eq(&stmt, &bad, &ctx).is_err());
        }
        6 => {
            let value = nonzero_scalar(u.arbitrary::<u64>().ok()?);
            let blinding = nonzero_scalar(u.arbitrary::<u64>().ok()?);
            let commitment_from = commit_default_bases(&value, &blinding);
            let rerand = nonzero_scalar(u.arbitrary::<u64>().ok()?);
            let ctx = ctx(&mut u, 7)?;
            let h = pedersen_h();
            let stmt = pedersen_rerand_statement_with_base(&h, &commitment_from, &rerand);
            let proof = prove_pedersen_rerand(&stmt, &rerand, &ctx, &mut rng).ok()?;
            let _ = verify_pedersen_rerand(&stmt, &proof, &ctx);

            let mut bad = proof.clone();
            bad.response = bad.response.add_mod(&Scalar::from_u64(1));
            assert!(verify_pedersen_rerand(&stmt, &bad, &ctx).is_err());
        }
        7 => {
            let n = (u.arbitrary::<u8>().ok()? % 4 + 1) as usize;
            let real_index = (u.arbitrary::<u8>().ok()? as usize) % n;
            let secret = nonzero_scalar(u.arbitrary::<u64>().ok()?);
            let ctx = ctx(&mut u, 8)?;

            let mut public_keys = Vec::with_capacity(n);
            for i in 0..n {
                let s = if i == real_index {
                    secret.clone()
                } else {
                    nonzero_scalar(u.arbitrary::<u64>().ok()?)
                };
                public_keys.push(mul(&generator(), &s));
            }

            let stmt = RingStatement { public_keys };
            let proof = prove_ring(&stmt, real_index, &secret, &ctx, &mut rng).ok()?;
            let _ = verify_ring(&stmt, &proof, &ctx);

            let mut bad = proof.clone();
            bad.challenges[0] = bad.challenges[0].add_mod(&Scalar::from_u64(1));
            assert!(verify_ring(&stmt, &bad, &ctx).is_err());
        }
        _ => {
            let n = (u.arbitrary::<u8>().ok()? % 6 + 1) as usize;
            let real_index = (u.arbitrary::<u8>().ok()? as usize) % n;
            let value = nonzero_scalar(u.arbitrary::<u64>().ok()?);
            let blind_commitment = nonzero_scalar(u.arbitrary::<u64>().ok()?);
            let blind_real = nonzero_scalar(u.arbitrary::<u64>().ok()?);
            let ctx = ctx(&mut u, 9)?;

            let commitment = commit_default_bases(&value, &blind_commitment);
            let mut candidates = Vec::with_capacity(n);
            for i in 0..n {
                if i == real_index {
                    candidates.push(commit_default_bases(&value, &blind_real));
                } else {
                    let candidate_value = nonzero_scalar(u.arbitrary::<u64>().ok()?);
                    let candidate_blind = nonzero_scalar(u.arbitrary::<u64>().ok()?);
                    candidates.push(commit_default_bases(&candidate_value, &candidate_blind));
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
                &ctx,
                &mut rng,
            )
            .ok()?;
            let _ = verify_pedersen_one_out_of_many(&stmt, &proof, &ctx);

            let mut bad = proof.clone();
            bad.zd = bad.zd.add_mod(&Scalar::from_u64(1));
            assert!(verify_pedersen_one_out_of_many(&stmt, &bad, &ctx).is_err());
        }
    }
    Some(())
}

fuzz_target!(|data: &[u8]| {
    let _ = run_once(data);
});

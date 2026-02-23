#![no_main]

use arbitrary::Unstructured;
use libfuzzer_sys::fuzz_target;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use starknet_crypto::Felt;

use rigel_prover::composition::batch::{
    batch_verify_chaum_ped, batch_verify_dlog, batch_verify_okamoto, batch_verify_pedersen,
    batch_verify_pedersen_eq, batch_verify_pedersen_rerand,
};
use rigel_prover::core::curve::{generator, mul, pedersen_h, Point};
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

    let tag = u.arbitrary::<u8>().ok()? % 6;

    match tag {
        0 => {
            let ctx = ctx(&mut u, 10)?;
            let base1 = rand_point(u.arbitrary::<u64>().ok()?);
            let secret1 = nonzero_scalar(u.arbitrary::<u64>().ok()?);
            let stmt1 = dlog_statement(&base1, &secret1);
            let proof1 = prove_dlog(&stmt1, &secret1, &ctx, &mut rng).ok()?;

            let base2 = rand_point(u.arbitrary::<u64>().ok()?);
            let secret2 = nonzero_scalar(u.arbitrary::<u64>().ok()?);
            let stmt2 = dlog_statement(&base2, &secret2);
            let proof2 = prove_dlog(&stmt2, &secret2, &ctx, &mut rng).ok()?;

            let statements = vec![stmt1.clone(), stmt2.clone()];
            let proofs = vec![proof1.clone(), proof2.clone()];
            let _ = batch_verify_dlog(&statements, &proofs, &ctx);

            let mut bad = proofs;
            bad[0].response = bad[0].response.add_mod(&Scalar::from_u64(1));
            assert!(batch_verify_dlog(&statements, &bad, &ctx).is_err());
        }
        1 => {
            let ctx = ctx(&mut u, 11)?;
            let h1 = rand_point(u.arbitrary::<u64>().ok()?);
            let secret1 = nonzero_scalar(u.arbitrary::<u64>().ok()?);
            let stmt1 = chaum_ped_statement(&h1, &secret1);
            let proof1 = prove_chaum_ped(&stmt1, &secret1, &ctx, &mut rng).ok()?;

            let h2 = rand_point(u.arbitrary::<u64>().ok()?);
            let secret2 = nonzero_scalar(u.arbitrary::<u64>().ok()?);
            let stmt2 = chaum_ped_statement(&h2, &secret2);
            let proof2 = prove_chaum_ped(&stmt2, &secret2, &ctx, &mut rng).ok()?;

            let statements = vec![stmt1.clone(), stmt2.clone()];
            let proofs = vec![proof1.clone(), proof2.clone()];
            let _ = batch_verify_chaum_ped(&statements, &proofs, &ctx);

            let mut bad = proofs;
            bad[0].response = bad[0].response.add_mod(&Scalar::from_u64(1));
            assert!(batch_verify_chaum_ped(&statements, &bad, &ctx).is_err());
        }
        2 => {
            let ctx = ctx(&mut u, 12)?;
            let bases1 = vec![
                rand_point(u.arbitrary::<u64>().ok()?),
                rand_point(u.arbitrary::<u64>().ok()?),
            ];
            let secrets1 = vec![
                nonzero_scalar(u.arbitrary::<u64>().ok()?),
                nonzero_scalar(u.arbitrary::<u64>().ok()?),
            ];
            let stmt1 = okamoto_statement(&bases1, &secrets1).ok()?;
            let proof1 = prove_okamoto(&stmt1, &secrets1, &ctx, &mut rng).ok()?;

            let bases2 = vec![
                rand_point(u.arbitrary::<u64>().ok()?),
                rand_point(u.arbitrary::<u64>().ok()?),
            ];
            let secrets2 = vec![
                nonzero_scalar(u.arbitrary::<u64>().ok()?),
                nonzero_scalar(u.arbitrary::<u64>().ok()?),
            ];
            let stmt2 = okamoto_statement(&bases2, &secrets2).ok()?;
            let proof2 = prove_okamoto(&stmt2, &secrets2, &ctx, &mut rng).ok()?;

            let statements = vec![stmt1.clone(), stmt2.clone()];
            let proofs = vec![proof1.clone(), proof2.clone()];
            let _ = batch_verify_okamoto(&statements, &proofs, &ctx);

            let mut bad = proofs;
            bad[0].responses[0] = bad[0].responses[0].add_mod(&Scalar::from_u64(1));
            assert!(batch_verify_okamoto(&statements, &bad, &ctx).is_err());
        }
        3 => {
            let ctx = ctx(&mut u, 13)?;
            let g = generator();
            let h = pedersen_h();
            let value1 = nonzero_scalar(u.arbitrary::<u64>().ok()?);
            let blind1 = nonzero_scalar(u.arbitrary::<u64>().ok()?);
            let stmt1 = pedersen_statement_with_bases(&g, &h, &value1, &blind1);
            let proof1 = prove_pedersen_opening(&stmt1, &value1, &blind1, &ctx, &mut rng).ok()?;

            let value2 = nonzero_scalar(u.arbitrary::<u64>().ok()?);
            let blind2 = nonzero_scalar(u.arbitrary::<u64>().ok()?);
            let stmt2 = pedersen_statement_with_bases(&g, &h, &value2, &blind2);
            let proof2 = prove_pedersen_opening(&stmt2, &value2, &blind2, &ctx, &mut rng).ok()?;

            let statements = vec![stmt1.clone(), stmt2.clone()];
            let proofs = vec![proof1.clone(), proof2.clone()];
            let _ = batch_verify_pedersen(&statements, &proofs, &ctx);

            let mut bad = proofs;
            bad[0].response_value = bad[0].response_value.add_mod(&Scalar::from_u64(1));
            assert!(batch_verify_pedersen(&statements, &bad, &ctx).is_err());
        }
        4 => {
            let ctx = ctx(&mut u, 14)?;
            let g = generator();
            let h = pedersen_h();
            let value1 = nonzero_scalar(u.arbitrary::<u64>().ok()?);
            let blind1a = nonzero_scalar(u.arbitrary::<u64>().ok()?);
            let blind1b = nonzero_scalar(u.arbitrary::<u64>().ok()?);
            let stmt1 =
                pedersen_eq_statement_with_bases(&g, &h, &g, &h, &value1, &blind1a, &blind1b);
            let proof1 =
                prove_pedersen_eq(&stmt1, &value1, &blind1a, &blind1b, &ctx, &mut rng).ok()?;

            let value2 = nonzero_scalar(u.arbitrary::<u64>().ok()?);
            let blind2a = nonzero_scalar(u.arbitrary::<u64>().ok()?);
            let blind2b = nonzero_scalar(u.arbitrary::<u64>().ok()?);
            let stmt2 =
                pedersen_eq_statement_with_bases(&g, &h, &g, &h, &value2, &blind2a, &blind2b);
            let proof2 =
                prove_pedersen_eq(&stmt2, &value2, &blind2a, &blind2b, &ctx, &mut rng).ok()?;

            let statements = vec![stmt1.clone(), stmt2.clone()];
            let proofs = vec![proof1.clone(), proof2.clone()];
            let _ = batch_verify_pedersen_eq(&statements, &proofs, &ctx);

            let mut bad = proofs;
            bad[0].response_value = bad[0].response_value.add_mod(&Scalar::from_u64(1));
            assert!(batch_verify_pedersen_eq(&statements, &bad, &ctx).is_err());
        }
        _ => {
            let ctx = ctx(&mut u, 15)?;
            let h = pedersen_h();
            let value1 = nonzero_scalar(u.arbitrary::<u64>().ok()?);
            let blind1 = nonzero_scalar(u.arbitrary::<u64>().ok()?);
            let commitment_from1 = commit_default_bases(&value1, &blind1);
            let rerand1 = nonzero_scalar(u.arbitrary::<u64>().ok()?);
            let stmt1 = pedersen_rerand_statement_with_base(&h, &commitment_from1, &rerand1);
            let proof1 = prove_pedersen_rerand(&stmt1, &rerand1, &ctx, &mut rng).ok()?;

            let value2 = nonzero_scalar(u.arbitrary::<u64>().ok()?);
            let blind2 = nonzero_scalar(u.arbitrary::<u64>().ok()?);
            let commitment_from2 = commit_default_bases(&value2, &blind2);
            let rerand2 = nonzero_scalar(u.arbitrary::<u64>().ok()?);
            let stmt2 = pedersen_rerand_statement_with_base(&h, &commitment_from2, &rerand2);
            let proof2 = prove_pedersen_rerand(&stmt2, &rerand2, &ctx, &mut rng).ok()?;

            let statements = vec![stmt1.clone(), stmt2.clone()];
            let proofs = vec![proof1.clone(), proof2.clone()];
            let _ = batch_verify_pedersen_rerand(&statements, &proofs, &ctx);

            let mut bad = proofs;
            bad[0].response = bad[0].response.add_mod(&Scalar::from_u64(1));
            assert!(batch_verify_pedersen_rerand(&statements, &bad, &ctx).is_err());
        }
    }
    Some(())
}

fuzz_target!(|data: &[u8]| {
    let _ = run_once(data);
});

use rand::RngCore;
use starknet_crypto::Felt;

use crate::core::curve::{Point, add, ensure_non_identity, generator, mul, pedersen_h, sub};
use crate::core::errors::{ProverError, Result};
use crate::core::limits::MAX_ONE_OUT_OF_MANY;
use crate::core::scalar::Scalar;
use crate::core::transcript::transcript_new_one_out_of_many;
use crate::protocols::pedersen::{commit_default_bases, commit_with_bases};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PedersenOneOutOfManyStatement {
    pub commitment: Point,
    pub candidates: Vec<Point>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PedersenOneOutOfManyProof {
    pub cl: Vec<Point>,
    pub ca: Vec<Point>,
    pub cb: Vec<Point>,
    pub cd: Vec<Point>,
    pub f: Vec<Scalar>,
    pub za: Vec<Scalar>,
    pub zb: Vec<Scalar>,
    pub zd: Scalar,
}

const MAX_OOM_ATTEMPTS: usize = 128;

#[inline]
fn bit_at(index: usize, bit: usize) -> u64 {
    ((index >> bit) & 1) as u64
}

#[inline]
fn challenge_bit_width(statement_size: usize) -> Result<usize> {
    if statement_size == 0 || statement_size > MAX_ONE_OUT_OF_MANY {
        return Err(ProverError::InvalidStatement);
    }
    if !statement_size.is_power_of_two() {
        return Err(ProverError::RingSizeMustBePowerOfTwo);
    }
    Ok(statement_size.trailing_zeros() as usize)
}

fn derive_oom_challenge(
    statement: &PedersenOneOutOfManyStatement,
    n_bits: usize,
    cl: &[Point],
    ca: &[Point],
    cb: &[Point],
    cd: &[Point],
    context: &[Felt],
) -> Result<Scalar> {
    let mut transcript = transcript_new_one_out_of_many();
    transcript.append_felt(Felt::from(statement.candidates.len() as u64));
    transcript.append_point(&statement.commitment);
    for cand in &statement.candidates {
        transcript.append_point(cand);
    }
    transcript.append_felt(Felt::from(n_bits as u64));
    for p in cl {
        transcript.append_point(p);
    }
    for p in ca {
        transcript.append_point(p);
    }
    for p in cb {
        transcript.append_point(p);
    }
    for p in cd {
        transcript.append_point(p);
    }
    transcript.append_span(context);
    transcript.challenge()
}

fn poly_coeffs_for_index(index: usize, l_bits: &[u64], a: &[Scalar]) -> Vec<Scalar> {
    let n_bits = l_bits.len();
    let mut coeffs = vec![Scalar::from_u64(1)];
    let zero = Scalar::from_u64(0);

    for bit in 0..n_bits {
        let i_bit = bit_at(index, bit);
        let l_bit = l_bits[bit];

        let (constant, linear) = if i_bit == 1 {
            (a[bit].clone(), Scalar::from_u64(l_bit))
        } else {
            let const_term = zero.sub_mod(&a[bit]);
            (const_term, Scalar::from_u64(1 - l_bit))
        };

        let mut next = vec![Scalar::from_u64(0); coeffs.len() + 1];
        for deg in 0..coeffs.len() {
            let c = &coeffs[deg];
            let const_contrib = c.mul_mod(&constant);
            next[deg] = next[deg].add_mod(&const_contrib);

            if !linear.is_zero() {
                let lin_contrib = c.mul_mod(&linear);
                next[deg + 1] = next[deg + 1].add_mod(&lin_contrib);
            }
        }

        coeffs = next;
    }

    coeffs
}

fn statement_differences(statement: &PedersenOneOutOfManyStatement) -> Result<Vec<Point>> {
    let n = statement.candidates.len();
    if n == 0 || n > MAX_ONE_OUT_OF_MANY {
        return Err(ProverError::InvalidStatement);
    }
    ensure_non_identity(&statement.commitment)?;

    let mut out = Vec::with_capacity(n);
    for cand in &statement.candidates {
        ensure_non_identity(cand)?;
        out.push(sub(&statement.commitment, cand));
    }
    Ok(out)
}

fn proof_has_valid_shape(proof: &PedersenOneOutOfManyProof, expected_bits: usize) -> bool {
    proof.cl.len() == expected_bits
        && proof.ca.len() == expected_bits
        && proof.cb.len() == expected_bits
        && proof.cd.len() == expected_bits
        && proof.f.len() == expected_bits
        && proof.za.len() == expected_bits
        && proof.zb.len() == expected_bits
}

pub fn prove_pedersen_one_out_of_many<R: RngCore>(
    statement: &PedersenOneOutOfManyStatement,
    real_index: usize,
    value: &Scalar,
    blinding_commitment: &Scalar,
    blinding_candidate: &Scalar,
    context: &[Felt],
    rng: &mut R,
) -> Result<PedersenOneOutOfManyProof> {
    let n = statement.candidates.len();
    if n == 0 || n > MAX_ONE_OUT_OF_MANY {
        return Err(ProverError::InvalidStatement);
    }
    if real_index >= n {
        return Err(ProverError::InvalidStatement);
    }
    ensure_non_identity(&statement.commitment)?;
    for cand in &statement.candidates {
        ensure_non_identity(cand)?;
    }

    let expected_commitment = commit_default_bases(value, blinding_commitment);
    if expected_commitment != statement.commitment {
        return Err(ProverError::InvalidWitness);
    }

    let expected_real_candidate = commit_default_bases(value, blinding_candidate);
    if expected_real_candidate != statement.candidates[real_index] {
        return Err(ProverError::InvalidWitness);
    }

    let n_bits = challenge_bit_width(n)?;
    let c_points = statement_differences(statement)?;
    let candidate_count = c_points.len();

    let g = generator();
    let h = pedersen_h();
    let zero = Scalar::from_u64(0);

    let l_bits: Vec<u64> = (0..n_bits).map(|j| bit_at(real_index, j)).collect();

    let opening_diff = blinding_commitment.sub_mod(blinding_candidate);

    for _ in 0..MAX_OOM_ATTEMPTS {
        let mut r_bits = Vec::with_capacity(n_bits);
        let mut a_bits = Vec::with_capacity(n_bits);
        let mut s_bits = Vec::with_capacity(n_bits);
        let mut t_bits = Vec::with_capacity(n_bits);

        let mut cl = Vec::with_capacity(n_bits);
        let mut ca = Vec::with_capacity(n_bits);
        let mut cb = Vec::with_capacity(n_bits);

        let mut restart = false;

        for &l_bit in &l_bits {
            let r_j = Scalar::random(rng, true)?;
            let a_j = Scalar::random(rng, true)?;
            let s_j = Scalar::random(rng, true)?;
            let t_j = Scalar::random(rng, true)?;

            let l_j = Scalar::from_u64(l_bit);
            let la_j = if l_bit == 1 {
                a_j.clone()
            } else {
                zero.clone()
            };

            let c_lj = add(&mul(&g, &l_j), &mul(&h, &r_j));
            let c_aj = add(&mul(&g, &a_j), &mul(&h, &s_j));
            let c_bj = add(&mul(&g, &la_j), &mul(&h, &t_j));

            if ensure_non_identity(&c_lj).is_err()
                || ensure_non_identity(&c_aj).is_err()
                || ensure_non_identity(&c_bj).is_err()
            {
                restart = true;
                break;
            }

            r_bits.push(r_j);
            a_bits.push(a_j);
            s_bits.push(s_j);
            t_bits.push(t_j);
            cl.push(c_lj);
            ca.push(c_aj);
            cb.push(c_bj);
        }

        if restart {
            continue;
        }

        let mut coeffs = Vec::with_capacity(candidate_count);
        for i in 0..candidate_count {
            coeffs.push(poly_coeffs_for_index(i, &l_bits, &a_bits));
        }

        let mut rho = Vec::with_capacity(n_bits);
        let mut cd = Vec::with_capacity(n_bits);

        for (k, _) in l_bits.iter().enumerate() {
            let rho_k = Scalar::random(rng, true)?;
            let mut c_dk = mul(&h, &rho_k);

            for i in 0..candidate_count {
                let coeff_ik = &coeffs[i][k];
                if coeff_ik.is_zero() {
                    continue;
                }
                c_dk = add(&c_dk, &mul(&c_points[i], coeff_ik));
            }

            if ensure_non_identity(&c_dk).is_err() {
                restart = true;
                break;
            }

            rho.push(rho_k);
            cd.push(c_dk);
        }

        if restart {
            continue;
        }

        let challenge = derive_oom_challenge(statement, n_bits, &cl, &ca, &cb, &cd, context)?;

        let mut x_pows = Vec::with_capacity(n_bits + 1);
        let mut x_pow = Scalar::from_u64(1);
        for _ in 0..=n_bits {
            x_pows.push(x_pow.clone());
            x_pow = x_pow.mul_mod(&challenge);
        }

        let mut f = Vec::with_capacity(n_bits);
        let mut za = Vec::with_capacity(n_bits);
        let mut zb = Vec::with_capacity(n_bits);

        for j in 0..n_bits {
            let l_j = Scalar::from_u64(l_bits[j]);
            let f_j = a_bits[j].add_mod(&challenge.mul_mod(&l_j));
            let za_j = r_bits[j].mul_mod(&challenge).add_mod(&s_bits[j]);
            let x_minus_fj = challenge.sub_mod(&f_j);
            let zb_j = r_bits[j].mul_mod(&x_minus_fj).add_mod(&t_bits[j]);

            f.push(f_j);
            za.push(za_j);
            zb.push(zb_j);
        }

        let mut zd = opening_diff.mul_mod(&x_pows[n_bits]);
        for k in 0..n_bits {
            zd = zd.sub_mod(&rho[k].mul_mod(&x_pows[k]));
        }

        return Ok(PedersenOneOutOfManyProof {
            cl,
            ca,
            cb,
            cd,
            f,
            za,
            zb,
            zd,
        });
    }

    Err(ProverError::InvalidWitness)
}

pub fn verify_pedersen_one_out_of_many(
    statement: &PedersenOneOutOfManyStatement,
    proof: &PedersenOneOutOfManyProof,
    context: &[Felt],
) -> Result<()> {
    let n = statement.candidates.len();
    if n == 0 || n > MAX_ONE_OUT_OF_MANY {
        return Err(ProverError::InvalidStatement);
    }
    ensure_non_identity(&statement.commitment)?;
    for cand in &statement.candidates {
        ensure_non_identity(cand)?;
    }

    let n_bits = challenge_bit_width(n)?;
    if !proof_has_valid_shape(proof, n_bits) {
        return Err(ProverError::MismatchedLength);
    }

    for p in &proof.cl {
        ensure_non_identity(p)?;
    }
    for p in &proof.ca {
        ensure_non_identity(p)?;
    }
    for p in &proof.cb {
        ensure_non_identity(p)?;
    }
    for p in &proof.cd {
        ensure_non_identity(p)?;
    }
    for s in &proof.f {
        s.ensure_canonical()?;
    }
    for s in &proof.za {
        s.ensure_canonical()?;
    }
    for s in &proof.zb {
        s.ensure_canonical()?;
    }
    proof.zd.ensure_canonical()?;

    let challenge = derive_oom_challenge(
        statement, n_bits, &proof.cl, &proof.ca, &proof.cb, &proof.cd, context,
    )?;

    let g = generator();
    let h = pedersen_h();

    let mut x_pows = Vec::with_capacity(n_bits + 1);
    let mut x_pow = Scalar::from_u64(1);
    for _ in 0..=n_bits {
        x_pows.push(x_pow.clone());
        x_pow = x_pow.mul_mod(&challenge);
    }

    let mut x_minus_f = Vec::with_capacity(n_bits);
    for j in 0..n_bits {
        x_minus_f.push(challenge.sub_mod(&proof.f[j]));
    }

    for (j, cl_j) in proof.cl.iter().enumerate() {
        let lhs1 = add(&mul(cl_j, &challenge), &proof.ca[j]);
        let rhs1 = commit_with_bases(&g, &h, &proof.f[j], &proof.za[j]);
        if lhs1 != rhs1 {
            return Err(ProverError::InvalidProof);
        }

        let lhs2 = add(&mul(cl_j, &x_minus_f[j]), &proof.cb[j]);
        let rhs2 = mul(&h, &proof.zb[j]);
        if lhs2 != rhs2 {
            return Err(ProverError::InvalidProof);
        }
    }

    let c_points = statement_differences(statement)?;
    let candidate_count = c_points.len();

    let mut lhs = Point::identity();
    for (i, c_point) in c_points.iter().enumerate().take(candidate_count) {
        let mut e_i = Scalar::from_u64(1);
        for (j, (f_j, x_minus_f_j)) in proof.f.iter().zip(x_minus_f.iter()).enumerate() {
            let term = if bit_at(i, j) == 1 { f_j } else { x_minus_f_j };
            e_i = e_i.mul_mod(term);
        }
        if !e_i.is_zero() {
            lhs = add(&lhs, &mul(c_point, &e_i));
        }
    }

    for (cd_k, x_pow_k) in proof.cd.iter().zip(x_pows.iter()) {
        lhs = sub(&lhs, &mul(cd_k, x_pow_k));
    }

    let rhs = mul(&h, &proof.zd);
    if lhs == rhs {
        Ok(())
    } else {
        Err(ProverError::InvalidProof)
    }
}

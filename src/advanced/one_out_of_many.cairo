use core::array::{Array, ArrayTrait, Span, SpanTrait};
use core::ec::{EcPoint, EcStateTrait, NonZeroEcPoint};
use core::integer::u256;
use core::option::Option;
use core::traits::{Into, TryInto};

use crate::core::curve::generator;
use crate::core::errors::{VerifyError, VerifyResult};
use crate::core::limits::MAX_ONE_OUT_OF_MANY_U256;
use crate::core::scalar::{is_canonical_scalar, mul_mod_order, sub_mod_order};
use crate::core::transcript::{
    transcript_append_felt,
    transcript_append_point,
    transcript_append_span,
    transcript_challenge,
    transcript_new_one_out_of_many,
};
use crate::protocols::pedersen::bases::pedersen_h;
use crate::utils::bytes::{
    POINT_BYTES,
    SCALAR_BYTES,
    decode_point_be64,
    decode_points_be64,
    decode_scalars_be32,
};

pub const OOM_GK_COMMITMENT_BLOCKS_PER_BIT: u32 = 4;
pub const OOM_GK_SCALAR_BLOCKS_PER_BIT: u32 = 3;

#[derive(Copy, Drop)]
pub struct PedersenOneOutOfManyStatement {
    pub commitment: NonZeroEcPoint,
    pub candidates: Span<NonZeroEcPoint>,
}

#[derive(Copy, Drop)]
pub struct PedersenOneOutOfManyProof {
    pub cl: Span<NonZeroEcPoint>,
    pub ca: Span<NonZeroEcPoint>,
    pub cb: Span<NonZeroEcPoint>,
    pub cd: Span<NonZeroEcPoint>,
    pub f: Span<felt252>,
    pub za: Span<felt252>,
    pub zb: Span<felt252>,
    pub zd: felt252,
}

#[inline]
fn point_eq(a: EcPoint, b: EcPoint) -> bool {
    let delta = a + (-b);
    let maybe: Option<NonZeroEcPoint> = delta.try_into();
    match maybe {
        Some(_) => false,
        None => true,
    }
}

#[inline]
fn bit_at(index: u32, bit: u32) -> u32 {
    let mut divisor: u32 = 1;
    let mut i: u32 = 0;
    loop {
        if i >= bit {
            break;
        }
        divisor = divisor * 2;
        i += 1;
    }
    (index / divisor) % 2_u32
}

#[inline]
fn challenge_bit_width(n: u32) -> Result<u32, VerifyError> {
    if n == 0 {
        return Err(VerifyError::EmptyInstances);
    }
    let n_u256: u256 = n.into();
    if n_u256 > MAX_ONE_OUT_OF_MANY_U256 {
        return Err(VerifyError::InvalidStatement);
    }

    let mut size: u32 = n;
    let mut bits: u32 = 0;
    loop {
        if size == 1_u32 {
            break;
        }
        if size % 2_u32 != 0_u32 {
            return Err(VerifyError::RingSizeMustBePowerOfTwo);
        }
        size = size / 2_u32;
        bits += 1;
    }

    Ok(bits)
}

#[inline]
fn proof_shape_ok(proof: PedersenOneOutOfManyProof, n_bits: u32) -> bool {
    proof.cl.len() == n_bits
        && proof.ca.len() == n_bits
        && proof.cb.len() == n_bits
        && proof.cd.len() == n_bits
        && proof.f.len() == n_bits
        && proof.za.len() == n_bits
        && proof.zb.len() == n_bits
}

#[inline]
fn statement_differences(stmt: PedersenOneOutOfManyStatement) -> Result<Array<EcPoint>, VerifyError> {
    let mut out: Array<EcPoint> = ArrayTrait::new();
    let mut candidates = stmt.candidates;

    loop {
        match candidates.pop_front() {
            Some(c_ref) => {
                let mut st = EcStateTrait::init();
                st.add(stmt.commitment);
                st.add(-*c_ref);
                out.append(st.finalize());
            },
            None => {
                break;
            },
        }
    }

    if out.len() == 0 {
        return Err(VerifyError::EmptyInstances);
    }

    Ok(out)
}

fn derive_oom_challenge(
    stmt: PedersenOneOutOfManyStatement,
    proof: PedersenOneOutOfManyProof,
    context: Span<felt252>,
) -> Result<felt252, VerifyError> {
    let mut transcript = transcript_new_one_out_of_many();
    let n_felt: felt252 = stmt.candidates.len().into();
    transcript_append_felt(ref transcript, n_felt);
    transcript_append_point(ref transcript, stmt.commitment);

    let mut cand_iter = stmt.candidates;
    loop {
        match cand_iter.pop_front() {
            Some(c_ref) => {
                transcript_append_point(ref transcript, *c_ref);
            },
            None => {
                break;
            },
        }
    }

    let n_bits_felt: felt252 = proof.f.len().into();
    transcript_append_felt(ref transcript, n_bits_felt);

    let mut cl_iter = proof.cl;
    loop {
        match cl_iter.pop_front() {
            Some(p_ref) => {
                transcript_append_point(ref transcript, *p_ref);
            },
            None => {
                break;
            },
        }
    }

    let mut ca_iter = proof.ca;
    loop {
        match ca_iter.pop_front() {
            Some(p_ref) => {
                transcript_append_point(ref transcript, *p_ref);
            },
            None => {
                break;
            },
        }
    }

    let mut cb_iter = proof.cb;
    loop {
        match cb_iter.pop_front() {
            Some(p_ref) => {
                transcript_append_point(ref transcript, *p_ref);
            },
            None => {
                break;
            },
        }
    }

    let mut cd_iter = proof.cd;
    loop {
        match cd_iter.pop_front() {
            Some(p_ref) => {
                transcript_append_point(ref transcript, *p_ref);
            },
            None => {
                break;
            },
        }
    }

    transcript_append_span(ref transcript, context);
    match transcript_challenge(@transcript) {
        Some(challenge) => Ok(challenge),
        None => Err(VerifyError::ZeroChallenge),
    }
}

/// logarithmic groth-kohlweiss one-out-of-many proof over pedersen commitments candidate set size must be a power of two (`n = 2^k`)
pub fn verify_pedersen_one_out_of_many(
    stmt: PedersenOneOutOfManyStatement,
    proof: PedersenOneOutOfManyProof,
    context: Span<felt252>,
) -> VerifyResult {
    let n = stmt.candidates.len();
    let n_bits = challenge_bit_width(n)?;
    if !proof_shape_ok(proof, n_bits) {
        return Err(VerifyError::MismatchedLength);
    }

    if !is_canonical_scalar(proof.zd) {
        return Err(VerifyError::NonCanonicalScalar);
    }

    let mut f_iter_check = proof.f;
    loop {
        match f_iter_check.pop_front() {
            Some(s_ref) => {
                if !is_canonical_scalar(*s_ref) {
                    return Err(VerifyError::NonCanonicalScalar);
                }
            },
            None => {
                break;
            },
        }
    }

    let mut za_iter_check = proof.za;
    loop {
        match za_iter_check.pop_front() {
            Some(s_ref) => {
                if !is_canonical_scalar(*s_ref) {
                    return Err(VerifyError::NonCanonicalScalar);
                }
            },
            None => {
                break;
            },
        }
    }

    let mut zb_iter_check = proof.zb;
    loop {
        match zb_iter_check.pop_front() {
            Some(s_ref) => {
                if !is_canonical_scalar(*s_ref) {
                    return Err(VerifyError::NonCanonicalScalar);
                }
            },
            None => {
                break;
            },
        }
    }

    let challenge = derive_oom_challenge(stmt, proof, context)?;

    let Some(g) = generator() else {
        return Err(VerifyError::InvalidPoint);
    };
    let Some(h) = pedersen_h() else {
        return Err(VerifyError::InvalidPoint);
    };

    let mut cl_iter = proof.cl;
    let mut ca_iter = proof.ca;
    let mut cb_iter = proof.cb;
    let mut f_iter = proof.f;
    let mut za_iter = proof.za;
    let mut zb_iter = proof.zb;

    loop {
        match cl_iter.pop_front() {
            Some(cl_ref) => {
                let Some(ca_ref) = ca_iter.pop_front() else {
                    return Err(VerifyError::MismatchedLength);
                };
                let Some(cb_ref) = cb_iter.pop_front() else {
                    return Err(VerifyError::MismatchedLength);
                };
                let Some(f_ref) = f_iter.pop_front() else {
                    return Err(VerifyError::MismatchedLength);
                };
                let Some(za_ref) = za_iter.pop_front() else {
                    return Err(VerifyError::MismatchedLength);
                };
                let Some(zb_ref) = zb_iter.pop_front() else {
                    return Err(VerifyError::MismatchedLength);
                };

                let x_minus_f = sub_mod_order(challenge, *f_ref);

                let mut lhs1_state = EcStateTrait::init();
                lhs1_state.add_mul(challenge, *cl_ref);
                lhs1_state.add(*ca_ref);
                let lhs1 = lhs1_state.finalize();

                let mut rhs1_state = EcStateTrait::init();
                rhs1_state.add_mul(*f_ref, g);
                rhs1_state.add_mul(*za_ref, h);
                let rhs1 = rhs1_state.finalize();

                if !point_eq(lhs1, rhs1) {
                    return Err(VerifyError::InvalidProof);
                }

                let mut lhs2_state = EcStateTrait::init();
                lhs2_state.add_mul(x_minus_f, *cl_ref);
                lhs2_state.add(*cb_ref);
                let lhs2 = lhs2_state.finalize();

                let mut rhs2_state = EcStateTrait::init();
                rhs2_state.add_mul(*zb_ref, h);
                let rhs2 = rhs2_state.finalize();

                if !point_eq(lhs2, rhs2) {
                    return Err(VerifyError::InvalidProof);
                }
            },
            None => {
                break;
            },
        }
    }

    let c_points = statement_differences(stmt)?;
    let candidate_n = c_points.len();

    let mut lhs_state = EcStateTrait::init();
    let mut c_iter = c_points.span();
    let mut i: u32 = 0;
    loop {
        if i >= candidate_n {
            break;
        }
        let Some(c_ref) = c_iter.pop_front() else {
            return Err(VerifyError::InvalidStatement);
        };

        let mut e_i: felt252 = 1;
        let mut f_eval_iter = proof.f;
        let mut j: u32 = 0;
        loop {
            if j >= n_bits {
                break;
            }
            let Some(fj_ref) = f_eval_iter.pop_front() else {
                return Err(VerifyError::MismatchedLength);
            };
            let term = if bit_at(i, j) == 1_u32 {
                *fj_ref
            } else {
                sub_mod_order(challenge, *fj_ref)
            };
            e_i = mul_mod_order(e_i, term);
            j += 1;
        }

        if e_i != 0 {
            let maybe_nz: Option<NonZeroEcPoint> = (*c_ref).try_into();
            match maybe_nz {
                Some(nz) => {
                    lhs_state.add_mul(e_i, nz);
                },
                None => {},
            }
        }

        i += 1;
    }

    let mut cd_iter = proof.cd;
    let mut x_pow: felt252 = 1;
    loop {
        match cd_iter.pop_front() {
            Some(cd_ref) => {
                let neg_x_pow = sub_mod_order(0, x_pow);
                lhs_state.add_mul(neg_x_pow, *cd_ref);
                x_pow = mul_mod_order(x_pow, challenge);
            },
            None => {
                break;
            },
        }
    }

    let lhs = lhs_state.finalize();
    let mut rhs_state = EcStateTrait::init();
    rhs_state.add_mul(proof.zd, h);
    let rhs = rhs_state.finalize();

    if point_eq(lhs, rhs) {
        Ok(())
    } else {
        Err(VerifyError::InvalidProof)
    }
}

/// logarithmic one-out-of-many proof over byte-encoded inputs `proof_commitments = cl || ca || cb || cd` and `proof_scalars = f || za || zb || zd` candidate set size must be a power of two (`n = 2^k`)
pub fn verify_pedersen_one_out_of_many_bytes(
    commitment: Span<u8>,
    candidates: Span<u8>,
    proof_commitments: Span<u8>,
    proof_scalars: Span<u8>,
    context: Span<felt252>,
) -> VerifyResult {
    let commitment_point = decode_point_be64(commitment)?;
    if candidates.len() % POINT_BYTES != 0 {
        return Err(VerifyError::InvalidEncoding);
    }

    let n: u32 = candidates.len() / POINT_BYTES;
    if n == 0 {
        return Err(VerifyError::EmptyInstances);
    }
    let n_u256: u256 = n.into();
    if n_u256 > MAX_ONE_OUT_OF_MANY_U256 {
        return Err(VerifyError::InvalidStatement);
    }

    let n_bits = challenge_bit_width(n)?;
    let expected_commitment_blocks = n_bits * OOM_GK_COMMITMENT_BLOCKS_PER_BIT;
    let expected_scalar_blocks = n_bits * OOM_GK_SCALAR_BLOCKS_PER_BIT + 1;

    if proof_commitments.len() != expected_commitment_blocks * POINT_BYTES {
        return Err(VerifyError::InvalidEncoding);
    }
    if proof_scalars.len() != expected_scalar_blocks * SCALAR_BYTES {
        return Err(VerifyError::InvalidEncoding);
    }

    let candidates_arr = decode_points_be64(candidates)?;
    let commitment_blocks = decode_points_be64(proof_commitments)?;
    let scalar_blocks = decode_scalars_be32(proof_scalars)?;

    if commitment_blocks.len() != expected_commitment_blocks {
        return Err(VerifyError::InvalidEncoding);
    }
    if scalar_blocks.len() != expected_scalar_blocks {
        return Err(VerifyError::InvalidEncoding);
    }

    let mut block_iter = commitment_blocks.span();
    let mut cl: Array<NonZeroEcPoint> = ArrayTrait::new();
    let mut ca: Array<NonZeroEcPoint> = ArrayTrait::new();
    let mut cb: Array<NonZeroEcPoint> = ArrayTrait::new();
    let mut cd: Array<NonZeroEcPoint> = ArrayTrait::new();

    let mut i: u32 = 0;
    loop {
        if i >= n_bits {
            break;
        }
        let Some(p_ref) = block_iter.pop_front() else {
            return Err(VerifyError::InvalidEncoding);
        };
        cl.append(*p_ref);
        i += 1;
    }

    let mut j: u32 = 0;
    loop {
        if j >= n_bits {
            break;
        }
        let Some(p_ref) = block_iter.pop_front() else {
            return Err(VerifyError::InvalidEncoding);
        };
        ca.append(*p_ref);
        j += 1;
    }

    let mut k: u32 = 0;
    loop {
        if k >= n_bits {
            break;
        }
        let Some(p_ref) = block_iter.pop_front() else {
            return Err(VerifyError::InvalidEncoding);
        };
        cb.append(*p_ref);
        k += 1;
    }

    let mut m: u32 = 0;
    loop {
        if m >= n_bits {
            break;
        }
        let Some(p_ref) = block_iter.pop_front() else {
            return Err(VerifyError::InvalidEncoding);
        };
        cd.append(*p_ref);
        m += 1;
    }

    if block_iter.len() != 0 {
        return Err(VerifyError::InvalidEncoding);
    }

    let mut scalar_iter = scalar_blocks.span();
    let mut f: Array<felt252> = ArrayTrait::new();
    let mut za: Array<felt252> = ArrayTrait::new();
    let mut zb: Array<felt252> = ArrayTrait::new();

    let mut a: u32 = 0;
    loop {
        if a >= n_bits {
            break;
        }
        let Some(s_ref) = scalar_iter.pop_front() else {
            return Err(VerifyError::InvalidEncoding);
        };
        f.append(*s_ref);
        a += 1;
    }

    let mut b: u32 = 0;
    loop {
        if b >= n_bits {
            break;
        }
        let Some(s_ref) = scalar_iter.pop_front() else {
            return Err(VerifyError::InvalidEncoding);
        };
        za.append(*s_ref);
        b += 1;
    }

    let mut c: u32 = 0;
    loop {
        if c >= n_bits {
            break;
        }
        let Some(s_ref) = scalar_iter.pop_front() else {
            return Err(VerifyError::InvalidEncoding);
        };
        zb.append(*s_ref);
        c += 1;
    }

    let Some(zd_ref) = scalar_iter.pop_front() else {
        return Err(VerifyError::InvalidEncoding);
    };
    if scalar_iter.len() != 0 {
        return Err(VerifyError::InvalidEncoding);
    }

    let stmt = PedersenOneOutOfManyStatement {
        commitment: commitment_point,
        candidates: candidates_arr.span(),
    };
    let proof = PedersenOneOutOfManyProof {
        cl: cl.span(),
        ca: ca.span(),
        cb: cb.span(),
        cd: cd.span(),
        f: f.span(),
        za: za.span(),
        zb: zb.span(),
        zd: *zd_ref,
    };
    verify_pedersen_one_out_of_many(stmt, proof, context)
}

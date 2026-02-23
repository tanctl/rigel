use rand::RngCore;
use starknet_crypto::Felt;

use crate::core::challenge::validate_challenge;
use crate::core::curve::{
    Point, add, ensure_non_identity, generator, mul, pedersen_h, reject_identity, sub,
};
use crate::core::errors::{ProverError, Result};
use crate::core::scalar::Scalar;
use crate::core::sigma::{derive_challenge, verify_batchable, verify_with_challenge};
use crate::core::transcript::{
    build_pedersen_eq_transcript, build_pedersen_rerand_transcript, build_pedersen_transcript,
};
use crate::protocols::types::{
    PedersenEqProof, PedersenEqShortProof, PedersenEqStatement, PedersenProof, PedersenRerandProof,
    PedersenRerandShortProof, PedersenRerandStatement, PedersenShortProof, PedersenStatement,
    SigmaProof, SigmaStatement,
};

/// commits with the default pedersen profile bases `(g, h_ped)`
/// prefer `commit_with_bases` in production integrations so the base choice stays explicit end-to-end
pub fn commit_default_bases(value: &Scalar, blinding: &Scalar) -> Point {
    let g = generator();
    let h = pedersen_h();
    let vg = mul(&g, value);
    let rh = mul(&h, blinding);
    add(&vg, &rh)
}

pub fn commit_with_bases(
    value_base: &Point,
    blinding_base: &Point,
    value: &Scalar,
    blinding: &Scalar,
) -> Point {
    let vg = mul(value_base, value);
    let rh = mul(blinding_base, blinding);
    add(&vg, &rh)
}

pub fn pedersen_statement_with_bases(
    value_base: &Point,
    blinding_base: &Point,
    value: &Scalar,
    blinding: &Scalar,
) -> PedersenStatement {
    PedersenStatement {
        commitment: commit_with_bases(value_base, blinding_base, value, blinding),
        value_base: value_base.clone(),
        blinding_base: blinding_base.clone(),
    }
}

pub fn prove_pedersen_opening<R: RngCore>(
    statement: &PedersenStatement,
    value: &Scalar,
    blinding: &Scalar,
    context: &[Felt],
    rng: &mut R,
) -> Result<PedersenProof> {
    ensure_non_identity(&statement.value_base)?;
    ensure_non_identity(&statement.blinding_base)?;
    ensure_non_identity(&statement.commitment)?;
    let expected = commit_with_bases(
        &statement.value_base,
        &statement.blinding_base,
        value,
        blinding,
    );
    if expected != statement.commitment {
        return Err(ProverError::InvalidWitness);
    }

    let k_v = Scalar::random_nonzero(rng)?;
    let k_r = Scalar::random_nonzero(rng)?;
    let nonce_commitment = add(
        &mul(&statement.value_base, &k_v),
        &mul(&statement.blinding_base, &k_r),
    );
    reject_identity(&nonce_commitment)?;

    let transcript = build_pedersen_transcript(
        &statement.value_base,
        &statement.blinding_base,
        &statement.commitment,
        &nonce_commitment,
        context,
    );
    let challenge = transcript.challenge()?;

    let response_value = k_v.add_mod(&challenge.mul_mod(value));
    let response_blinding = k_r.add_mod(&challenge.mul_mod(blinding));

    Ok(PedersenProof {
        nonce_commitment,
        response_value,
        response_blinding,
    })
}

pub fn verify_pedersen_opening(
    statement: &PedersenStatement,
    proof: &PedersenProof,
    context: &[Felt],
) -> Result<()> {
    let stmt = SigmaStatement::Pedersen(statement.clone());
    let sigma_proof = SigmaProof::Pedersen(proof.clone());
    verify_batchable(&stmt, &sigma_proof, context)
}

pub fn prove_pedersen_opening_short<R: RngCore>(
    statement: &PedersenStatement,
    value: &Scalar,
    blinding: &Scalar,
    context: &[Felt],
    rng: &mut R,
) -> Result<PedersenShortProof> {
    let proof = prove_pedersen_opening(statement, value, blinding, context, rng)?;
    let transcript = build_pedersen_transcript(
        &statement.value_base,
        &statement.blinding_base,
        &statement.commitment,
        &proof.nonce_commitment,
        context,
    );
    let challenge = transcript.challenge()?;
    Ok(PedersenShortProof {
        challenge,
        response_value: proof.response_value,
        response_blinding: proof.response_blinding,
    })
}

pub fn verify_pedersen_opening_short(
    statement: &PedersenStatement,
    proof: &PedersenShortProof,
    context: &[Felt],
) -> Result<()> {
    ensure_non_identity(&statement.value_base)?;
    ensure_non_identity(&statement.blinding_base)?;
    ensure_non_identity(&statement.commitment)?;
    validate_challenge(&proof.challenge)?;
    proof.response_value.ensure_canonical()?;
    proof.response_blinding.ensure_canonical()?;

    let simulated_nonce = sub(
        &add(
            &mul(&statement.value_base, &proof.response_value),
            &mul(&statement.blinding_base, &proof.response_blinding),
        ),
        &mul(&statement.commitment, &proof.challenge),
    );
    reject_identity(&simulated_nonce)?;

    let stmt = SigmaStatement::Pedersen(statement.clone());
    let sigma_proof = SigmaProof::Pedersen(PedersenProof {
        nonce_commitment: simulated_nonce,
        response_value: proof.response_value.clone(),
        response_blinding: proof.response_blinding.clone(),
    });
    verify_with_challenge(&stmt, &sigma_proof, &proof.challenge)?;
    let expected = derive_challenge(&stmt, &sigma_proof, context)?;
    if expected == proof.challenge {
        Ok(())
    } else {
        Err(ProverError::InvalidProof)
    }
}

pub fn pedersen_eq_statement_with_bases(
    value_base1: &Point,
    blinding_base1: &Point,
    value_base2: &Point,
    blinding_base2: &Point,
    value: &Scalar,
    blinding1: &Scalar,
    blinding2: &Scalar,
) -> PedersenEqStatement {
    PedersenEqStatement {
        commitment1: commit_with_bases(value_base1, blinding_base1, value, blinding1),
        commitment2: commit_with_bases(value_base2, blinding_base2, value, blinding2),
        value_base1: value_base1.clone(),
        blinding_base1: blinding_base1.clone(),
        value_base2: value_base2.clone(),
        blinding_base2: blinding_base2.clone(),
    }
}

pub fn prove_pedersen_eq<R: RngCore>(
    statement: &PedersenEqStatement,
    value: &Scalar,
    blinding1: &Scalar,
    blinding2: &Scalar,
    context: &[Felt],
    rng: &mut R,
) -> Result<PedersenEqProof> {
    ensure_non_identity(&statement.commitment1)?;
    ensure_non_identity(&statement.commitment2)?;
    ensure_non_identity(&statement.value_base1)?;
    ensure_non_identity(&statement.blinding_base1)?;
    ensure_non_identity(&statement.value_base2)?;
    ensure_non_identity(&statement.blinding_base2)?;
    let expected = pedersen_eq_statement_with_bases(
        &statement.value_base1,
        &statement.blinding_base1,
        &statement.value_base2,
        &statement.blinding_base2,
        value,
        blinding1,
        blinding2,
    );
    if expected.commitment1 != statement.commitment1
        || expected.commitment2 != statement.commitment2
    {
        return Err(ProverError::InvalidWitness);
    }

    let k_v = Scalar::random_nonzero(rng)?;
    let k_r1 = Scalar::random_nonzero(rng)?;
    let k_r2 = Scalar::random_nonzero(rng)?;
    let nonce_commitment1 = add(
        &mul(&statement.value_base1, &k_v),
        &mul(&statement.blinding_base1, &k_r1),
    );
    let nonce_commitment2 = add(
        &mul(&statement.value_base2, &k_v),
        &mul(&statement.blinding_base2, &k_r2),
    );
    reject_identity(&nonce_commitment1)?;
    reject_identity(&nonce_commitment2)?;

    let transcript = build_pedersen_eq_transcript(
        &statement.value_base1,
        &statement.blinding_base1,
        &statement.commitment1,
        &statement.value_base2,
        &statement.blinding_base2,
        &statement.commitment2,
        &nonce_commitment1,
        &nonce_commitment2,
        context,
    );
    let challenge = transcript.challenge()?;

    let response_value = k_v.add_mod(&challenge.mul_mod(value));
    let response_blinding1 = k_r1.add_mod(&challenge.mul_mod(blinding1));
    let response_blinding2 = k_r2.add_mod(&challenge.mul_mod(blinding2));

    Ok(PedersenEqProof {
        nonce_commitment1,
        nonce_commitment2,
        response_value,
        response_blinding1,
        response_blinding2,
    })
}

pub fn verify_pedersen_eq(
    statement: &PedersenEqStatement,
    proof: &PedersenEqProof,
    context: &[Felt],
) -> Result<()> {
    let stmt = SigmaStatement::PedersenEq(statement.clone());
    let sigma_proof = SigmaProof::PedersenEq(proof.clone());
    verify_batchable(&stmt, &sigma_proof, context)
}

pub fn prove_pedersen_eq_short<R: RngCore>(
    statement: &PedersenEqStatement,
    value: &Scalar,
    blinding1: &Scalar,
    blinding2: &Scalar,
    context: &[Felt],
    rng: &mut R,
) -> Result<PedersenEqShortProof> {
    let proof = prove_pedersen_eq(statement, value, blinding1, blinding2, context, rng)?;
    let transcript = build_pedersen_eq_transcript(
        &statement.value_base1,
        &statement.blinding_base1,
        &statement.commitment1,
        &statement.value_base2,
        &statement.blinding_base2,
        &statement.commitment2,
        &proof.nonce_commitment1,
        &proof.nonce_commitment2,
        context,
    );
    let challenge = transcript.challenge()?;
    Ok(PedersenEqShortProof {
        challenge,
        response_value: proof.response_value,
        response_blinding1: proof.response_blinding1,
        response_blinding2: proof.response_blinding2,
    })
}

pub fn verify_pedersen_eq_short(
    statement: &PedersenEqStatement,
    proof: &PedersenEqShortProof,
    context: &[Felt],
) -> Result<()> {
    ensure_non_identity(&statement.commitment1)?;
    ensure_non_identity(&statement.commitment2)?;
    ensure_non_identity(&statement.value_base1)?;
    ensure_non_identity(&statement.blinding_base1)?;
    ensure_non_identity(&statement.value_base2)?;
    ensure_non_identity(&statement.blinding_base2)?;
    validate_challenge(&proof.challenge)?;
    proof.response_value.ensure_canonical()?;
    proof.response_blinding1.ensure_canonical()?;
    proof.response_blinding2.ensure_canonical()?;

    let simulated_nonce1 = sub(
        &add(
            &mul(&statement.value_base1, &proof.response_value),
            &mul(&statement.blinding_base1, &proof.response_blinding1),
        ),
        &mul(&statement.commitment1, &proof.challenge),
    );
    let simulated_nonce2 = sub(
        &add(
            &mul(&statement.value_base2, &proof.response_value),
            &mul(&statement.blinding_base2, &proof.response_blinding2),
        ),
        &mul(&statement.commitment2, &proof.challenge),
    );
    reject_identity(&simulated_nonce1)?;
    reject_identity(&simulated_nonce2)?;

    let stmt = SigmaStatement::PedersenEq(statement.clone());
    let sigma_proof = SigmaProof::PedersenEq(PedersenEqProof {
        nonce_commitment1: simulated_nonce1,
        nonce_commitment2: simulated_nonce2,
        response_value: proof.response_value.clone(),
        response_blinding1: proof.response_blinding1.clone(),
        response_blinding2: proof.response_blinding2.clone(),
    });
    verify_with_challenge(&stmt, &sigma_proof, &proof.challenge)?;
    let expected = derive_challenge(&stmt, &sigma_proof, context)?;
    if expected == proof.challenge {
        Ok(())
    } else {
        Err(ProverError::InvalidProof)
    }
}

pub fn pedersen_rerand_statement_with_base(
    rerand_base: &Point,
    commitment_from: &Point,
    rerand: &Scalar,
) -> PedersenRerandStatement {
    let commitment_to = add(commitment_from, &mul(rerand_base, rerand));
    PedersenRerandStatement {
        rerand_base: rerand_base.clone(),
        commitment_from: commitment_from.clone(),
        commitment_to,
    }
}

pub fn prove_pedersen_rerand<R: RngCore>(
    statement: &PedersenRerandStatement,
    rerand: &Scalar,
    context: &[Felt],
    rng: &mut R,
) -> Result<PedersenRerandProof> {
    if rerand.is_zero() {
        return Err(ProverError::InvalidWitness);
    }
    ensure_non_identity(&statement.rerand_base)?;
    ensure_non_identity(&statement.commitment_from)?;
    ensure_non_identity(&statement.commitment_to)?;
    let expected = pedersen_rerand_statement_with_base(
        &statement.rerand_base,
        &statement.commitment_from,
        rerand,
    );
    if expected.commitment_to != statement.commitment_to {
        return Err(ProverError::InvalidWitness);
    }

    let delta = sub(&statement.commitment_to, &statement.commitment_from);
    reject_identity(&delta)?;

    let k = Scalar::random_nonzero(rng)?;
    let nonce_commitment = mul(&statement.rerand_base, &k);
    reject_identity(&nonce_commitment)?;

    let transcript = build_pedersen_rerand_transcript(
        &statement.rerand_base,
        &statement.commitment_from,
        &statement.commitment_to,
        &nonce_commitment,
        context,
    );
    let challenge = transcript.challenge()?;
    let response = k.add_mod(&challenge.mul_mod(rerand));
    Ok(PedersenRerandProof {
        nonce_commitment,
        response,
    })
}

pub fn verify_pedersen_rerand(
    statement: &PedersenRerandStatement,
    proof: &PedersenRerandProof,
    context: &[Felt],
) -> Result<()> {
    let stmt = SigmaStatement::PedersenRerand(statement.clone());
    let sigma_proof = SigmaProof::PedersenRerand(proof.clone());
    verify_batchable(&stmt, &sigma_proof, context)
}

pub fn prove_pedersen_rerand_short<R: RngCore>(
    statement: &PedersenRerandStatement,
    rerand: &Scalar,
    context: &[Felt],
    rng: &mut R,
) -> Result<PedersenRerandShortProof> {
    let proof = prove_pedersen_rerand(statement, rerand, context, rng)?;
    let transcript = build_pedersen_rerand_transcript(
        &statement.rerand_base,
        &statement.commitment_from,
        &statement.commitment_to,
        &proof.nonce_commitment,
        context,
    );
    let challenge = transcript.challenge()?;
    Ok(PedersenRerandShortProof {
        challenge,
        response: proof.response,
    })
}

pub fn verify_pedersen_rerand_short(
    statement: &PedersenRerandStatement,
    proof: &PedersenRerandShortProof,
    context: &[Felt],
) -> Result<()> {
    ensure_non_identity(&statement.rerand_base)?;
    ensure_non_identity(&statement.commitment_from)?;
    ensure_non_identity(&statement.commitment_to)?;
    validate_challenge(&proof.challenge)?;
    proof.response.ensure_canonical()?;

    let delta = sub(&statement.commitment_to, &statement.commitment_from);
    reject_identity(&delta)?;
    let simulated_nonce = sub(
        &mul(&statement.rerand_base, &proof.response),
        &mul(&delta, &proof.challenge),
    );
    reject_identity(&simulated_nonce)?;

    let stmt = SigmaStatement::PedersenRerand(statement.clone());
    let sigma_proof = SigmaProof::PedersenRerand(PedersenRerandProof {
        nonce_commitment: simulated_nonce,
        response: proof.response.clone(),
    });
    verify_with_challenge(&stmt, &sigma_proof, &proof.challenge)?;
    let expected = derive_challenge(&stmt, &sigma_proof, context)?;
    if expected == proof.challenge {
        Ok(())
    } else {
        Err(ProverError::InvalidProof)
    }
}

use starknet_crypto::{Felt, poseidon_hash_many};

use crate::core::constants::{
    CURVE_ID_STARK, PROTOCOL_AND, PROTOCOL_BATCH, PROTOCOL_CHAUM_PED, PROTOCOL_DLOG,
    PROTOCOL_OKAMOTO, PROTOCOL_ONE_OUT_OF_MANY, PROTOCOL_OR, PROTOCOL_PEDERSEN,
    PROTOCOL_PEDERSEN_EQ, PROTOCOL_PEDERSEN_RERAND, PROTOCOL_RING, PROTOCOL_SCHNORR,
};
use crate::core::curve::{Point, point_coordinates};
use crate::core::errors::{ProverError, Result};
use crate::core::scalar::Scalar;

#[derive(Clone, Debug)]
pub struct Transcript {
    pub data: Vec<Felt>,
}

impl Transcript {
    pub fn new(protocol_id: &Felt) -> Self {
        Transcript {
            data: vec![*protocol_id, *CURVE_ID_STARK],
        }
    }

    pub fn append_felt(&mut self, v: Felt) {
        self.data.push(v);
    }

    pub fn append_span(&mut self, span: &[Felt]) {
        self.data.extend_from_slice(span);
    }

    pub fn append_scalar(&mut self, s: &Scalar) {
        self.data.push(s.to_felt());
    }

    pub fn append_point(&mut self, p: &Point) {
        let (x, y) = point_coordinates(p);
        self.data.push(x);
        self.data.push(y);
    }

    pub fn hash(&self) -> Felt {
        poseidon_hash_many(self.data.iter())
    }

    pub fn challenge(&self) -> Result<Scalar> {
        let h = self.hash();
        let c = Scalar::from_felt_mod_order(&h);
        if c.is_zero() {
            Err(ProverError::ZeroChallenge)
        } else {
            Ok(c)
        }
    }
}

pub fn transcript_new_schnorr() -> Transcript {
    Transcript::new(&PROTOCOL_SCHNORR)
}
pub fn transcript_new_dlog() -> Transcript {
    Transcript::new(&PROTOCOL_DLOG)
}
pub fn transcript_new_chaum_ped() -> Transcript {
    Transcript::new(&PROTOCOL_CHAUM_PED)
}
pub fn transcript_new_okamoto() -> Transcript {
    Transcript::new(&PROTOCOL_OKAMOTO)
}
pub fn transcript_new_pedersen() -> Transcript {
    Transcript::new(&PROTOCOL_PEDERSEN)
}
pub fn transcript_new_pedersen_eq() -> Transcript {
    Transcript::new(&PROTOCOL_PEDERSEN_EQ)
}
pub fn transcript_new_pedersen_rerand() -> Transcript {
    Transcript::new(&PROTOCOL_PEDERSEN_RERAND)
}
pub fn transcript_new_and() -> Transcript {
    Transcript::new(&PROTOCOL_AND)
}
pub fn transcript_new_or() -> Transcript {
    Transcript::new(&PROTOCOL_OR)
}
pub fn transcript_new_ring() -> Transcript {
    Transcript::new(&PROTOCOL_RING)
}
pub fn transcript_new_batch() -> Transcript {
    Transcript::new(&PROTOCOL_BATCH)
}
pub fn transcript_new_one_out_of_many() -> Transcript {
    Transcript::new(&PROTOCOL_ONE_OUT_OF_MANY)
}

pub fn build_schnorr_transcript(
    public_key: &Point,
    commitment: &Point,
    context: &[Felt],
) -> Transcript {
    let mut t = transcript_new_schnorr();
    t.append_point(public_key);
    t.append_point(commitment);
    t.append_span(context);
    t
}

pub fn build_dlog_transcript(
    base: &Point,
    public_key: &Point,
    commitment: &Point,
    context: &[Felt],
) -> Transcript {
    let mut t = transcript_new_dlog();
    t.append_point(base);
    t.append_point(public_key);
    t.append_point(commitment);
    t.append_span(context);
    t
}

pub fn build_chaum_ped_transcript(
    y1: &Point,
    y2: &Point,
    h: &Point,
    r1: &Point,
    r2: &Point,
    context: &[Felt],
) -> Transcript {
    let mut t = transcript_new_chaum_ped();
    t.append_point(y1);
    t.append_point(y2);
    t.append_point(h);
    t.append_point(r1);
    t.append_point(r2);
    t.append_span(context);
    t
}

pub fn build_okamoto_transcript(
    bases: &[Point],
    y: &Point,
    r: &Point,
    context: &[Felt],
) -> Transcript {
    let mut t = transcript_new_okamoto();
    t.append_felt(Felt::from(bases.len() as u64));
    for base in bases {
        t.append_point(base);
    }
    t.append_point(y);
    t.append_point(r);
    t.append_span(context);
    t
}

pub fn build_pedersen_transcript(
    value_base: &Point,
    blinding_base: &Point,
    commitment: &Point,
    nonce_commitment: &Point,
    context: &[Felt],
) -> Transcript {
    let mut t = transcript_new_pedersen();
    t.append_point(value_base);
    t.append_point(blinding_base);
    t.append_point(commitment);
    t.append_point(nonce_commitment);
    t.append_span(context);
    t
}

#[allow(clippy::too_many_arguments)]
pub fn build_pedersen_eq_transcript(
    value_base1: &Point,
    blinding_base1: &Point,
    commitment1: &Point,
    value_base2: &Point,
    blinding_base2: &Point,
    commitment2: &Point,
    nonce_commitment1: &Point,
    nonce_commitment2: &Point,
    context: &[Felt],
) -> Transcript {
    let mut t = transcript_new_pedersen_eq();
    t.append_point(value_base1);
    t.append_point(blinding_base1);
    t.append_point(commitment1);
    t.append_point(value_base2);
    t.append_point(blinding_base2);
    t.append_point(commitment2);
    t.append_point(nonce_commitment1);
    t.append_point(nonce_commitment2);
    t.append_span(context);
    t
}

pub fn build_pedersen_rerand_transcript(
    rerand_base: &Point,
    commitment_from: &Point,
    commitment_to: &Point,
    nonce_commitment: &Point,
    context: &[Felt],
) -> Transcript {
    let mut t = transcript_new_pedersen_rerand();
    t.append_point(rerand_base);
    t.append_point(commitment_from);
    t.append_point(commitment_to);
    t.append_point(nonce_commitment);
    t.append_span(context);
    t
}

pub fn build_ring_transcript(
    public_keys: &[Point],
    commitments: &[Point],
    context: &[Felt],
) -> Transcript {
    let mut t = transcript_new_ring();
    t.append_felt(Felt::from(public_keys.len() as u64));
    for pk in public_keys {
        t.append_point(pk);
    }
    for r in commitments {
        t.append_point(r);
    }
    t.append_span(context);
    t
}

use core::array::{ArrayTrait, Span, SpanTrait};
use core::poseidon::poseidon_hash_span;
use core::ec::NonZeroEcPoint;
use core::traits::Into;
use crate::core::encoding::{append_point, append_point_xy, append_scalar};
use crate::core::scalar::{is_nonzero_scalar, reduce_mod_order};

/// domain separation identifiers (short-string felt252 constants)
pub const CURVE_ID_STARK: felt252 = 'STARK-CURVE';
pub const PROTOCOL_SCHNORR: felt252 = 'Rigel/Schnorr';
pub const PROTOCOL_DLOG: felt252 = 'Rigel/DLog';
pub const PROTOCOL_CHAUM_PED: felt252 = 'Rigel/ChaumPed';
pub const PROTOCOL_OKAMOTO: felt252 = 'Rigel/Okamoto';
pub const PROTOCOL_PEDERSEN: felt252 = 'Rigel/Pedersen';
pub const PROTOCOL_PEDERSEN_EQ: felt252 = 'Rigel/PedersenEq';
pub const PROTOCOL_PEDERSEN_RERAND: felt252 = 'Rigel/PedersenRerand';
pub const PROTOCOL_ONE_OUT_OF_MANY: felt252 = 'Rigel/OneOutOfMany';
pub const PROTOCOL_AND: felt252 = 'Rigel/AND';
pub const PROTOCOL_OR: felt252 = 'Rigel/OR';
pub const PROTOCOL_RING: felt252 = 'Rigel/Ring';
pub const PROTOCOL_BATCH: felt252 = 'Rigel/Batch';

#[derive(Drop)]
pub struct Transcript {
    /// flat sequence of felt252 values with no explicit length markers
    pub data: Array<felt252>,
}

#[inline]
pub fn transcript_new_schnorr() -> Transcript {
    let mut data = ArrayTrait::new();
    data.append(PROTOCOL_SCHNORR);
    data.append(CURVE_ID_STARK);
    Transcript { data }
}

#[inline]
pub fn transcript_new_dlog() -> Transcript {
    let mut data = ArrayTrait::new();
    data.append(PROTOCOL_DLOG);
    data.append(CURVE_ID_STARK);
    Transcript { data }
}

#[inline]
pub fn transcript_new_chaum_ped() -> Transcript {
    let mut data = ArrayTrait::new();
    data.append(PROTOCOL_CHAUM_PED);
    data.append(CURVE_ID_STARK);
    Transcript { data }
}

#[inline]
pub fn transcript_new_okamoto() -> Transcript {
    let mut data = ArrayTrait::new();
    data.append(PROTOCOL_OKAMOTO);
    data.append(CURVE_ID_STARK);
    Transcript { data }
}

#[inline]
pub fn transcript_new_pedersen() -> Transcript {
    let mut data = ArrayTrait::new();
    data.append(PROTOCOL_PEDERSEN);
    data.append(CURVE_ID_STARK);
    Transcript { data }
}

#[inline]
pub fn transcript_new_pedersen_eq() -> Transcript {
    let mut data = ArrayTrait::new();
    data.append(PROTOCOL_PEDERSEN_EQ);
    data.append(CURVE_ID_STARK);
    Transcript { data }
}

#[inline]
pub fn transcript_new_pedersen_rerand() -> Transcript {
    let mut data = ArrayTrait::new();
    data.append(PROTOCOL_PEDERSEN_RERAND);
    data.append(CURVE_ID_STARK);
    Transcript { data }
}

#[inline]
pub fn transcript_new_and() -> Transcript {
    let mut data = ArrayTrait::new();
    data.append(PROTOCOL_AND);
    data.append(CURVE_ID_STARK);
    Transcript { data }
}

#[inline]
pub fn transcript_new_or() -> Transcript {
    let mut data = ArrayTrait::new();
    data.append(PROTOCOL_OR);
    data.append(CURVE_ID_STARK);
    Transcript { data }
}

#[inline]
pub fn transcript_new_ring() -> Transcript {
    let mut data = ArrayTrait::new();
    data.append(PROTOCOL_RING);
    data.append(CURVE_ID_STARK);
    Transcript { data }
}

#[inline]
pub fn transcript_new_batch() -> Transcript {
    let mut data = ArrayTrait::new();
    data.append(PROTOCOL_BATCH);
    data.append(CURVE_ID_STARK);
    Transcript { data }
}

#[inline]
pub fn transcript_new_one_out_of_many() -> Transcript {
    let mut data = ArrayTrait::new();
    data.append(PROTOCOL_ONE_OUT_OF_MANY);
    data.append(CURVE_ID_STARK);
    Transcript { data }
}

/// transcript layout: protocol_id, curve_id, y.x, y.y, r.x, r.y, context
#[inline]
pub fn build_schnorr_transcript(
    public_key: NonZeroEcPoint,
    commitment: NonZeroEcPoint,
    context: Span<felt252>,
) -> Transcript {
    let mut t = transcript_new_schnorr();
    transcript_append_point(ref t, public_key);
    transcript_append_point(ref t, commitment);
    transcript_append_span(ref t, context);
    t
}

/// transcript layout: protocol_id, curve_id, base.x, base.y, y.x, y.y, r.x, r.y, context
#[inline]
pub fn build_dlog_transcript(
    base: NonZeroEcPoint,
    public_key: NonZeroEcPoint,
    commitment: NonZeroEcPoint,
    context: Span<felt252>,
) -> Transcript {
    let mut t = transcript_new_dlog();
    transcript_append_point(ref t, base);
    transcript_append_point(ref t, public_key);
    transcript_append_point(ref t, commitment);
    transcript_append_span(ref t, context);
    t
}

/// transcript layout: protocol_id, curve_id, y1.x, y1.y, y2.x, y2.y, h.x, h.y, r1.x, r1.y, r2.x, r2.y, context
#[inline]
pub fn build_chaum_ped_transcript(
    y1: NonZeroEcPoint,
    y2: NonZeroEcPoint,
    h: NonZeroEcPoint,
    r1: NonZeroEcPoint,
    r2: NonZeroEcPoint,
    context: Span<felt252>,
) -> Transcript {
    let mut t = transcript_new_chaum_ped();
    transcript_append_point(ref t, y1);
    transcript_append_point(ref t, y2);
    transcript_append_point(ref t, h);
    transcript_append_point(ref t, r1);
    transcript_append_point(ref t, r2);
    transcript_append_span(ref t, context);
    t
}

/// transcript layout: protocol_id, curve_id, n, g1.x, g1.y, ..., gn.x, gn.y, y.x, y.y, r.x, r.y, context
#[inline]
pub fn build_okamoto_transcript(
    mut bases: Span<NonZeroEcPoint>,
    y: NonZeroEcPoint,
    r: NonZeroEcPoint,
    context: Span<felt252>,
) -> Transcript {
    let mut t = transcript_new_okamoto();
    let n_felt: felt252 = bases.len().into();
    transcript_append_felt(ref t, n_felt);
    loop {
        match bases.pop_front() {
            Some(p) => transcript_append_point(ref t, *p),
            None => { break; },
        }
    }
    transcript_append_point(ref t, y);
    transcript_append_point(ref t, r);
    transcript_append_span(ref t, context);
    t
}

/// transcript layout: protocol_id, curve_id, gv.x, gv.y, h.x, h.y, c.x, c.y, r.x, r.y, context
#[inline]
pub fn build_pedersen_transcript(
    value_base: NonZeroEcPoint,
    blinding_base: NonZeroEcPoint,
    commitment: NonZeroEcPoint,
    nonce_commitment: NonZeroEcPoint,
    context: Span<felt252>,
) -> Transcript {
    let mut t = transcript_new_pedersen();
    transcript_append_point(ref t, value_base);
    transcript_append_point(ref t, blinding_base);
    transcript_append_point(ref t, commitment);
    transcript_append_point(ref t, nonce_commitment);
    transcript_append_span(ref t, context);
    t
}

/// transcript layout for generalized pedersen equality:
/// protocol_id, curve_id,
/// g1v.x, g1v.y, h1.x, h1.y, c1.x, c1.y,
/// g2v.x, g2v.y, h2.x, h2.y, c2.x, c2.y,
/// r1.x, r1.y, r2.x, r2.y,
/// context
#[inline]
pub fn build_pedersen_eq_transcript(
    value_base1: NonZeroEcPoint,
    blinding_base1: NonZeroEcPoint,
    commitment1: NonZeroEcPoint,
    value_base2: NonZeroEcPoint,
    blinding_base2: NonZeroEcPoint,
    commitment2: NonZeroEcPoint,
    nonce_commitment1: NonZeroEcPoint,
    nonce_commitment2: NonZeroEcPoint,
    context: Span<felt252>,
) -> Transcript {
    let mut t = transcript_new_pedersen_eq();
    transcript_append_point(ref t, value_base1);
    transcript_append_point(ref t, blinding_base1);
    transcript_append_point(ref t, commitment1);
    transcript_append_point(ref t, value_base2);
    transcript_append_point(ref t, blinding_base2);
    transcript_append_point(ref t, commitment2);
    transcript_append_point(ref t, nonce_commitment1);
    transcript_append_point(ref t, nonce_commitment2);
    transcript_append_span(ref t, context);
    t
}

/// transcript layout: protocol_id, curve_id, h.x, h.y, c1.x, c1.y, c2.x, c2.y, r.x, r.y, context
#[inline]
pub fn build_pedersen_rerand_transcript(
    rerand_base: NonZeroEcPoint,
    commitment_from: NonZeroEcPoint,
    commitment_to: NonZeroEcPoint,
    nonce_commitment: NonZeroEcPoint,
    context: Span<felt252>,
) -> Transcript {
    let mut t = transcript_new_pedersen_rerand();
    transcript_append_point(ref t, rerand_base);
    transcript_append_point(ref t, commitment_from);
    transcript_append_point(ref t, commitment_to);
    transcript_append_point(ref t, nonce_commitment);
    transcript_append_span(ref t, context);
    t
}

/// transcript layout: protocol_id, curve_id, n, y1.x, y1.y, ..., yn.x, yn.y, r1.x, r1.y, ..., rn.x, rn.y, context
#[inline]
pub fn build_ring_transcript(
    mut public_keys: Span<NonZeroEcPoint>,
    mut commitments: Span<NonZeroEcPoint>,
    context: Span<felt252>,
) -> Transcript {
    let mut t = transcript_new_ring();
    let n_felt: felt252 = public_keys.len().into();
    transcript_append_felt(ref t, n_felt);
    loop {
        match public_keys.pop_front() {
            Some(p) => transcript_append_point(ref t, *p),
            None => { break; },
        }
    }
    loop {
        match commitments.pop_front() {
            Some(p) => transcript_append_point(ref t, *p),
            None => { break; },
        }
    }
    transcript_append_span(ref t, context);
    t
}

#[inline]
pub fn transcript_append_felt(ref t: Transcript, v: felt252) {
    t.data.append(v);
}

#[inline]
pub fn transcript_append_span(ref t: Transcript, span: Span<felt252>) {
    t.data.append_span(span);
}

#[inline]
pub fn transcript_append_scalar(ref t: Transcript, s: felt252) -> Option<()> {
    append_scalar(ref t.data, s)
}

#[inline]
pub fn transcript_append_point(ref t: Transcript, p: NonZeroEcPoint) {
    append_point(ref t.data, p);
}

#[inline]
pub fn transcript_append_point_xy(ref t: Transcript, x: felt252, y: felt252) -> Option<()> {
    append_point_xy(ref t.data, x, y)
}

#[inline]
pub fn transcript_hash(t: @Transcript) -> felt252 {
    poseidon_hash_span(t.data.span())
}

/// computes `h(transcript) mod order` and returns `none` when zero
#[inline]
pub fn transcript_challenge(t: @Transcript) -> Option<felt252> {
    let h = poseidon_hash_span(t.data.span());
    let c = reduce_mod_order(h);
    if is_nonzero_scalar(c) { Some(c) } else { None }
}

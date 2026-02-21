use core::array::Span;
use core::ec::NonZeroEcPoint;

#[derive(Copy, Drop)]
pub struct SchnorrStatement {
    pub public_key: NonZeroEcPoint,
}

#[derive(Copy, Drop)]
pub struct SchnorrProof {
    pub commitment: NonZeroEcPoint,
    pub response: felt252,
}

#[derive(Copy, Drop)]
pub struct DLogStatement {
    pub base: NonZeroEcPoint,
    pub public_key: NonZeroEcPoint,
}

#[derive(Copy, Drop)]
pub struct DLogProof {
    pub commitment: NonZeroEcPoint,
    pub response: felt252,
}

#[derive(Copy, Drop)]
pub struct ChaumPedStatement {
    pub y1: NonZeroEcPoint,
    pub y2: NonZeroEcPoint,
    pub h: NonZeroEcPoint,
}

#[derive(Copy, Drop)]
pub struct ChaumPedProof {
    pub r1: NonZeroEcPoint,
    pub r2: NonZeroEcPoint,
    pub response: felt252,
}

#[derive(Copy, Drop)]
pub struct OkamotoStatement {
    pub bases: Span<NonZeroEcPoint>,
    pub y: NonZeroEcPoint,
}

#[derive(Copy, Drop)]
pub struct OkamotoProof {
    pub commitment: NonZeroEcPoint,
    pub responses: Span<felt252>,
}

#[derive(Copy, Drop)]
pub struct PedersenStatement {
    pub value_base: NonZeroEcPoint,
    pub blinding_base: NonZeroEcPoint,
    pub commitment: NonZeroEcPoint,
}

#[derive(Copy, Drop)]
pub struct PedersenProof {
    pub nonce_commitment: NonZeroEcPoint,
    pub response_value: felt252,
    pub response_blinding: felt252,
}

#[derive(Copy, Drop)]
pub struct PedersenEqStatement {
    pub commitment1: NonZeroEcPoint,
    pub commitment2: NonZeroEcPoint,
    pub value_base1: NonZeroEcPoint,
    pub blinding_base1: NonZeroEcPoint,
    pub value_base2: NonZeroEcPoint,
    pub blinding_base2: NonZeroEcPoint,
}

#[derive(Copy, Drop)]
pub struct PedersenEqProof {
    pub nonce_commitment1: NonZeroEcPoint,
    pub nonce_commitment2: NonZeroEcPoint,
    pub response_value: felt252,
    pub response_blinding1: felt252,
    pub response_blinding2: felt252,
}

#[derive(Copy, Drop)]
pub struct PedersenRerandStatement {
    pub rerand_base: NonZeroEcPoint,
    pub commitment_from: NonZeroEcPoint,
    pub commitment_to: NonZeroEcPoint,
}

#[derive(Copy, Drop)]
pub struct PedersenRerandProof {
    pub nonce_commitment: NonZeroEcPoint,
    pub response: felt252,
}

#[derive(Copy, Drop)]
pub enum SigmaStatement {
    Schnorr: SchnorrStatement,
    DLog: DLogStatement,
    ChaumPed: ChaumPedStatement,
    Okamoto: OkamotoStatement,
    Pedersen: PedersenStatement,
    PedersenEq: PedersenEqStatement,
    PedersenRerand: PedersenRerandStatement,
}

#[derive(Copy, Drop)]
pub enum SigmaProof {
    Schnorr: SchnorrProof,
    DLog: DLogProof,
    ChaumPed: ChaumPedProof,
    Okamoto: OkamotoProof,
    Pedersen: PedersenProof,
    PedersenEq: PedersenEqProof,
    PedersenRerand: PedersenRerandProof,
}

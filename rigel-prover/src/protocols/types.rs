use crate::core::curve::Point;
use crate::core::scalar::Scalar;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchnorrStatement {
    pub public_key: Point,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchnorrProof {
    pub commitment: Point,
    pub response: Scalar,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchnorrShortProof {
    pub challenge: Scalar,
    pub response: Scalar,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DLogStatement {
    pub base: Point,
    pub public_key: Point,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DLogProof {
    pub commitment: Point,
    pub response: Scalar,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DLogShortProof {
    pub challenge: Scalar,
    pub response: Scalar,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChaumPedStatement {
    pub y1: Point,
    pub y2: Point,
    pub h: Point,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChaumPedProof {
    pub r1: Point,
    pub r2: Point,
    pub response: Scalar,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChaumPedShortProof {
    pub challenge: Scalar,
    pub response: Scalar,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OkamotoStatement {
    pub bases: Vec<Point>,
    pub y: Point,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OkamotoProof {
    pub commitment: Point,
    pub responses: Vec<Scalar>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OkamotoShortProof {
    pub challenge: Scalar,
    pub responses: Vec<Scalar>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PedersenStatement {
    pub value_base: Point,
    pub blinding_base: Point,
    pub commitment: Point,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PedersenProof {
    pub nonce_commitment: Point,
    pub response_value: Scalar,
    pub response_blinding: Scalar,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PedersenShortProof {
    pub challenge: Scalar,
    pub response_value: Scalar,
    pub response_blinding: Scalar,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PedersenEqStatement {
    pub commitment1: Point,
    pub commitment2: Point,
    pub value_base1: Point,
    pub blinding_base1: Point,
    pub value_base2: Point,
    pub blinding_base2: Point,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PedersenEqProof {
    pub nonce_commitment1: Point,
    pub nonce_commitment2: Point,
    pub response_value: Scalar,
    pub response_blinding1: Scalar,
    pub response_blinding2: Scalar,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PedersenEqShortProof {
    pub challenge: Scalar,
    pub response_value: Scalar,
    pub response_blinding1: Scalar,
    pub response_blinding2: Scalar,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PedersenRerandStatement {
    pub rerand_base: Point,
    pub commitment_from: Point,
    pub commitment_to: Point,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PedersenRerandProof {
    pub nonce_commitment: Point,
    pub response: Scalar,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PedersenRerandShortProof {
    pub challenge: Scalar,
    pub response: Scalar,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum SigmaStatement {
    Schnorr(SchnorrStatement),
    DLog(DLogStatement),
    ChaumPed(ChaumPedStatement),
    Okamoto(OkamotoStatement),
    Pedersen(PedersenStatement),
    PedersenEq(PedersenEqStatement),
    PedersenRerand(PedersenRerandStatement),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SigmaProof {
    Schnorr(SchnorrProof),
    DLog(DLogProof),
    ChaumPed(ChaumPedProof),
    Okamoto(OkamotoProof),
    Pedersen(PedersenProof),
    PedersenEq(PedersenEqProof),
    PedersenRerand(PedersenRerandProof),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SigmaWitness {
    Schnorr {
        secret: Scalar,
    },
    DLog {
        secret: Scalar,
    },
    ChaumPed {
        secret: Scalar,
    },
    Okamoto {
        secrets: Vec<Scalar>,
    },
    Pedersen {
        value: Scalar,
        blinding: Scalar,
    },
    PedersenEq {
        value: Scalar,
        blinding1: Scalar,
        blinding2: Scalar,
    },
    PedersenRerand {
        rerand: Scalar,
    },
}

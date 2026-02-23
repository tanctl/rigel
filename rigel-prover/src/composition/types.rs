use crate::core::scalar::Scalar;
use crate::protocols::types::{SigmaProof, SigmaStatement};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AndInstance {
    pub statement: SigmaStatement,
    pub proof: SigmaProof,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrInstance {
    pub statement: SigmaStatement,
    pub proof: SigmaProof,
    pub challenge: Scalar,
}

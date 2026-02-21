use crate::protocols::types::{SigmaStatement, SigmaProof};

#[derive(Copy, Drop)]
pub struct AndInstance {
    pub statement: SigmaStatement,
    pub proof: SigmaProof,
}

#[derive(Copy, Drop)]
pub struct OrInstance {
    pub statement: SigmaStatement,
    pub proof: SigmaProof,
    pub challenge: felt252,
}

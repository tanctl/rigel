use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProverError {
    #[error("non-canonical scalar")]
    NonCanonicalScalar,
    #[error("invalid point")]
    InvalidPoint,
    #[error("identity point not allowed")]
    IdentityPoint,
    #[error("zero challenge")]
    ZeroChallenge,
    #[error("invalid statement")]
    InvalidStatement,
    #[error("invalid proof")]
    InvalidProof,
    #[error("invalid witness")]
    InvalidWitness,
    #[error("mismatched length")]
    MismatchedLength,
    #[error("mismatched proof type")]
    MismatchedProofType,
    #[error("empty instances")]
    EmptyInstances,
    #[error("ring size must be a power of two")]
    RingSizeMustBePowerOfTwo,
    #[error("or-challenge sum mismatch")]
    OrChallengeSumMismatch,
    #[error("invalid encoding")]
    InvalidEncoding,
    #[error("unsupported")]
    Unsupported,
}

pub type Result<T> = core::result::Result<T, ProverError>;

#[derive(Copy, Drop, PartialEq, Serde)]
pub enum VerifyError {
    NonCanonicalScalar,
    InvalidPoint,
    ZeroChallenge,
    InvalidProof,
    InvalidStatement,
    MismatchedLength,
    MismatchedProofType,
    EmptyInstances,
    RingSizeMustBePowerOfTwo,
    OrChallengeSumMismatch,
    InvalidEncoding,
}

pub type VerifyResult = Result<(), VerifyError>;

use num_bigint::BigUint;
use num_traits::{One, Zero};
use rand::RngCore;
use starknet_crypto::Felt;

use crate::core::constants::ORDER;
use crate::core::errors::{ProverError, Result};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Scalar(BigUint);

impl Scalar {
    pub fn from_biguint(value: BigUint) -> Result<Self> {
        if value < *ORDER {
            Ok(Self(value))
        } else {
            Err(ProverError::NonCanonicalScalar)
        }
    }

    pub fn from_u64(value: u64) -> Self {
        Scalar(BigUint::from(value) % &*ORDER)
    }

    pub fn from_felt_mod_order(value: &Felt) -> Self {
        Scalar(value.to_biguint() % &*ORDER)
    }

    pub fn is_zero(&self) -> bool {
        self.0.is_zero()
    }

    pub fn is_canonical(&self) -> bool {
        self.0 < *ORDER
    }

    pub fn ensure_canonical(&self) -> Result<()> {
        if self.is_canonical() {
            Ok(())
        } else {
            Err(ProverError::NonCanonicalScalar)
        }
    }

    pub fn as_biguint(&self) -> &BigUint {
        &self.0
    }

    pub fn to_felt(&self) -> Felt {
        Felt::from(&self.0)
    }

    pub fn to_bytes_be(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        let bytes = self.0.to_bytes_be();
        let start = out.len().saturating_sub(bytes.len());
        out[start..].copy_from_slice(&bytes);
        out
    }

    pub fn add_mod(&self, other: &Scalar) -> Scalar {
        Scalar((&self.0 + &other.0) % &*ORDER)
    }

    pub fn sub_mod(&self, other: &Scalar) -> Scalar {
        if self.0 >= other.0 {
            Scalar(&self.0 - &other.0)
        } else {
            Scalar((&self.0 + &*ORDER) - &other.0)
        }
    }

    pub fn mul_mod(&self, other: &Scalar) -> Scalar {
        Scalar((&self.0 * &other.0) % &*ORDER)
    }

    pub fn inv_mod(&self) -> Result<Scalar> {
        if self.is_zero() {
            return Err(ProverError::NonCanonicalScalar);
        }
        let exponent = &*ORDER - BigUint::one() - BigUint::one();
        Ok(Scalar(self.0.modpow(&exponent, &ORDER)))
    }

    pub fn random<R: RngCore>(rng: &mut R, allow_zero: bool) -> Result<Scalar> {
        let mut buf = [0u8; 32];
        loop {
            rng.fill_bytes(&mut buf);
            let candidate = BigUint::from_bytes_be(&buf);
            if candidate >= *ORDER {
                continue;
            }
            if !allow_zero && candidate.is_zero() {
                continue;
            }
            return Ok(Scalar(candidate));
        }
    }

    pub fn random_nonzero<R: RngCore>(rng: &mut R) -> Result<Scalar> {
        Self::random(rng, false)
    }
}

pub fn pow2_mod_order(exp: u32) -> Scalar {
    let base = BigUint::from(2u64);
    Scalar(base.modpow(&BigUint::from(exp), &ORDER))
}

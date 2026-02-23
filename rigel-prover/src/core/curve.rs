use starknet_crypto::Felt;
use starknet_types_core::curve::AffinePoint;

use crate::core::constants::{PEDERSEN_H_X, PEDERSEN_H_Y};
use crate::core::errors::{ProverError, Result};
use crate::core::scalar::Scalar;

pub type Point = AffinePoint;

pub fn validate_point(x: Felt, y: Felt) -> Result<Point> {
    let p = AffinePoint::new(x, y).map_err(|_| ProverError::InvalidPoint)?;
    if p.is_identity() {
        return Err(ProverError::IdentityPoint);
    }
    Ok(p)
}

pub fn reject_identity(point: &Point) -> Result<Point> {
    if point.is_identity() {
        Err(ProverError::IdentityPoint)
    } else {
        Ok(point.clone())
    }
}

pub fn ensure_non_identity(point: &Point) -> Result<()> {
    if point.is_identity() {
        Err(ProverError::IdentityPoint)
    } else {
        Ok(())
    }
}

pub fn point_coordinates(point: &Point) -> (Felt, Felt) {
    (point.x(), point.y())
}

pub fn point_x(point: &Point) -> Felt {
    point.x()
}

pub fn point_y(point: &Point) -> Felt {
    point.y()
}

pub fn generator() -> Point {
    AffinePoint::generator()
}

pub fn pedersen_h() -> Point {
    // coordinates are precomputed and frozen in constants; use unchecked construction so this function remains infallible at runtime
    AffinePoint::new_unchecked(*PEDERSEN_H_X, *PEDERSEN_H_Y)
}

pub fn add(a: &Point, b: &Point) -> Point {
    a.clone() + b.clone()
}

pub fn sub(a: &Point, b: &Point) -> Point {
    a.clone() + (-b)
}

pub fn neg(p: &Point) -> Point {
    -p
}

pub fn mul(point: &Point, scalar: &Scalar) -> Point {
    point * scalar.to_felt()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::constants::{PEDERSEN_H_X, PEDERSEN_H_Y};

    #[test]
    fn pedersen_h_is_valid_and_not_generator() {
        let h_checked = validate_point(*PEDERSEN_H_X, *PEDERSEN_H_Y).expect("valid Pedersen H");
        let h = pedersen_h();
        assert_eq!(h, h_checked);
        assert_ne!(h, generator());
    }
}

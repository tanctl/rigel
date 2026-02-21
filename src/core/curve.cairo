use core::ec::{EcPoint, EcPointTrait, NonZeroEcPoint};
use core::ec::stark_curve::{GEN_X, GEN_Y};
use core::traits::TryInto;

#[inline]
pub fn validate_point(x: felt252, y: felt252) -> Option<NonZeroEcPoint> {
    EcPointTrait::new_nz(x, y)
}

#[inline]
pub fn reject_identity(p: EcPoint) -> Option<NonZeroEcPoint> {
    p.try_into()
}

#[inline]
pub fn point_coordinates(p: NonZeroEcPoint) -> (felt252, felt252) {
    EcPointTrait::coordinates(p)
}

#[inline]
pub fn point_x(p: NonZeroEcPoint) -> felt252 {
    EcPointTrait::x(p)
}

#[inline]
pub fn point_y(p: NonZeroEcPoint) -> felt252 {
    EcPointTrait::y(p)
}

#[inline]
pub fn generator() -> Option<NonZeroEcPoint> {
    EcPointTrait::new_nz(GEN_X, GEN_Y)
}

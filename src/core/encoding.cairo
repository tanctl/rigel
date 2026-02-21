use core::array::ArrayTrait;
use core::ec::NonZeroEcPoint;

use crate::core::curve::{point_coordinates, validate_point};
use crate::core::scalar::is_canonical_scalar;

#[inline]
pub fn append_scalar(ref out: Array<felt252>, s: felt252) -> Option<()> {
    if !is_canonical_scalar(s) {
        return None;
    }
    out.append(s);
    Some(())
}

#[inline]
pub fn append_point(ref out: Array<felt252>, p: NonZeroEcPoint) {
    let (x, y) = point_coordinates(p);
    out.append(x);
    out.append(y);
}

#[inline]
pub fn append_point_xy(ref out: Array<felt252>, x: felt252, y: felt252) -> Option<()> {
    let _p = validate_point(x, y)?;
    out.append(x);
    out.append(y);
    Some(())
}

#[inline]
pub fn encode_scalar(s: felt252) -> Option<Array<felt252>> {
    let mut out = ArrayTrait::new();
    append_scalar(ref out, s)?;
    Some(out)
}

#[inline]
pub fn encode_point(p: NonZeroEcPoint) -> Array<felt252> {
    let mut out = ArrayTrait::new();
    append_point(ref out, p);
    out
}

#[inline]
pub fn encode_point_xy(x: felt252, y: felt252) -> Option<Array<felt252>> {
    let mut out = ArrayTrait::new();
    append_point_xy(ref out, x, y)?;
    Some(out)
}

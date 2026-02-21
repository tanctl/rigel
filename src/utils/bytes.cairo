use core::array::{Array, ArrayTrait, Span, SpanTrait};
use core::integer::u256;
use core::traits::{Into, TryInto};
use core::ec::NonZeroEcPoint;

use crate::core::curve::validate_point;
use crate::core::errors::VerifyError;
use crate::core::scalar::order_u256;

pub const SCALAR_BYTES: u32 = 32;
pub const POINT_BYTES: u32 = 64;

#[inline]
fn pop_u8(ref data: Span<u8>) -> Result<u8, VerifyError> {
    match data.pop_front() {
        Some(b_ref) => Ok(*b_ref),
        None => Err(VerifyError::InvalidEncoding),
    }
}

#[inline]
fn pop_u256_be(ref data: Span<u8>, count: u32) -> Result<u256, VerifyError> {
    let mut acc: u256 = 0_u256;
    let base: u256 = 256_u32.into();
    let mut i: u32 = 0;
    loop {
        if i >= count {
            break;
        }
        let b = pop_u8(ref data)?;
        let b_u256: u256 = b.into();
        acc = acc * base + b_u256;
        i += 1;
    }
    Ok(acc)
}

#[inline]
fn scalar_from_u256(value: u256) -> Result<felt252, VerifyError> {
    let order = order_u256();
    if value >= order {
        return Err(VerifyError::NonCanonicalScalar);
    }
    value.try_into().ok_or(VerifyError::NonCanonicalScalar)
}

#[inline]
fn point_from_u256(x: u256, y: u256) -> Result<NonZeroEcPoint, VerifyError> {
    let x_felt: felt252 = x.try_into().ok_or(VerifyError::InvalidPoint)?;
    let y_felt: felt252 = y.try_into().ok_or(VerifyError::InvalidPoint)?;
    match validate_point(x_felt, y_felt) {
        Some(p) => Ok(p),
        None => Err(VerifyError::InvalidPoint),
    }
}

pub fn decode_scalar_be32(bytes: Span<u8>) -> Result<felt252, VerifyError> {
    if bytes.len() != SCALAR_BYTES {
        return Err(VerifyError::InvalidEncoding);
    }
    let mut data = bytes;
    let value = pop_u256_be(ref data, SCALAR_BYTES)?;
    scalar_from_u256(value)
}

pub fn decode_point_be64(bytes: Span<u8>) -> Result<NonZeroEcPoint, VerifyError> {
    if bytes.len() != POINT_BYTES {
        return Err(VerifyError::InvalidEncoding);
    }
    let mut data = bytes;
    let x = pop_u256_be(ref data, SCALAR_BYTES)?;
    let y = pop_u256_be(ref data, SCALAR_BYTES)?;
    point_from_u256(x, y)
}

pub fn decode_scalars_be32(bytes: Span<u8>) -> Result<Array<felt252>, VerifyError> {
    if bytes.len() % SCALAR_BYTES != 0 {
        return Err(VerifyError::InvalidEncoding);
    }
    let mut data = bytes;
    let mut out: Array<felt252> = ArrayTrait::new();
    loop {
        if data.len() == 0 {
            break;
        }
        let value = pop_u256_be(ref data, SCALAR_BYTES)?;
        let scalar = scalar_from_u256(value)?;
        out.append(scalar);
    }
    Ok(out)
}

pub fn decode_points_be64(bytes: Span<u8>) -> Result<Array<NonZeroEcPoint>, VerifyError> {
    if bytes.len() % POINT_BYTES != 0 {
        return Err(VerifyError::InvalidEncoding);
    }
    let mut data = bytes;
    let mut out: Array<NonZeroEcPoint> = ArrayTrait::new();
    loop {
        if data.len() == 0 {
            break;
        }
        let x = pop_u256_be(ref data, SCALAR_BYTES)?;
        let y = pop_u256_be(ref data, SCALAR_BYTES)?;
        let point = point_from_u256(x, y)?;
        out.append(point);
    }
    Ok(out)
}

pub(crate) fn pop_scalar_be32(ref data: Span<u8>) -> Result<felt252, VerifyError> {
    if data.len() < SCALAR_BYTES {
        return Err(VerifyError::InvalidEncoding);
    }
    let value = pop_u256_be(ref data, SCALAR_BYTES)?;
    scalar_from_u256(value)
}

pub(crate) fn pop_point_be64(ref data: Span<u8>) -> Result<NonZeroEcPoint, VerifyError> {
    if data.len() < POINT_BYTES {
        return Err(VerifyError::InvalidEncoding);
    }
    let x = pop_u256_be(ref data, SCALAR_BYTES)?;
    let y = pop_u256_be(ref data, SCALAR_BYTES)?;
    point_from_u256(x, y)
}

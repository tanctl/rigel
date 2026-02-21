use core::integer::u256;
use core::math::u256_mul_mod_n;
use core::traits::Into;
use core::zeroable::NonZero;

const ORDER_U256: u256 = u256 {
    low: 0xb781126dcae7b2321e66a241adc64d2f,
    high: 0x800000000000010ffffffffffffffff,
};
const ORDER_U256_NZ: NonZero<u256> =
    0x800000000000010ffffffffffffffffb781126dcae7b2321e66a241adc64d2f;
const U128_SHIFT_FELT: felt252 = 0x100000000000000000000000000000000_felt252;

#[inline]
fn scalar_from_u256(v: u256) -> felt252 {
    // all values converted here are reduced modulo curve ORDER, and ORDER < felt252 prime
    v.high.into() * U128_SHIFT_FELT + v.low.into()
}

#[inline]
pub fn is_nonzero_scalar(s: felt252) -> bool {
    s != 0
}

#[inline]
pub fn is_canonical_scalar(s: felt252) -> bool {
    let s_u256: u256 = s.into();
    s_u256 < ORDER_U256
}

#[inline]
pub fn order_u256() -> u256 {
    ORDER_U256
}

/// uses full integer division/remainder to avoid assumptions about the relationship between field modulus and curve order
#[inline]
pub fn reduce_mod_order(x: felt252) -> felt252 {
    let x_u256: u256 = x.into();
    let (_q, r) = DivRem::div_rem(x_u256, ORDER_U256_NZ);
    scalar_from_u256(r)
}

#[inline]
pub fn sub_mod_order(a: felt252, b: felt252) -> felt252 {
    let a_u256: u256 = a.into();
    let b_u256: u256 = b.into();
    let reduced = if a_u256 >= b_u256 {
        a_u256 - b_u256
    } else {
        ORDER_U256 - (b_u256 - a_u256)
    };
    scalar_from_u256(reduced)
}

#[inline]
pub fn mul_mod_order(a: felt252, b: felt252) -> felt252 {
    let a_u256: u256 = a.into();
    let b_u256: u256 = b.into();
    let r = u256_mul_mod_n(a_u256, b_u256, ORDER_U256_NZ);
    scalar_from_u256(r)
}

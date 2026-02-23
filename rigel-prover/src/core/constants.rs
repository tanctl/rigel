use num_bigint::BigUint;
use once_cell::sync::Lazy;
use starknet_crypto::Felt;

pub const PEDERSEN_H_DOMAIN: &str = "Rigel/Pedersen/H";
pub const PEDERSEN_H_COUNTER: u32 = 0;

pub const TAG_SCHNORR: u64 = 1;
pub const TAG_CHAUM_PED: u64 = 2;
pub const TAG_OKAMOTO: u64 = 3;
pub const TAG_PEDERSEN: u64 = 4;
pub const TAG_PEDERSEN_EQ: u64 = 5;
pub const TAG_PEDERSEN_RERAND: u64 = 6;
pub const TAG_DLOG: u64 = 7;

const ORDER_BE: [u8; 32] = [
    8, 0, 0, 0, 0, 0, 0, 16, 255, 255, 255, 255, 255, 255, 255, 255, 183, 129, 18, 109, 202,
    231, 178, 50, 30, 102, 162, 65, 173, 198, 77, 47,
];
const FIELD_PRIME_BE: [u8; 32] = [
    8, 0, 0, 0, 0, 0, 0, 17, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 1,
];
const PEDERSEN_H_X_BE: [u8; 32] = [
    0, 148, 157, 42, 223, 233, 175, 146, 229, 187, 151, 210, 107, 79, 99, 175, 124, 149, 143,
    131, 106, 26, 91, 156, 112, 30, 112, 23, 189, 239, 246, 138,
];
const PEDERSEN_H_Y_BE: [u8; 32] = [
    3, 252, 253, 83, 120, 147, 50, 234, 174, 121, 199, 166, 252, 158, 179, 2, 186, 131, 99, 47,
    146, 91, 87, 203, 214, 66, 40, 90, 183, 58, 155, 107,
];

pub static ORDER: Lazy<BigUint> = Lazy::new(|| {
    BigUint::from_bytes_be(&ORDER_BE)
});

/// stark field prime p = 2^251 + 17*2^192 + 1
pub static FIELD_PRIME: Lazy<BigUint> = Lazy::new(|| {
    BigUint::from_bytes_be(&FIELD_PRIME_BE)
});

pub static PEDERSEN_H_X: Lazy<Felt> = Lazy::new(|| {
    Felt::from_bytes_be(&PEDERSEN_H_X_BE)
});

pub static PEDERSEN_H_Y: Lazy<Felt> = Lazy::new(|| {
    Felt::from_bytes_be(&PEDERSEN_H_Y_BE)
});

pub static CURVE_ID_STARK: Lazy<Felt> = Lazy::new(|| felt_from_short_string("STARK-CURVE"));
pub static PROTOCOL_SCHNORR: Lazy<Felt> = Lazy::new(|| felt_from_short_string("Rigel/Schnorr"));
pub static PROTOCOL_DLOG: Lazy<Felt> = Lazy::new(|| felt_from_short_string("Rigel/DLog"));
pub static PROTOCOL_CHAUM_PED: Lazy<Felt> = Lazy::new(|| felt_from_short_string("Rigel/ChaumPed"));
pub static PROTOCOL_OKAMOTO: Lazy<Felt> = Lazy::new(|| felt_from_short_string("Rigel/Okamoto"));
pub static PROTOCOL_PEDERSEN: Lazy<Felt> = Lazy::new(|| felt_from_short_string("Rigel/Pedersen"));
pub static PROTOCOL_PEDERSEN_EQ: Lazy<Felt> =
    Lazy::new(|| felt_from_short_string("Rigel/PedersenEq"));
pub static PROTOCOL_PEDERSEN_RERAND: Lazy<Felt> =
    Lazy::new(|| felt_from_short_string("Rigel/PedersenRerand"));
pub static PROTOCOL_ONE_OUT_OF_MANY: Lazy<Felt> =
    Lazy::new(|| felt_from_short_string("Rigel/OneOutOfMany"));
pub static PROTOCOL_AND: Lazy<Felt> = Lazy::new(|| felt_from_short_string("Rigel/AND"));
pub static PROTOCOL_OR: Lazy<Felt> = Lazy::new(|| felt_from_short_string("Rigel/OR"));
pub static PROTOCOL_RING: Lazy<Felt> = Lazy::new(|| felt_from_short_string("Rigel/Ring"));
pub static PROTOCOL_BATCH: Lazy<Felt> = Lazy::new(|| felt_from_short_string("Rigel/Batch"));

pub fn felt_from_short_string(s: &str) -> Felt {
    Felt::from_bytes_be_slice(s.as_bytes())
}

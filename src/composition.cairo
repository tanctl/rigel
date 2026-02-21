use core::array::Span;

pub mod types;
mod bytes;
mod shared;
pub mod and;
pub mod or;
pub mod batch;

pub use types::{AndInstance, OrInstance};
pub use and::verify_and;
pub use or::verify_or;
pub use batch::{
    batch_verify_schnorr,
    batch_verify_dlog,
    batch_verify_chaum_ped,
    batch_verify_okamoto,
    batch_verify_pedersen,
    batch_verify_pedersen_eq,
    batch_verify_pedersen_rerand,
};
pub use and::verify_and_bytes;
pub use or::verify_or_bytes;
pub use batch::{
    batch_verify_schnorr_bytes,
    batch_verify_dlog_bytes,
    batch_verify_chaum_ped_bytes,
    batch_verify_okamoto_bytes,
    batch_verify_pedersen_bytes,
    batch_verify_pedersen_eq_bytes,
    batch_verify_pedersen_rerand_bytes,
};

pub fn composition_pair_label(protocol_tag: felt252, left_label: felt252, right_label: felt252) -> felt252 {
    shared::composition_pair_label(protocol_tag, left_label, right_label)
}

pub fn fold_composition_labels(protocol_tag: felt252, labels: Span<felt252>) -> Option<felt252> {
    shared::fold_composition_labels(protocol_tag, labels)
}

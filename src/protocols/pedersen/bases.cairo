use core::ec::{EcPointTrait, NonZeroEcPoint};

/// domain separation tag for pedersen h generator derivation
pub const PEDERSEN_H_DOMAIN: felt252 = 'Rigel/Pedersen/H';

pub const PEDERSEN_H_COUNTER: u32 = 0;

/// frozen pedersen h generator coordinates
/// these values are precomputed as the first valid curve point produced by:
/// seed = poseidon([pedersen_h_domain, curve_id_stark, counter]), starting at counter = 0
/// implementations must use this frozen constant and must not derive h at runtime
pub const PEDERSEN_H_X: felt252 = 262578095662180838419669744841577391006900930438465299949309013509530449546;
pub const PEDERSEN_H_Y: felt252 = 1803932398273292515046854939238941106017389255947930720851306443211978480491;

#[inline]
pub fn pedersen_h() -> Option<NonZeroEcPoint> {
    EcPointTrait::new_nz(PEDERSEN_H_X, PEDERSEN_H_Y)
}

#[cfg(test)]
pub(crate) mod test_derivation {
    use core::array::ArrayTrait;
    use core::ec::{EcPointTrait, NonZeroEcPoint};
    use core::poseidon::poseidon_hash_span;
    use core::traits::Into;

    use crate::core::curve::{generator, point_coordinates};
    use crate::core::transcript::CURVE_ID_STARK;
    use super::{PEDERSEN_H_DOMAIN, PEDERSEN_H_COUNTER};

    pub(crate) fn derive_pedersen_h_via_poseidon() -> Option<NonZeroEcPoint> {
        let Some(g) = generator() else {
            return None;
        };
        let (gx, gy) = point_coordinates(g);
        let mut counter: u32 = PEDERSEN_H_COUNTER;
        loop {
            if counter >= 1024_u32 {
                return None;
            }

            let mut inputs = ArrayTrait::new();
            inputs.append(PEDERSEN_H_DOMAIN);
            inputs.append(CURVE_ID_STARK);
            let counter_felt: felt252 = counter.into();
            inputs.append(counter_felt);

            let seed = poseidon_hash_span(inputs.span());
            match EcPointTrait::new_nz_from_x(seed) {
                Some(p) => {
                    let (px, py) = point_coordinates(p);
                    if px == gx && py == gy {
                        counter += 1;
                        continue;
                    }
                    return Some(p);
                },
                None => {
                    counter += 1;
                    continue;
                },
            }
        }
    }
}

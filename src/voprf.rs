// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::ciphersuite::CipherSuite;
use crate::errors::InternalError;
use crate::group::Group;
use crate::hash::Hash;
use crate::serialization::serialize;
use digest::Digest;
use generic_array::GenericArray;
use rand::{CryptoRng, RngCore};

use alloc::vec;
use generic_array::typenum::Unsigned;

static STR_VOPRF: &[u8] = b"HashToGroup-VOPRF07-";
static STR_VOPRF_FINALIZE: &[u8] = b"Finalize-VOPRF07-";
static MODE_BASE: u8 = 0x00;

pub struct Client<CS: CipherSuite> {
    data: alloc::vec::Vec<u8>,
    blind: <CS::Group as Group>::Scalar,
}

impl<CS: CipherSuite> Client<CS> {
    /// Computes the first step for the multiplicative blinding version of DH-OPRF.
    pub fn blind<R: RngCore + CryptoRng>(
        input: &[u8],
        blinding_factor_rng: &mut R,
    ) -> Result<(Self, CS::Group), InternalError> {
        // Choose a random scalar that must be non-zero
        let blind = <CS::Group as Group>::random_nonzero_scalar(blinding_factor_rng);
        let dst = [
            STR_VOPRF,
            &<CS::Group as Group>::get_context_string(MODE_BASE)?,
        ]
        .concat();
        let mapped_point = <CS::Group as Group>::map_to_curve::<CS::Hash>(input, &dst)?;
        let blind_token = mapped_point * &blind;
        Ok((
            Self {
                data: input.to_vec(),
                blind,
            },
            blind_token,
        ))
    }

    /// Computes the third step for the multiplicative blinding version of DH-OPRF, in which
    /// the client unblinds the server's message.
    pub fn finalize(
        &self,
        evaluated_element: CS::Group,
    ) -> Result<GenericArray<u8, <CS::Hash as Digest>::OutputSize>, InternalError> {
        let unblinded_element =
            evaluated_element * &<CS::Group as Group>::scalar_invert(&self.blind);
        finalize_after_unblind::<CS::Group, CS::Hash>(&self.data, unblinded_element)
    }

    #[cfg(test)]
    /// Only used for test functions
    pub fn from_data_and_blind(data: &[u8], blind: &<CS::Group as Group>::Scalar) -> Self {
        Self {
            data: data.to_vec(),
            blind: blind.clone(),
        }
    }

    #[cfg(test)]
    /// Only used for test functions
    pub fn get_blind(&self) -> <CS::Group as Group>::Scalar {
        self.blind
    }
}

pub struct Server<CS: CipherSuite> {
    oprf_key: <CS::Group as Group>::Scalar,
}

impl<CS: CipherSuite> Server<CS> {
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Result<Self, InternalError> {
        let mut key = vec![0u8; <CS::Hash as Digest>::OutputSize::USIZE];
        rng.fill_bytes(&mut key);
        Self::new_with_key(&key)
    }

    pub fn new_with_key(key: &[u8]) -> Result<Self, InternalError> {
        Ok(Self {
            oprf_key: CS::Group::from_scalar_slice(&GenericArray::clone_from_slice(key))?,
        })
    }

    /// Computes the second step for the multiplicative blinding version of DH-OPRF. This
    /// message is sent from the server (who holds the OPRF key) to the client.
    pub fn evaluate(&self, point: CS::Group) -> CS::Group {
        point * &self.oprf_key
    }
}

fn finalize_after_unblind<G: Group, H: Hash>(
    input: &[u8],
    unblinded_element: G,
) -> Result<GenericArray<u8, <H as Digest>::OutputSize>, InternalError> {
    let finalize_dst = [STR_VOPRF_FINALIZE, &G::get_context_string(MODE_BASE)?].concat();
    let hash_input = [
        serialize(input, 2)?,
        serialize(&unblinded_element.to_arr().to_vec(), 2)?,
        serialize(&finalize_dst, 2)?,
    ]
    .concat();
    Ok(<H as Digest>::digest(&hash_input))
}

///////////
// Tests //
// ===== //
///////////

#[cfg(test)]
mod tests {
    use super::*;
    use crate::group::Group;
    use curve25519_dalek::ristretto::RistrettoPoint;
    use generic_array::{arr, GenericArray};
    use rand::rngs::OsRng;
    use sha2::Sha512;

    struct Ristretto255Sha512;
    impl CipherSuite for Ristretto255Sha512 {
        type Group = RistrettoPoint;
        type Hash = Sha512;
    }

    fn prf(input: &[u8], oprf_key: &[u8]) -> GenericArray<u8, <Sha512 as Digest>::OutputSize> {
        let dst = [
            STR_VOPRF,
            &RistrettoPoint::get_context_string(MODE_BASE).unwrap(),
        ]
        .concat();
        let point = RistrettoPoint::map_to_curve::<Sha512>(input, &dst).unwrap();
        let scalar =
            RistrettoPoint::from_scalar_slice(GenericArray::from_slice(&oprf_key[..])).unwrap();
        let res = point * scalar;

        finalize_after_unblind::<RistrettoPoint, sha2::Sha512>(&input, res).unwrap()
    }

    #[test]
    fn oprf_retrieval() {
        let input = b"hunter2";
        let mut rng = OsRng;
        let (client, alpha) = Client::<Ristretto255Sha512>::blind(&input[..], &mut rng).unwrap();
        let oprf_key_bytes = arr![
            u8; 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31, 32,
        ];
        let server = Server::<Ristretto255Sha512>::new_with_key(&oprf_key_bytes).unwrap();
        let beta = server.evaluate(alpha);
        let res = client.finalize(beta).unwrap();
        let res2 = prf(&input[..], &oprf_key_bytes);
        assert_eq!(res, res2);
    }

    #[test]
    fn oprf_inversion_unsalted() {
        let mut rng = OsRng;
        let mut input = alloc::vec![0u8; 64];
        rng.fill_bytes(&mut input);
        let (client, alpha) = Client::<Ristretto255Sha512>::blind(&input, &mut rng).unwrap();
        let res = client.finalize(alpha).unwrap();

        let dst = [
            STR_VOPRF,
            &RistrettoPoint::get_context_string(MODE_BASE).unwrap(),
        ]
        .concat();
        let point = RistrettoPoint::map_to_curve::<Sha512>(&input, &dst).unwrap();
        let res2 = finalize_after_unblind::<RistrettoPoint, sha2::Sha512>(&input, point).unwrap();

        assert_eq!(res, res2);
    }
}

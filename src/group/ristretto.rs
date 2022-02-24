// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use digest::core_api::BlockSizeUser;
use digest::Digest;
use elliptic_curve::hash2curve::{ExpandMsg, ExpandMsgXmd, Expander};
use generic_array::typenum::{IsLess, IsLessOrEqual, U256, U32, U64};
use generic_array::GenericArray;
use rand_core::{CryptoRng, RngCore};
use subtle::ConstantTimeEq;

use super::Group;
use crate::{Error, InternalError, Result};

/// [`Group`] implementation for Ristretto255.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
// `cfg` here is only needed because of a bug in Rust's crate feature documentation. See: https://github.com/rust-lang/rust/issues/83428
#[cfg(feature = "ristretto255")]
pub struct Ristretto255;

#[cfg(feature = "ristretto255-ciphersuite")]
impl crate::CipherSuite for Ristretto255 {
    const ID: u16 = 0x0001;

    type Group = Ristretto255;

    type Hash = sha2::Sha512;
}

// `cfg` here is only needed because of a bug in Rust's crate feature documentation. See: https://github.com/rust-lang/rust/issues/83428
#[cfg(feature = "ristretto255")]
impl Group for Ristretto255 {
    type Elem = RistrettoPoint;

    type ElemLen = U32;

    type Scalar = Scalar;

    type ScalarLen = U32;

    // Implements the `hash_to_ristretto255()` function from
    // https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-10.txt
    fn hash_to_curve<H>(input: &[&[u8]], dst: &[u8]) -> Result<Self::Elem, InternalError>
    where
        H: Digest + BlockSizeUser,
        H::OutputSize: IsLess<U256> + IsLessOrEqual<H::BlockSize>,
    {
        let mut uniform_bytes = GenericArray::<_, U64>::default();
        ExpandMsgXmd::<H>::expand_message(input, dst, 64)
            .map_err(|_| InternalError::Input)?
            .fill_bytes(&mut uniform_bytes);

        Ok(RistrettoPoint::from_uniform_bytes(&uniform_bytes.into()))
    }

    // Implements the `HashToScalar()` function from
    // https://www.ietf.org/archive/id/draft-irtf-cfrg-voprf-07.html#section-4.1
    fn hash_to_scalar<H>(input: &[&[u8]], dst: &[u8]) -> Result<Self::Scalar, InternalError>
    where
        H: Digest + BlockSizeUser,
        H::OutputSize: IsLess<U256> + IsLessOrEqual<H::BlockSize>,
    {
        let mut uniform_bytes = GenericArray::<_, U64>::default();
        ExpandMsgXmd::<H>::expand_message(input, dst, 64)
            .map_err(|_| InternalError::Input)?
            .fill_bytes(&mut uniform_bytes);

        Ok(Scalar::from_bytes_mod_order_wide(&uniform_bytes.into()))
    }

    fn base_elem() -> Self::Elem {
        RISTRETTO_BASEPOINT_POINT
    }

    fn identity_elem() -> Self::Elem {
        RistrettoPoint::identity()
    }

    // serialization of a group element
    fn serialize_elem(elem: Self::Elem) -> GenericArray<u8, Self::ElemLen> {
        elem.compress().to_bytes().into()
    }

    fn deserialize_elem(element_bits: &[u8]) -> Result<Self::Elem> {
        CompressedRistretto::from_slice(element_bits)
            .decompress()
            .filter(|point| point != &RistrettoPoint::identity())
            .ok_or(Error::Deserialization)
    }

    fn random_scalar<R: RngCore + CryptoRng>(rng: &mut R) -> Self::Scalar {
        loop {
            let scalar = {
                let mut scalar_bytes = [0u8; 64];
                rng.fill_bytes(&mut scalar_bytes);
                Scalar::from_bytes_mod_order_wide(&scalar_bytes)
            };

            if scalar != Scalar::zero() {
                break scalar;
            }
        }
    }

    fn invert_scalar(scalar: Self::Scalar) -> Self::Scalar {
        scalar.invert()
    }

    fn is_zero_scalar(scalar: Self::Scalar) -> subtle::Choice {
        scalar.ct_eq(&Scalar::zero())
    }

    #[cfg(test)]
    fn zero_scalar() -> Self::Scalar {
        Scalar::zero()
    }

    fn serialize_scalar(scalar: Self::Scalar) -> GenericArray<u8, Self::ScalarLen> {
        scalar.to_bytes().into()
    }

    fn deserialize_scalar(scalar_bits: &[u8]) -> Result<Self::Scalar> {
        scalar_bits
            .try_into()
            .ok()
            .and_then(Scalar::from_canonical_bytes)
            .filter(|scalar| scalar != &Scalar::zero())
            .ok_or(Error::Deserialization)
    }
}

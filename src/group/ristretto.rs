// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use core::convert::TryInto;
use core::ops::Add;

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use digest::core_api::BlockSizeUser;
use digest::{Digest, FixedOutputReset};
use generic_array::typenum::{U1, U32, U64};
use generic_array::{ArrayLength, GenericArray};
use rand_core::{CryptoRng, RngCore};

use super::Group;
use crate::{Error, Result};

/// [`Group`] implementation for Ristretto255.
pub struct Ristretto255;

// `cfg` here is only needed because of a bug in Rust's crate feature documentation. See: https://github.com/rust-lang/rust/issues/83428
#[cfg(feature = "ristretto255")]
impl Group for Ristretto255 {
    const SUITE_ID: u16 = 0x0001;

    type Elem = RistrettoPoint;

    type ElemLen = U32;

    type Scalar = Scalar;

    type ScalarLen = U32;

    // Implements the `hash_to_ristretto255()` function from
    // https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-10.txt
    fn hash_to_curve<H: BlockSizeUser + Digest + FixedOutputReset, D: ArrayLength<u8> + Add<U1>>(
        msg: &[u8],
        dst: GenericArray<u8, D>,
    ) -> Result<Self::Elem>
    where
        <D as Add<U1>>::Output: ArrayLength<u8>,
    {
        let uniform_bytes = super::expand::expand_message_xmd::<H, U64, _, _>(Some(msg), dst)?;

        Ok(RistrettoPoint::from_uniform_bytes(
            uniform_bytes
                .as_slice()
                .try_into()
                .map_err(|_| Error::HashToCurveError)?,
        ))
    }

    // Implements the `HashToScalar()` function from
    // https://www.ietf.org/archive/id/draft-irtf-cfrg-voprf-07.html#section-4.1
    fn hash_to_scalar<
        'a,
        H: BlockSizeUser + Digest + FixedOutputReset,
        D: ArrayLength<u8> + Add<U1>,
        I: IntoIterator<Item = &'a [u8]>,
    >(
        input: I,
        dst: GenericArray<u8, D>,
    ) -> Result<Self::Scalar>
    where
        <D as Add<U1>>::Output: ArrayLength<u8>,
    {
        let uniform_bytes = super::expand::expand_message_xmd::<H, U64, _, _>(input, dst)?;

        Ok(Scalar::from_bytes_mod_order_wide(
            uniform_bytes
                .as_slice()
                .try_into()
                .map_err(|_| Error::HashToCurveError)?,
        ))
    }

    fn deserialize_scalar(scalar_bits: &GenericArray<u8, Self::ScalarLen>) -> Result<Self::Scalar> {
        Scalar::from_canonical_bytes((*scalar_bits).into())
            .filter(|scalar| scalar != &Scalar::zero())
            .ok_or(Error::ScalarError)
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

    fn serialize_scalar(scalar: Self::Scalar) -> GenericArray<u8, Self::ScalarLen> {
        scalar.to_bytes().into()
    }

    fn invert_scalar(scalar: Self::Scalar) -> Self::Scalar {
        scalar.invert()
    }

    fn deserialize_elem(element_bits: &GenericArray<u8, Self::ElemLen>) -> Result<Self::Elem> {
        CompressedRistretto::from_slice(element_bits)
            .decompress()
            .filter(|point| point != &RistrettoPoint::identity())
            .ok_or(Error::PointError)
    }

    // serialization of a group element
    fn serialize_elem(elem: Self::Elem) -> GenericArray<u8, Self::ElemLen> {
        elem.compress().to_bytes().into()
    }

    fn base_elem() -> Self::Elem {
        RISTRETTO_BASEPOINT_POINT
    }

    fn identity_elem() -> Self::Elem {
        RistrettoPoint::identity()
    }

    #[cfg(test)]
    fn zero_scalar() -> Self::Scalar {
        Scalar::zero()
    }
}

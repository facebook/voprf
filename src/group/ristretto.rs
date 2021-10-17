// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use super::Group;
use crate::errors::InternalError;
use core::convert::TryInto;
use core::ops::Add;
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
    traits::Identity,
};
use digest::{BlockInput, Digest};
use generic_array::{
    typenum::{U1, U32, U64},
    ArrayLength, GenericArray,
};
use rand_core::{CryptoRng, RngCore};

/// The implementation of such a subgroup for Ristretto
#[cfg(any(
    feature = "ristretto255_u64",
    feature = "ristretto255_u32",
    feature = "ristretto255_fiat_u64",
    feature = "ristretto255_fiat_u32",
    feature = "ristretto255_simd",
))]
impl Group for RistrettoPoint {
    const SUITE_ID: usize = 0x0001;

    // Implements the `hash_to_ristretto255()` function from
    // https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-10.txt
    fn hash_to_curve<H: BlockInput + Digest, D: ArrayLength<u8> + Add<U1>>(
        msg: &[u8],
        dst: GenericArray<u8, D>,
    ) -> Result<Self, InternalError>
    where
        <D as Add<U1>>::Output: ArrayLength<u8>,
    {
        let uniform_bytes = super::expand::expand_message_xmd::<H, U64, _, _>(Some(msg), dst)?;

        Ok(RistrettoPoint::from_uniform_bytes(
            uniform_bytes
                .as_slice()
                .try_into()
                .map_err(|_| InternalError::HashToCurveError)?,
        ))
    }

    // Implements the `HashToScalar()` function from
    // https://www.ietf.org/archive/id/draft-irtf-cfrg-voprf-07.html#section-4.1
    fn hash_to_scalar<
        'a,
        H: BlockInput + Digest,
        D: ArrayLength<u8> + Add<U1>,
        I: IntoIterator<Item = &'a [u8]>,
    >(
        input: I,
        dst: GenericArray<u8, D>,
    ) -> Result<Self::Scalar, InternalError>
    where
        <D as Add<U1>>::Output: ArrayLength<u8>,
    {
        let uniform_bytes = super::expand::expand_message_xmd::<H, U64, _, _>(input, dst)?;

        Ok(Scalar::from_bytes_mod_order_wide(
            uniform_bytes
                .as_slice()
                .try_into()
                .map_err(|_| InternalError::HashToCurveError)?,
        ))
    }

    type Scalar = Scalar;
    type ScalarLen = U32;
    fn from_scalar_slice_unchecked(
        scalar_bits: &GenericArray<u8, Self::ScalarLen>,
    ) -> Result<Self::Scalar, InternalError> {
        Ok(Scalar::from_bytes_mod_order(*scalar_bits.as_ref()))
    }

    fn random_nonzero_scalar<R: RngCore + CryptoRng>(rng: &mut R) -> Self::Scalar {
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

    fn scalar_as_bytes(scalar: Self::Scalar) -> GenericArray<u8, Self::ScalarLen> {
        scalar.to_bytes().into()
    }

    fn scalar_invert(scalar: &Self::Scalar) -> Self::Scalar {
        scalar.invert()
    }

    // The byte length necessary to represent group elements
    type ElemLen = U32;
    fn from_element_slice_unchecked(
        element_bits: &GenericArray<u8, Self::ElemLen>,
    ) -> Result<Self, InternalError> {
        CompressedRistretto::from_slice(element_bits)
            .decompress()
            .ok_or(InternalError::PointError)
    }
    // serialization of a group element
    fn to_arr(&self) -> GenericArray<u8, Self::ElemLen> {
        self.compress().to_bytes().into()
    }

    fn base_point() -> Self {
        RISTRETTO_BASEPOINT_POINT
    }

    fn identity() -> Self {
        <Self as Identity>::identity()
    }

    fn scalar_zero() -> Self::Scalar {
        Self::Scalar::zero()
    }
}

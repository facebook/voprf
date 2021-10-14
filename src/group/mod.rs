// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Defines the Group trait to specify the underlying prime order group

#[cfg(any(
    feature = "ristretto255_u64",
    feature = "ristretto255_u32",
    feature = "ristretto255_fiat_u64",
    feature = "ristretto255_fiat_u32",
    feature = "ristretto255_simd",
    eature = "p256",
))]
mod expand;
#[cfg(feature = "p256")]
#[cfg_attr(docsrs, doc(cfg(feature = "p256")))]
pub(crate) mod p256;
#[cfg(any(
    feature = "ristretto255_u64",
    feature = "ristretto255_u32",
    feature = "ristretto255_fiat_u64",
    feature = "ristretto255_fiat_u32",
    feature = "ristretto255_simd",
))]
#[cfg_attr(
    docsrs,
    doc(cfg(any(
        feature = "ristretto255_u64",
        feature = "ristretto255_u32",
        feature = "ristretto255_fiat_u64",
        feature = "ristretto255_fiat_u32",
        feature = "ristretto255_simd",
    )))
)]
mod ristretto;

use crate::errors::InternalError;
use core::ops::{Add, Mul, Sub};
use digest::{BlockInput, Digest};
use generic_array::{typenum::U1, ArrayLength, GenericArray};
use rand_core::{CryptoRng, RngCore};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// A prime-order subgroup of a base field (EC, prime-order field ...). This
/// subgroup is noted additively — as in the draft RFC — in this trait.
pub trait Group:
    Copy
    + Sized
    + ConstantTimeEq
    + for<'a> Mul<&'a <Self as Group>::Scalar, Output = Self>
    + for<'a> Add<&'a Self, Output = Self>
{
    /// The ciphersuite identifier as dictated by
    /// <https://www.ietf.org/archive/id/draft-irtf-cfrg-voprf-05.txt>
    const SUITE_ID: usize;

    /// transforms a password and domain separation tag (DST) into a curve point
    fn hash_to_curve<H: BlockInput + Digest, D: ArrayLength<u8> + Add<U1>>(
        msg: &[u8],
        dst: GenericArray<u8, D>,
    ) -> Result<Self, InternalError>
    where
        <D as Add<U1>>::Output: ArrayLength<u8>;

    /// Hashes a slice of pseudo-random bytes to a scalar
    fn hash_to_scalar<H: BlockInput + Digest, D: ArrayLength<u8> + Add<U1>>(
        input: &[u8],
        dst: GenericArray<u8, D>,
    ) -> Result<Self::Scalar, InternalError>
    where
        <D as Add<U1>>::Output: ArrayLength<u8>;

    /// The type of base field scalars
    type Scalar: Zeroize
        + Copy
        + ConstantTimeEq
        + for<'a> Add<&'a Self::Scalar, Output = Self::Scalar>
        + for<'a> Sub<&'a Self::Scalar, Output = Self::Scalar>
        + for<'a> Mul<&'a Self::Scalar, Output = Self::Scalar>;
    /// The byte length necessary to represent scalars
    type ScalarLen: ArrayLength<u8> + 'static;

    /// Return a scalar from its fixed-length bytes representation, without
    /// checking if the scalar is zero.
    fn from_scalar_slice_unchecked(
        scalar_bits: &GenericArray<u8, Self::ScalarLen>,
    ) -> Result<Self::Scalar, InternalError>;

    /// Return a scalar from its fixed-length bytes representation. If the scalar
    /// is zero, then return an error.
    fn from_scalar_slice<'a>(
        scalar_bits: impl Into<&'a GenericArray<u8, Self::ScalarLen>>,
    ) -> Result<Self::Scalar, InternalError> {
        let scalar = Self::from_scalar_slice_unchecked(scalar_bits.into())?;
        if scalar.ct_eq(&Self::scalar_zero()).into() {
            return Err(InternalError::ZeroScalarError);
        }
        Ok(scalar)
    }

    /// picks a scalar at random
    fn random_nonzero_scalar<R: RngCore + CryptoRng>(rng: &mut R) -> Self::Scalar;
    /// Serializes a scalar to bytes
    fn scalar_as_bytes(scalar: Self::Scalar) -> GenericArray<u8, Self::ScalarLen>;
    /// The multiplicative inverse of this scalar
    fn scalar_invert(scalar: &Self::Scalar) -> Self::Scalar;

    /// The byte length necessary to represent group elements
    type ElemLen: ArrayLength<u8> + 'static;

    /// Return an element from its fixed-length bytes representation. This is
    /// the unchecked version, which does not check for deserializing the identity
    /// element
    fn from_element_slice_unchecked(
        element_bits: &GenericArray<u8, Self::ElemLen>,
    ) -> Result<Self, InternalError>;

    /// Return an element from its fixed-length bytes representation. If the element
    /// is the identity element, return an error.
    fn from_element_slice<'a>(
        element_bits: impl Into<&'a GenericArray<u8, Self::ElemLen>>,
    ) -> Result<Self, InternalError> {
        let elem = Self::from_element_slice_unchecked(element_bits.into())?;

        if Self::ct_eq(&elem, &<Self as Group>::identity()).into() {
            // found the identity element
            return Err(InternalError::PointError);
        }

        Ok(elem)
    }

    /// Serializes the `self` group element
    fn to_arr(&self) -> GenericArray<u8, Self::ElemLen>;

    /// Get the base point for the group
    fn base_point() -> Self;

    /// Returns if the group element is equal to the identity (1)
    fn is_identity(&self) -> bool {
        self.ct_eq(&<Self as Group>::identity()).into()
    }

    /// Returns the identity group element
    fn identity() -> Self;

    /// Returns the scalar representing zero
    fn scalar_zero() -> Self::Scalar;

    /// Set the contents of self to the identity value
    fn zeroize(&mut self) {
        *self = <Self as Group>::identity();
    }
}

#[cfg(test)]
mod tests;

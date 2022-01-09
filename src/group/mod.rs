// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Defines the Group trait to specify the underlying prime order group

#[cfg(any(feature = "ristretto255", feature = "p256",))]
mod expand;
#[cfg(feature = "p256")]
mod p256;
#[cfg(feature = "ristretto255")]
mod ristretto;

use core::ops::{Add, Mul, Sub};

use digest::core_api::BlockSizeUser;
use digest::{Digest, FixedOutputReset};
use generic_array::typenum::U1;
use generic_array::{ArrayLength, GenericArray};
use rand_core::{CryptoRng, RngCore};
#[cfg(feature = "ristretto255")]
pub use ristretto::Ristretto255;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::{Error, Result};

/// A prime-order subgroup of a base field (EC, prime-order field ...). This
/// subgroup is noted additively — as in the draft RFC — in this trait.
pub trait Group {
    /// The ciphersuite identifier as dictated by
    /// <https://www.ietf.org/archive/id/draft-irtf-cfrg-voprf-05.txt>
    const SUITE_ID: u16;

    /// The type of group elements
    type Elem: Copy
        + Sized
        + ConstantTimeEq
        + Zeroize
        + for<'a> Mul<&'a Self::Scalar, Output = Self::Elem>
        + for<'a> Add<&'a Self::Elem, Output = Self::Elem>;

    /// The byte length necessary to represent group elements
    type ElemLen: ArrayLength<u8> + 'static;

    /// The type of base field scalars
    type Scalar: Zeroize
        + Copy
        + ConstantTimeEq
        + for<'a> Add<&'a Self::Scalar, Output = Self::Scalar>
        + for<'a> Sub<&'a Self::Scalar, Output = Self::Scalar>
        + for<'a> Mul<&'a Self::Scalar, Output = Self::Scalar>;

    /// The byte length necessary to represent scalars
    type ScalarLen: ArrayLength<u8> + 'static;

    /// transforms a password and domain separation tag (DST) into a curve point
    fn hash_to_curve<H: BlockSizeUser + Digest + FixedOutputReset, D: ArrayLength<u8> + Add<U1>>(
        msg: &[u8],
        dst: GenericArray<u8, D>,
    ) -> Result<Self::Elem>
    where
        <D as Add<U1>>::Output: ArrayLength<u8>;

    /// Hashes a slice of pseudo-random bytes to a scalar
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
        <D as Add<U1>>::Output: ArrayLength<u8>;

    /// Return a scalar from its fixed-length bytes representation. If the
    /// scalar is zero or invalid, then return an error.
    fn deserialize_scalar(scalar_bits: &GenericArray<u8, Self::ScalarLen>) -> Result<Self::Scalar>;

    /// picks a scalar at random
    fn random_nonzero_scalar<R: RngCore + CryptoRng>(rng: &mut R) -> Self::Scalar;

    /// Serializes a scalar to bytes
    fn scalar_as_bytes(scalar: Self::Scalar) -> GenericArray<u8, Self::ScalarLen>;

    /// The multiplicative inverse of this scalar
    fn scalar_invert(scalar: &Self::Scalar) -> Self::Scalar;

    /// Return an element from its fixed-length bytes representation. This is
    /// the unchecked version, which does not check for deserializing the
    /// identity element
    fn from_element_slice_unchecked(
        element_bits: &GenericArray<u8, Self::ElemLen>,
    ) -> Result<Self::Elem>;

    /// Return an element from its fixed-length bytes representation. If the
    /// element is the identity element, return an error.
    fn from_element_slice<'a>(
        element_bits: impl Into<&'a GenericArray<u8, Self::ElemLen>>,
    ) -> Result<Self::Elem> {
        let elem = Self::from_element_slice_unchecked(element_bits.into())?;

        if Self::Elem::ct_eq(&elem, &Self::identity()).into() {
            // found the identity element
            return Err(Error::PointError);
        }

        Ok(elem)
    }

    /// Serializes the `self` group element
    fn to_arr(elem: Self::Elem) -> GenericArray<u8, Self::ElemLen>;

    /// Get the base point for the group
    fn base_point() -> Self::Elem;

    /// Returns if the group element is equal to the identity (1)
    fn is_identity(elem: Self::Elem) -> bool {
        elem.ct_eq(&Self::identity()).into()
    }

    /// Returns the identity group element
    fn identity() -> Self::Elem;

    /// Returns the scalar representing zero
    fn scalar_zero() -> Self::Scalar;
}

#[cfg(test)]
mod tests;

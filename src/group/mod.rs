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

use crate::Result;

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
    fn random_scalar<R: RngCore + CryptoRng>(rng: &mut R) -> Self::Scalar;

    /// Serializes a scalar to bytes
    fn serialize_scalar(scalar: Self::Scalar) -> GenericArray<u8, Self::ScalarLen>;

    /// The multiplicative inverse of this scalar
    fn invert_scalar(scalar: Self::Scalar) -> Self::Scalar;

    /// Return an element from its fixed-length bytes representation. If the
    /// element is the identity element, return an error.
    fn deserialize_elem(element_bits: &GenericArray<u8, Self::ElemLen>) -> Result<Self::Elem>;

    /// Serializes the `self` group element
    fn serialize_elem(elem: Self::Elem) -> GenericArray<u8, Self::ElemLen>;

    /// Get the base point for the group
    fn base_elem() -> Self::Elem;

    /// Returns the identity group element
    fn identity_elem() -> Self::Elem;

    /// Returns the scalar representing zero
    #[cfg(test)]
    fn zero_scalar() -> Self::Scalar;
}

#[cfg(test)]
mod tests;

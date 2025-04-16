// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

//! Defines the Group trait to specify the underlying prime order group

mod elliptic_curve;
#[cfg(feature = "ristretto255")]
mod ristretto;

use core::ops::{Add, Mul, Sub};

use digest::core_api::BlockSizeUser;
use digest::{FixedOutput, HashMarker};
use hybrid_array::typenum::{IsLess, IsLessOrEqual, Sum, U256};
use hybrid_array::{Array, ArraySize};
use rand_core::{TryCryptoRng, TryRngCore};
#[cfg(feature = "ristretto255")]
pub use ristretto::Ristretto255;
use subtle::{Choice, ConstantTimeEq};
use zeroize::Zeroize;

use crate::{InternalError, Result};

/// A prime-order subgroup of a base field (EC, prime-order field ...). This
/// subgroup is noted additively — as in the RFC — in this trait.
pub trait Group
where
    // `VoprfClientLen`, `PoprfClientLen`, `VoprfServerLen`, `PoprfServerLen`
    Self::ScalarLen: Add<Self::ElemLen>,
    Sum<Self::ScalarLen, Self::ElemLen>: ArraySize,
    // `ProofLen`
    Self::ScalarLen: Add<Self::ScalarLen>,
    Sum<Self::ScalarLen, Self::ScalarLen>: ArraySize,
{
    /// The type of group elements
    type Elem: ConstantTimeEq
        + Copy
        + Zeroize
        + for<'a> Add<&'a Self::Elem, Output = Self::Elem>
        + for<'a> Mul<&'a Self::Scalar, Output = Self::Elem>;

    /// The byte length necessary to represent group elements
    type ElemLen: ArraySize + 'static;

    /// The type of base field scalars
    type Scalar: ConstantTimeEq
        + Copy
        + Zeroize
        + for<'a> Add<&'a Self::Scalar, Output = Self::Scalar>
        + for<'a> Mul<&'a Self::Scalar, Output = Self::Scalar>
        + for<'a> Sub<&'a Self::Scalar, Output = Self::Scalar>;

    /// The byte length necessary to represent scalars
    type ScalarLen: ArraySize + 'static;

    /// Transforms a password and domain separation tag (DST) into a curve point
    ///
    /// # Errors
    /// [`Error::Input`](crate::Error::Input) if the `input` is empty or longer
    /// then [`u16::MAX`].
    fn hash_to_curve<H>(input: &[&[u8]], dst: &[&[u8]]) -> Result<Self::Elem, InternalError>
    where
        H: BlockSizeUser + Default + FixedOutput + HashMarker,
        H::OutputSize: IsLess<U256> + IsLessOrEqual<H::BlockSize>;

    /// Hashes a slice of pseudo-random bytes to a scalar
    ///
    /// # Errors
    /// [`Error::Input`](crate::Error::Input) if the `input` is empty or longer
    /// then [`u16::MAX`].
    fn hash_to_scalar<H>(input: &[&[u8]], dst: &[&[u8]]) -> Result<Self::Scalar, InternalError>
    where
        H: BlockSizeUser + Default + FixedOutput + HashMarker,
        H::OutputSize: IsLess<U256> + IsLessOrEqual<H::BlockSize>;

    /// Get the base point for the group
    fn base_elem() -> Self::Elem;

    /// Returns the identity group element
    fn identity_elem() -> Self::Elem;

    /// Returns `true` if the element is equal to the identity element
    fn is_identity_elem(elem: Self::Elem) -> Choice {
        Self::identity_elem().ct_eq(&elem)
    }

    /// Serializes the `self` group element
    fn serialize_elem(elem: Self::Elem) -> Array<u8, Self::ElemLen>;

    /// Return an element from its fixed-length bytes representation. If the
    /// element is the identity element, return an error.
    ///
    /// # Errors
    /// [`Error::Deserialization`](crate::Error::Deserialization) if the element
    /// is not a valid point on the group or the identity element.
    fn deserialize_elem(element_bits: &[u8]) -> Result<Self::Elem>;

    /// picks a scalar at random
    ///
    /// # Errors
    /// Returns any errors from the supplied random generator.
    fn random_scalar<R: TryRngCore + TryCryptoRng>(rng: &mut R) -> Result<Self::Scalar, R::Error>;

    /// The multiplicative inverse of this scalar
    fn invert_scalar(scalar: Self::Scalar) -> Self::Scalar;

    /// Returns `true` if the scalar is zero.
    fn is_zero_scalar(scalar: Self::Scalar) -> Choice;

    /// Returns the scalar representing zero
    #[cfg(test)]
    fn zero_scalar() -> Self::Scalar;

    /// Serializes a scalar to bytes
    fn serialize_scalar(scalar: Self::Scalar) -> Array<u8, Self::ScalarLen>;

    /// Return a scalar from its fixed-length bytes representation. If the
    /// scalar is zero or invalid, then return an error.
    ///
    /// # Errors
    /// [`Error::Deserialization`](crate::Error::Deserialization) if the scalar
    /// is not a valid point on the group or zero.
    fn deserialize_scalar(scalar_bits: &[u8]) -> Result<Self::Scalar>;
}

#[cfg(test)]
mod tests;

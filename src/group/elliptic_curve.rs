// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

use core::ops::Add;

use digest::core_api::BlockSizeUser;
use digest::{FixedOutput, HashMarker};
use elliptic_curve::group::cofactor::CofactorGroup;
use elliptic_curve::hash2curve::{ExpandMsgXmd, FromOkm, GroupDigest};
use elliptic_curve::sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint};
use elliptic_curve::{
    AffinePoint, Field, FieldBytesSize, Group as _, ProjectivePoint, PublicKey, Scalar, SecretKey,
};
use hybrid_array::typenum::{IsLess, IsLessOrEqual, Sum, U256};
use hybrid_array::{Array, ArraySize};
use rand_core::{TryCryptoRng, TryRngCore};

use super::Group;
use crate::{Error, InternalError, Result};

type ElemLen<C> = <ScalarLen<C> as ModulusSize>::CompressedPointSize;
type ScalarLen<C> = FieldBytesSize<C>;

impl<C> Group for C
where
    C: GroupDigest,
    ProjectivePoint<Self>: CofactorGroup + ToEncodedPoint<Self>,
    ScalarLen<Self>: ModulusSize,
    AffinePoint<Self>: FromEncodedPoint<Self> + ToEncodedPoint<Self>,
    Scalar<Self>: FromOkm,
    // `VoprfClientLen`, `PoprfClientLen`, `VoprfServerLen`, `PoprfServerLen`
    ScalarLen<Self>: Add<ElemLen<Self>>,
    Sum<ScalarLen<Self>, ElemLen<Self>>: ArraySize,
    // `ProofLen`
    ScalarLen<Self>: Add<ScalarLen<Self>>,
    Sum<ScalarLen<Self>, ScalarLen<Self>>: ArraySize,
{
    type Elem = ProjectivePoint<Self>;

    type ElemLen = ElemLen<Self>;

    type Scalar = Scalar<Self>;

    type ScalarLen = ScalarLen<Self>;

    // Implements the `hash_to_curve()` function from
    // https://www.rfc-editor.org/rfc/rfc9380.html#section-3
    fn hash_to_curve<H>(input: &[&[u8]], dst: &[&[u8]]) -> Result<Self::Elem, InternalError>
    where
        H: BlockSizeUser + Default + FixedOutput + HashMarker,
        H::OutputSize: IsLess<U256> + IsLessOrEqual<H::BlockSize>,
    {
        Self::hash_from_bytes::<ExpandMsgXmd<H>>(input, dst).map_err(|_| InternalError::Input)
    }

    // Implements the `HashToScalar()` function
    fn hash_to_scalar<H>(input: &[&[u8]], dst: &[&[u8]]) -> Result<Self::Scalar, InternalError>
    where
        H: BlockSizeUser + Default + FixedOutput + HashMarker,
        H::OutputSize: IsLess<U256> + IsLessOrEqual<H::BlockSize>,
    {
        <Self as GroupDigest>::hash_to_scalar::<ExpandMsgXmd<H>>(input, dst)
            .map_err(|_| InternalError::Input)
    }

    fn base_elem() -> Self::Elem {
        ProjectivePoint::<Self>::generator()
    }

    fn identity_elem() -> Self::Elem {
        ProjectivePoint::<Self>::identity()
    }

    fn serialize_elem(elem: Self::Elem) -> Array<u8, Self::ElemLen> {
        let bytes = elem.to_encoded_point(true);
        let bytes = bytes.as_bytes();
        let mut result = Array::default();
        result[..bytes.len()].copy_from_slice(bytes);
        result
    }

    fn deserialize_elem(element_bits: &[u8]) -> Result<Self::Elem> {
        PublicKey::<Self>::from_sec1_bytes(element_bits)
            .map(|public_key| public_key.to_projective())
            .map_err(|_| Error::Deserialization)
    }

    fn random_scalar<R: TryRngCore + TryCryptoRng>(rng: &mut R) -> Result<Self::Scalar, R::Error> {
        Ok(*SecretKey::<Self>::try_from_rng(rng)?.to_nonzero_scalar())
    }

    fn invert_scalar(scalar: Self::Scalar) -> Self::Scalar {
        Option::from(scalar.invert()).unwrap()
    }

    fn is_zero_scalar(scalar: Self::Scalar) -> subtle::Choice {
        scalar.is_zero()
    }

    #[cfg(test)]
    fn zero_scalar() -> Self::Scalar {
        Scalar::<Self>::ZERO
    }

    fn serialize_scalar(scalar: Self::Scalar) -> Array<u8, Self::ScalarLen> {
        scalar.into()
    }

    fn deserialize_scalar(scalar_bits: &[u8]) -> Result<Self::Scalar> {
        SecretKey::<Self>::from_slice(scalar_bits)
            .map(|secret_key| *secret_key.to_nonzero_scalar())
            .map_err(|_| Error::Deserialization)
    }
}

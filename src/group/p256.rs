// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

#![allow(
    clippy::borrow_interior_mutable_const,
    clippy::declare_interior_mutable_const
)]

use digest::core_api::BlockSizeUser;
use digest::Digest;
use elliptic_curve::hash2curve::GroupDigest;
use elliptic_curve::hash2field::ExpandMsgXmd;
use elliptic_curve::sec1::ToEncodedPoint;
#[cfg(test)]
use elliptic_curve::Field;
use generic_array::sequence::Concat;
use generic_array::typenum::{IsLess, IsLessOrEqual, U256, U32, U33};
use generic_array::GenericArray;
use p256::{NistP256, ProjectivePoint, PublicKey, Scalar, SecretKey};
use rand_core::{CryptoRng, RngCore};

use super::Group;
use crate::group::{STR_HASH_TO_GROUP, STR_HASH_TO_SCALAR};
use crate::voprf::{self, Mode};
use crate::{Error, Result};

#[cfg(feature = "p256")]
impl Group for NistP256 {
    type Elem = ProjectivePoint;

    type ElemLen = U33;

    type Scalar = Scalar;

    type ScalarLen = U32;

    // Implements the `hash_to_curve()` function from
    // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-11#section-3
    fn hash_to_curve<H: BlockSizeUser + Digest>(msg: &[&[u8]], mode: Mode) -> Result<Self::Elem>
    where
        H::OutputSize: IsLess<U256> + IsLessOrEqual<H::BlockSize>,
    {
        let dst =
            GenericArray::from(STR_HASH_TO_GROUP).concat(voprf::get_context_string::<Self>(mode));

        Self::hash_from_bytes::<ExpandMsgXmd<H>>(msg, &dst).map_err(|_| Error::PointError)
    }

    // Implements the `HashToScalar()` function
    fn hash_to_scalar<H: BlockSizeUser + Digest>(
        input: &[&[u8]],
        mode: Mode,
    ) -> Result<Self::Scalar>
    where
        H::OutputSize: IsLess<U256> + IsLessOrEqual<H::BlockSize>,
    {
        let dst =
            GenericArray::from(STR_HASH_TO_SCALAR).concat(voprf::get_context_string::<Self>(mode));

        <Self as GroupDigest>::hash_to_scalar::<ExpandMsgXmd<H>>(input, &dst)
            .map_err(|_| Error::PointError)
    }

    fn base_elem() -> Self::Elem {
        ProjectivePoint::GENERATOR
    }

    fn identity_elem() -> Self::Elem {
        ProjectivePoint::IDENTITY
    }

    fn serialize_elem(elem: Self::Elem) -> GenericArray<u8, Self::ElemLen> {
        let bytes = elem.to_affine().to_encoded_point(true);
        let bytes = bytes.as_bytes();
        let mut result = GenericArray::default();
        result[..bytes.len()].copy_from_slice(bytes);
        result
    }

    fn deserialize_elem(element_bits: &GenericArray<u8, Self::ElemLen>) -> Result<Self::Elem> {
        PublicKey::from_sec1_bytes(element_bits)
            .map(|public_key| public_key.to_projective())
            .map_err(|_| Error::PointError)
    }

    fn random_scalar<R: RngCore + CryptoRng>(rng: &mut R) -> Self::Scalar {
        *SecretKey::random(rng).to_nonzero_scalar()
    }

    fn invert_scalar(scalar: Self::Scalar) -> Self::Scalar {
        Option::from(scalar.invert()).unwrap()
    }

    #[cfg(test)]
    fn zero_scalar() -> Self::Scalar {
        Scalar::zero()
    }

    fn serialize_scalar(scalar: Self::Scalar) -> GenericArray<u8, Self::ScalarLen> {
        scalar.into()
    }

    fn deserialize_scalar(scalar_bits: &GenericArray<u8, Self::ScalarLen>) -> Result<Self::Scalar> {
        SecretKey::from_be_bytes(scalar_bits)
            .map(|secret_key| *secret_key.to_nonzero_scalar())
            .map_err(|_| Error::ScalarError)
    }
}

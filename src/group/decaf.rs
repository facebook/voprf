// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

use ed448::{CompressedDecaf, DecafPoint, Scalar};
use elliptic_curve::bigint::{Encoding, NonZero, U448, U512};
use elliptic_curve::hash2curve::{ExpandMsg, ExpandMsgXof, Expander};
use hybrid_array::Array;
use hybrid_array::typenum::U56;
use rand_core::{TryCryptoRng, TryRngCore};
use subtle::ConstantTimeEq;

use super::Group;
use crate::{Error, InternalError, Result};

/// [`Group`] implementation for Decaf448.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Decaf448;

const WIDE_ORDER: NonZero<U512> = NonZero::<U512>::new_unwrap(U512::from_be_hex("00000000000000003fffffffffffffffffffffffffffffffffffffffffffffffffffffff7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f3"));
const ORDER: NonZero<U448> = NonZero::<U448>::new_unwrap(ed448::ORDER);

#[cfg(feature = "decaf448-ciphersuite")]
impl crate::CipherSuite for Decaf448 {
    const ID: &'static str = "decaf448-SHAKE256";

    type Group = Decaf448;

    type Hash = super::xof_fixed_wrapper::XofFixedWrapper<sha3::Shake256, hybrid_array::sizes::U64>;

    type ExpandMsg = ExpandMsgXof<Self::Hash>;
}

impl Group for Decaf448 {
    type Elem = DecafPoint;

    type ElemLen = U56;

    type Scalar = Scalar;

    type ScalarLen = U56;

    // Implements the `hash_to_ristretto255()` function from
    // https://www.rfc-editor.org/rfc/rfc9380.html#appendix-C
    fn hash_to_curve<X>(input: &[&[u8]], dst: &[&[u8]]) -> Result<Self::Elem, InternalError>
    where
        X: for<'a> ExpandMsg<'a>,
    {
        let mut uniform_bytes = [0; 112];
        X::expand_message(input, dst, 112)
            .map_err(|_| InternalError::Input)?
            .fill_bytes(&mut uniform_bytes);

        Ok(DecafPoint::from_uniform_bytes(&uniform_bytes))
    }

    // Implements the `HashToScalar()` function from
    // https://www.rfc-editor.org/rfc/rfc9497#section-4.2
    fn hash_to_scalar<X>(input: &[&[u8]], dst: &[&[u8]]) -> Result<Self::Scalar, InternalError>
    where
        X: for<'a> ExpandMsg<'a>,
    {
        let mut uniform_bytes = [0; 64];
        X::expand_message(input, dst, 64)
            .map_err(|_| InternalError::Input)?
            .fill_bytes(&mut uniform_bytes);
        let uniform_bytes = U512::from_le_slice(&uniform_bytes);

        let scalar = uniform_bytes.rem(&WIDE_ORDER);
        let scalar = Scalar::from_bytes(&scalar.to_le_bytes()[..56].try_into().unwrap());

        Ok(scalar)
    }

    fn base_elem() -> Self::Elem {
        DecafPoint::GENERATOR
    }

    fn identity_elem() -> Self::Elem {
        DecafPoint::IDENTITY
    }

    // serialization of a group element
    fn serialize_elem(elem: Self::Elem) -> Array<u8, Self::ElemLen> {
        elem.compress().0.into()
    }

    fn deserialize_elem(element_bits: &[u8]) -> Result<Self::Elem> {
        let result = element_bits
            .try_into()
            .map(CompressedDecaf)
            .map_err(|_| Error::Deserialization)?
            .decompress();
        Option::from(result)
            .filter(|point| point != &DecafPoint::IDENTITY)
            .ok_or(Error::Deserialization)
    }

    fn random_scalar<R: TryRngCore + TryCryptoRng>(rng: &mut R) -> Result<Self::Scalar, R::Error> {
        loop {
            let mut scalar_bytes = [0; 64];
            rng.try_fill_bytes(&mut scalar_bytes)?;
            let scalar_bytes = U512::from_le_slice(&scalar_bytes);
            let scalar = scalar_bytes.rem(&WIDE_ORDER);
            let scalar = Scalar::from_bytes(&scalar.to_le_bytes()[..56].try_into().unwrap());

            if scalar != Scalar::ZERO {
                break Ok(scalar);
            }
        }
    }

    fn invert_scalar(scalar: Self::Scalar) -> Self::Scalar {
        scalar.invert()
    }

    fn is_zero_scalar(scalar: Self::Scalar) -> subtle::Choice {
        scalar.ct_eq(&Scalar::ZERO)
    }

    #[cfg(test)]
    fn zero_scalar() -> Self::Scalar {
        Scalar::ZERO
    }

    fn serialize_scalar(scalar: Self::Scalar) -> Array<u8, Self::ScalarLen> {
        scalar.to_bytes().into()
    }

    fn deserialize_scalar(scalar_bits: &[u8]) -> Result<Self::Scalar> {
        scalar_bits
            .try_into()
            .ok()
            .map(U448::from_le_bytes)
            .map(|value| Scalar::from_bytes(&value.rem(&ORDER).to_le_bytes()))
            .filter(|scalar| scalar != &Scalar::ZERO)
            .ok_or(Error::Deserialization)
    }
}

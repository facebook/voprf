// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Handles the serialization of each of the components used in the VOPRF
//! protocol

use core::ops::Add;

use digest::core_api::BlockSizeUser;
use digest::OutputSizeUser;
use generic_array::sequence::Concat;
use generic_array::typenum::{IsLess, IsLessOrEqual, Sum, Unsigned, U256};
use generic_array::{ArrayLength, GenericArray};

use crate::{
    BlindedElement, CipherSuite, Error, EvaluationElement, Group, OprfClient, OprfServer,
    PoprfClient, PoprfServer, Proof, Result, VoprfClient, VoprfServer,
};

//////////////////////////////////////////////////////////
// Serialization and Deserialization for High-Level API //
// ==================================================== //
//////////////////////////////////////////////////////////

/// Length of [`NonVerifiableClient`] in bytes for serialization.
pub type NonVerifiableClientLen<CS> = <<CS as CipherSuite>::Group as Group>::ScalarLen;

impl<CS: CipherSuite> OprfClient<CS>
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
{
    /// Serialization into bytes
    pub fn serialize(&self) -> GenericArray<u8, NonVerifiableClientLen<CS>> {
        CS::Group::serialize_scalar(self.blind)
    }

    /// Deserialization from bytes
    ///
    /// # Errors
    /// [`Error::Deserialization`] if failed to deserialize `input`.
    pub fn deserialize(input: &[u8]) -> Result<Self> {
        let mut input = input.iter().copied();

        let blind = deserialize_scalar::<CS::Group, _>(&mut input)?;

        Ok(Self { blind })
    }
}

/// Length of [`VerifiableClient`] in bytes for serialization.
pub type VerifiableClientLen<CS> = Sum<
    <<CS as CipherSuite>::Group as Group>::ScalarLen,
    <<CS as CipherSuite>::Group as Group>::ElemLen,
>;

impl<CS: CipherSuite> VoprfClient<CS>
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
{
    /// Serialization into bytes
    pub fn serialize(&self) -> GenericArray<u8, VerifiableClientLen<CS>>
    where
        <CS::Group as Group>::ScalarLen: Add<<CS::Group as Group>::ElemLen>,
        VerifiableClientLen<CS>: ArrayLength<u8>,
    {
        <CS::Group as Group>::serialize_scalar(self.blind)
            .concat(<CS::Group as Group>::serialize_elem(self.blinded_element))
    }

    /// Deserialization from bytes
    ///
    /// # Errors
    /// [`Error::Deserialization`] if failed to deserialize `input`.
    pub fn deserialize(input: &[u8]) -> Result<Self> {
        let mut input = input.iter().copied();

        let blind = deserialize_scalar::<CS::Group, _>(&mut input)?;
        let blinded_element = deserialize_elem::<CS::Group, _>(&mut input)?;

        Ok(Self {
            blind,
            blinded_element,
        })
    }
}

impl<CS: CipherSuite> PoprfClient<CS>
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
{
    /// Serialization into bytes
    pub fn serialize(&self) -> GenericArray<u8, VerifiableClientLen<CS>>
    where
        <CS::Group as Group>::ScalarLen: Add<<CS::Group as Group>::ElemLen>,
        VerifiableClientLen<CS>: ArrayLength<u8>,
    {
        <CS::Group as Group>::serialize_scalar(self.blind)
            .concat(<CS::Group as Group>::serialize_elem(self.blinded_element))
    }

    /// Deserialization from bytes
    ///
    /// # Errors
    /// [`Error::Deserialization`] if failed to deserialize `input`.
    pub fn deserialize(input: &[u8]) -> Result<Self> {
        let mut input = input.iter().copied();

        let blind = deserialize_scalar::<CS::Group, _>(&mut input)?;
        let blinded_element = deserialize_elem::<CS::Group, _>(&mut input)?;

        Ok(Self {
            blind,
            blinded_element,
        })
    }
}

/// Length of [`NonVerifiableServer`] in bytes for serialization.
pub type NonVerifiableServerLen<CS> = <<CS as CipherSuite>::Group as Group>::ScalarLen;

impl<CS: CipherSuite> OprfServer<CS>
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
{
    /// Serialization into bytes
    pub fn serialize(&self) -> GenericArray<u8, NonVerifiableServerLen<CS>> {
        CS::Group::serialize_scalar(self.sk)
    }

    /// Deserialization from bytes
    ///
    /// # Errors
    /// [`Error::Deserialization`] if failed to deserialize `input`.
    pub fn deserialize(input: &[u8]) -> Result<Self> {
        let mut input = input.iter().copied();

        let sk = deserialize_scalar::<CS::Group, _>(&mut input)?;

        Ok(Self { sk })
    }
}

/// Length of [`VerifiableServer`] in bytes for serialization.
pub type VerifiableServerLen<CS> = Sum<
    <<CS as CipherSuite>::Group as Group>::ScalarLen,
    <<CS as CipherSuite>::Group as Group>::ElemLen,
>;

impl<CS: CipherSuite> VoprfServer<CS>
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
{
    /// Serialization into bytes
    pub fn serialize(&self) -> GenericArray<u8, VerifiableServerLen<CS>>
    where
        <CS::Group as Group>::ScalarLen: Add<<CS::Group as Group>::ElemLen>,
        VerifiableServerLen<CS>: ArrayLength<u8>,
    {
        CS::Group::serialize_scalar(self.sk).concat(CS::Group::serialize_elem(self.pk))
    }

    /// Deserialization from bytes
    ///
    /// # Errors
    /// [`Error::Deserialization`] if failed to deserialize `input`.
    pub fn deserialize(input: &[u8]) -> Result<Self> {
        let mut input = input.iter().copied();

        let sk = deserialize_scalar::<CS::Group, _>(&mut input)?;
        let pk = deserialize_elem::<CS::Group, _>(&mut input)?;

        Ok(Self { sk, pk })
    }
}

impl<CS: CipherSuite> PoprfServer<CS>
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
{
    /// Serialization into bytes
    pub fn serialize(&self) -> GenericArray<u8, VerifiableServerLen<CS>>
    where
        <CS::Group as Group>::ScalarLen: Add<<CS::Group as Group>::ElemLen>,
        VerifiableServerLen<CS>: ArrayLength<u8>,
    {
        CS::Group::serialize_scalar(self.sk).concat(CS::Group::serialize_elem(self.pk))
    }

    /// Deserialization from bytes
    ///
    /// # Errors
    /// [`Error::Deserialization`] if failed to deserialize `input`.
    pub fn deserialize(input: &[u8]) -> Result<Self> {
        let mut input = input.iter().copied();

        let sk = deserialize_scalar::<CS::Group, _>(&mut input)?;
        let pk = deserialize_elem::<CS::Group, _>(&mut input)?;

        Ok(Self { sk, pk })
    }
}

/// Length of [`Proof`] in bytes for serialization.
pub type ProofLen<CS> = Sum<
    <<CS as CipherSuite>::Group as Group>::ScalarLen,
    <<CS as CipherSuite>::Group as Group>::ScalarLen,
>;

impl<CS: CipherSuite> Proof<CS>
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
{
    /// Serialization into bytes
    pub fn serialize(&self) -> GenericArray<u8, ProofLen<CS>>
    where
        <CS::Group as Group>::ScalarLen: Add<<CS::Group as Group>::ScalarLen>,
        ProofLen<CS>: ArrayLength<u8>,
    {
        CS::Group::serialize_scalar(self.c_scalar)
            .concat(CS::Group::serialize_scalar(self.s_scalar))
    }

    /// Deserialization from bytes
    ///
    /// # Errors
    /// [`Error::Deserialization`] if failed to deserialize `input`.
    pub fn deserialize(input: &[u8]) -> Result<Self> {
        let mut input = input.iter().copied();

        let c_scalar = deserialize_scalar::<CS::Group, _>(&mut input)?;
        let s_scalar = deserialize_scalar::<CS::Group, _>(&mut input)?;

        Ok(Proof { c_scalar, s_scalar })
    }
}

/// Length of [`BlindedElement`] in bytes for serialization.
pub type BlindedElementLen<CS> = <<CS as CipherSuite>::Group as Group>::ElemLen;

impl<CS: CipherSuite> BlindedElement<CS>
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
{
    /// Serialization into bytes
    pub fn serialize(&self) -> GenericArray<u8, BlindedElementLen<CS>> {
        CS::Group::serialize_elem(self.0)
    }

    /// Deserialization from bytes
    ///
    /// # Errors
    /// [`Error::Deserialization`] if failed to deserialize `input`.
    pub fn deserialize(input: &[u8]) -> Result<Self> {
        let mut input = input.iter().copied();

        let value = deserialize_elem::<CS::Group, _>(&mut input)?;

        Ok(Self(value))
    }
}

/// Length of [`EvaluationElement`] in bytes for serialization.
pub type EvaluationElementLen<CS> = <<CS as CipherSuite>::Group as Group>::ElemLen;

impl<CS: CipherSuite> EvaluationElement<CS>
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
{
    /// Serialization into bytes
    pub fn serialize(&self) -> GenericArray<u8, EvaluationElementLen<CS>> {
        CS::Group::serialize_elem(self.0)
    }

    /// Deserialization from bytes
    ///
    /// # Errors
    /// [`Error::Deserialization`] if failed to deserialize `input`.
    pub fn deserialize(input: &[u8]) -> Result<Self> {
        let mut input = input.iter().copied();

        let value = deserialize_elem::<CS::Group, _>(&mut input)?;

        Ok(Self(value))
    }
}

fn deserialize_elem<G: Group, I: Iterator<Item = u8>>(input: &mut I) -> Result<G::Elem> {
    let input = input.by_ref().take(G::ElemLen::USIZE);
    GenericArray::<_, G::ElemLen>::from_exact_iter(input)
        .ok_or(Error::Deserialization)
        .and_then(|bytes| G::deserialize_elem(&bytes))
}

fn deserialize_scalar<G: Group, I: Iterator<Item = u8>>(input: &mut I) -> Result<G::Scalar> {
    let input = input.by_ref().take(G::ScalarLen::USIZE);
    GenericArray::<_, G::ScalarLen>::from_exact_iter(input)
        .ok_or(Error::Deserialization)
        .and_then(|bytes| G::deserialize_scalar(&bytes))
}

#[cfg(feature = "serde")]
pub(crate) mod serde {
    use core::marker::PhantomData;

    use generic_array::GenericArray;
    use serde::de::{Deserializer, Error};
    use serde::ser::Serializer;
    use serde::{Deserialize, Serialize};

    use crate::Group;

    pub(crate) struct Element<G: Group>(PhantomData<G>);

    impl<'de, G: Group> Element<G> {
        pub(crate) fn deserialize<D>(deserializer: D) -> Result<G::Elem, D::Error>
        where
            D: Deserializer<'de>,
        {
            GenericArray::<_, G::ElemLen>::deserialize(deserializer)
                .and_then(|bytes| G::deserialize_elem(&bytes).map_err(D::Error::custom))
        }

        pub(crate) fn serialize<S>(self_: &G::Elem, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            G::serialize_elem(*self_).serialize(serializer)
        }
    }

    pub(crate) struct Scalar<G: Group>(PhantomData<G>);

    impl<'de, G: Group> Scalar<G> {
        pub(crate) fn deserialize<D>(deserializer: D) -> Result<G::Scalar, D::Error>
        where
            D: Deserializer<'de>,
        {
            GenericArray::<_, G::ScalarLen>::deserialize(deserializer)
                .and_then(|bytes| G::deserialize_scalar(&bytes).map_err(D::Error::custom))
        }

        pub(crate) fn serialize<S>(self_: &G::Scalar, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            G::serialize_scalar(*self_).serialize(serializer)
        }
    }
}

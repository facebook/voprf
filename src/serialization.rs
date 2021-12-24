// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Handles the serialization of each of the components used in the VOPRF
//! protocol

use core::marker::PhantomData;
use core::ops::Add;

use digest::core_api::BlockSizeUser;
use digest::{Digest, FixedOutputReset};
use generic_array::sequence::Concat;
use generic_array::typenum::Sum;
use generic_array::{ArrayLength, GenericArray};

use crate::{
    BlindedElement, Error, EvaluationElement, Group, NonVerifiableClient, NonVerifiableServer,
    Proof, Result, VerifiableClient, VerifiableServer,
};

//////////////////////////////////////////////////////////
// Serialization and Deserialization for High-Level API //
// ==================================================== //
//////////////////////////////////////////////////////////

impl<G: Group, H: BlockSizeUser + Digest + FixedOutputReset> NonVerifiableClient<G, H> {
    /// Serialization into bytes
    pub fn serialize(&self) -> GenericArray<u8, G::ScalarLen> {
        G::scalar_as_bytes(self.blind)
    }

    /// Deserialization from bytes
    pub fn deserialize(input: &[u8]) -> Result<Self> {
        let mut input = input.iter().copied();

        let blind = G::from_scalar_slice(&deserialize(&mut input)?)?;

        Ok(Self {
            blind,
            hash: PhantomData,
        })
    }
}

impl<G: Group, H: BlockSizeUser + Digest + FixedOutputReset> VerifiableClient<G, H> {
    /// Serialization into bytes
    pub fn serialize(&self) -> GenericArray<u8, Sum<G::ScalarLen, G::ElemLen>>
    where
        G::ScalarLen: Add<G::ElemLen>,
        Sum<G::ScalarLen, G::ElemLen>: ArrayLength<u8>,
    {
        G::scalar_as_bytes(self.blind).concat(self.blinded_element.to_arr())
    }

    /// Deserialization from bytes
    pub fn deserialize(input: &[u8]) -> Result<Self> {
        let mut input = input.iter().copied();

        let blind = G::from_scalar_slice(&deserialize(&mut input)?)?;
        let blinded_element = G::from_element_slice(&deserialize(&mut input)?)?;

        Ok(Self {
            blind,
            blinded_element,
            hash: PhantomData,
        })
    }
}

impl<G: Group, H: BlockSizeUser + Digest + FixedOutputReset> NonVerifiableServer<G, H> {
    /// Serialization into bytes
    pub fn serialize(&self) -> GenericArray<u8, G::ScalarLen> {
        G::scalar_as_bytes(self.sk)
    }

    /// Deserialization from bytes
    pub fn deserialize(input: &[u8]) -> Result<Self> {
        let mut input = input.iter().copied();

        let sk = G::from_scalar_slice(&deserialize(&mut input)?)?;

        Ok(Self {
            sk,
            hash: PhantomData,
        })
    }
}

impl<G: Group, H: BlockSizeUser + Digest + FixedOutputReset> VerifiableServer<G, H> {
    /// Serialization into bytes
    pub fn serialize(&self) -> GenericArray<u8, Sum<G::ScalarLen, G::ElemLen>>
    where
        G::ScalarLen: Add<G::ElemLen>,
        Sum<G::ScalarLen, G::ElemLen>: ArrayLength<u8>,
    {
        G::scalar_as_bytes(self.sk).concat(self.pk.to_arr())
    }

    /// Deserialization from bytes
    pub fn deserialize(input: &[u8]) -> Result<Self> {
        let mut input = input.iter().copied();

        let sk = G::from_scalar_slice(&deserialize(&mut input)?)?;
        let pk = G::from_element_slice(&deserialize(&mut input)?)?;

        Ok(Self {
            sk,
            pk,
            hash: PhantomData,
        })
    }
}

impl<G: Group, H: BlockSizeUser + Digest + FixedOutputReset> Proof<G, H> {
    /// Serialization into bytes
    pub fn serialize(&self) -> GenericArray<u8, Sum<G::ScalarLen, G::ScalarLen>>
    where
        G::ScalarLen: Add<G::ScalarLen>,
        Sum<G::ScalarLen, G::ScalarLen>: ArrayLength<u8>,
    {
        G::scalar_as_bytes(self.c_scalar).concat(G::scalar_as_bytes(self.s_scalar))
    }

    /// Deserialization from bytes
    pub fn deserialize(input: &[u8]) -> Result<Self> {
        let mut input = input.iter().copied();

        let c_scalar = G::from_scalar_slice(&deserialize(&mut input)?)?;
        let s_scalar = G::from_scalar_slice(&deserialize(&mut input)?)?;

        Ok(Proof {
            c_scalar,
            s_scalar,
            hash: PhantomData,
        })
    }
}

impl<G: Group, H: BlockSizeUser + Digest + FixedOutputReset> BlindedElement<G, H> {
    /// Serialization into bytes
    pub fn serialize(&self) -> GenericArray<u8, G::ElemLen> {
        self.value.to_arr()
    }

    /// Deserialization from bytes
    pub fn deserialize(input: &[u8]) -> Result<Self> {
        let mut input = input.iter().copied();

        let value = G::from_element_slice(&deserialize(&mut input)?)?;

        Ok(Self {
            value,
            hash: PhantomData,
        })
    }
}

impl<G: Group, H: BlockSizeUser + Digest + FixedOutputReset> EvaluationElement<G, H> {
    /// Serialization into bytes
    pub fn serialize(&self) -> GenericArray<u8, G::ElemLen> {
        self.value.to_arr()
    }

    /// Deserialization from bytes
    pub fn deserialize(input: &[u8]) -> Result<Self> {
        let mut input = input.iter().copied();

        let value = G::from_element_slice(&deserialize(&mut input)?)?;

        Ok(Self {
            value,
            hash: PhantomData,
        })
    }
}

fn deserialize<L: ArrayLength<u8>>(
    input: &mut impl Iterator<Item = u8>,
) -> Result<GenericArray<u8, L>> {
    let input = input.by_ref().take(L::USIZE);
    GenericArray::from_exact_iter(input).ok_or(Error::SizeError)
}

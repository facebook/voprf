// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Handles the serialization of each of the components used
//! in the VOPRF protocol

use crate::{
    errors::InternalError,
    group::Group,
    voprf::{
        BlindedElement, EvaluationElement, NonVerifiableClient, NonVerifiableServer, Proof,
        VerifiableClient, VerifiableServer,
    },
};
use alloc::vec::Vec;
use core::marker::PhantomData;
use digest::{BlockInput, Digest};
use generic_array::{typenum::Unsigned, ArrayLength, GenericArray};

//////////////////////////////////////////////////////////
// Serialization and Deserialization for High-Level API //
// ==================================================== //
//////////////////////////////////////////////////////////

impl<G: Group, H: BlockInput + Digest> NonVerifiableClient<G, H> {
    /// Serialization into bytes
    pub fn serialize(&self) -> Vec<u8> {
        [G::scalar_as_bytes(self.blind).as_slice(), &self.data].concat()
    }

    /// Deserialization from bytes
    pub fn deserialize(input: &[u8]) -> Result<Self, InternalError> {
        let scalar_len = <G as Group>::ScalarLen::USIZE;
        if input.len() < scalar_len {
            return Err(InternalError::SizeError);
        }

        let blind = G::from_scalar_slice(&input[..scalar_len])?;
        let data = input[scalar_len..].to_vec();

        Ok(Self {
            blind,
            data,
            hash: PhantomData,
        })
    }
}

impl<G: Group, H: BlockInput + Digest> VerifiableClient<G, H> {
    /// Serialization into bytes
    pub fn serialize(&self) -> Vec<u8> {
        [
            G::scalar_as_bytes(self.blind).as_slice(),
            &self.blinded_element.to_arr(),
            &self.data,
        ]
        .concat()
    }

    /// Deserialization from bytes
    pub fn deserialize(input: &[u8]) -> Result<Self, InternalError> {
        let scalar_len = <G as Group>::ScalarLen::USIZE;
        let elem_len = <G as Group>::ElemLen::USIZE;
        if input.len() < scalar_len + elem_len {
            return Err(InternalError::SizeError);
        }

        let blind = G::from_scalar_slice(&input[..scalar_len])?;
        let blinded_element = G::from_element_slice(&input[scalar_len..scalar_len + elem_len])?;
        let data = input[scalar_len + elem_len..].to_vec();

        Ok(Self {
            blind,
            blinded_element,
            data,
            hash: PhantomData,
        })
    }
}

impl<G: Group, H: BlockInput + Digest> NonVerifiableServer<G, H> {
    /// Serialization into bytes
    pub fn serialize(&self) -> Vec<u8> {
        G::scalar_as_bytes(self.sk).to_vec()
    }

    /// Deserialization from bytes
    pub fn deserialize(input: &[u8]) -> Result<Self, InternalError> {
        let scalar_len = <G as Group>::ScalarLen::USIZE;
        if input.len() != scalar_len {
            return Err(InternalError::SizeError);
        }

        let sk = G::from_scalar_slice(input)?;

        Ok(Self {
            sk,
            hash: PhantomData,
        })
    }
}

impl<G: Group, H: BlockInput + Digest> VerifiableServer<G, H> {
    /// Serialization into bytes
    pub fn serialize(&self) -> Vec<u8> {
        [G::scalar_as_bytes(self.sk).as_slice(), &self.pk.to_arr()].concat()
    }

    /// Deserialization from bytes
    pub fn deserialize(input: &[u8]) -> Result<Self, InternalError> {
        let scalar_len = <G as Group>::ScalarLen::USIZE;
        let elem_len = <G as Group>::ElemLen::USIZE;
        if input.len() != scalar_len + elem_len {
            return Err(InternalError::SizeError);
        }

        let sk = G::from_scalar_slice(&input[..scalar_len])?;
        let pk = G::from_element_slice(&input[scalar_len..])?;

        Ok(Self {
            sk,
            pk,
            hash: PhantomData,
        })
    }
}

impl<G: Group, H: BlockInput + Digest> Proof<G, H> {
    /// Serialization into bytes
    pub fn serialize(&self) -> Vec<u8> {
        [
            G::scalar_as_bytes(self.c_scalar),
            G::scalar_as_bytes(self.s_scalar),
        ]
        .concat()
    }

    /// Deserialization from bytes
    pub fn deserialize(input: &[u8]) -> Result<Self, InternalError> {
        let scalar_len = <G as Group>::ScalarLen::USIZE;
        if input.len() < scalar_len + scalar_len {
            return Err(InternalError::SizeError);
        }
        Ok(Proof {
            c_scalar: G::from_scalar_slice(&input[..scalar_len])?,
            s_scalar: G::from_scalar_slice(&input[scalar_len..])?,
            hash: PhantomData,
        })
    }
}

impl<G: Group, H: BlockInput + Digest> BlindedElement<G, H> {
    /// Serialization into bytes
    pub fn serialize(&self) -> Vec<u8> {
        self.value.to_arr().to_vec()
    }

    /// Deserialization from bytes
    pub fn deserialize(input: &[u8]) -> Result<Self, InternalError> {
        Ok(Self {
            value: G::from_element_slice(input)?,
            hash: PhantomData,
        })
    }
}

impl<G: Group, H: BlockInput + Digest> EvaluationElement<G, H> {
    /// Serialization into bytes
    pub fn serialize(&self) -> Vec<u8> {
        self.value.to_arr().to_vec()
    }

    /// Deserialization from bytes
    pub fn deserialize(input: &[u8]) -> Result<Self, InternalError> {
        Ok(Self {
            value: G::from_element_slice(input)?,
            hash: PhantomData,
        })
    }
}

//////////////////////
// Helper Functions //
// ================ //
//////////////////////

// Corresponds to the I2OSP() function from RFC8017
pub(crate) fn i2osp<L: ArrayLength<u8>>(
    input: usize,
) -> Result<GenericArray<u8, L>, InternalError> {
    const SIZEOF_USIZE: usize = core::mem::size_of::<usize>();

    // Check if input >= 256^length
    if (SIZEOF_USIZE as u32 - input.leading_zeros() / 8) > L::U32 {
        return Err(InternalError::SerializationError);
    }

    if L::USIZE <= SIZEOF_USIZE {
        return Ok(GenericArray::clone_from_slice(
            &input.to_be_bytes()[SIZEOF_USIZE - L::USIZE..],
        ));
    }

    let mut output = GenericArray::default();
    output[L::USIZE - SIZEOF_USIZE..L::USIZE].copy_from_slice(&input.to_be_bytes());
    Ok(output)
}

// Computes I2OSP(len(input), max_bytes) || input
pub(crate) fn serialize<L: ArrayLength<u8>>(input: &[u8]) -> Result<Vec<u8>, InternalError> {
    Ok([&i2osp::<L>(input.len())?, input].concat())
}

#[cfg(test)]
mod unit_tests {
    use super::*;
    use generic_array::typenum::{U1, U2};

    // Test the error condition for I2OSP
    #[test]
    fn test_i2osp_err_check() {
        assert!(i2osp::<U1>(0).is_ok());

        assert!(i2osp::<U1>(255).is_ok());
        assert!(i2osp::<U1>(256).is_err());
        assert!(i2osp::<U1>(257).is_err());

        assert!(i2osp::<U2>(256 * 256 - 1).is_ok());
        assert!(i2osp::<U2>(256 * 256).is_err());
        assert!(i2osp::<U2>(256 * 256 + 1).is_err());
    }
}

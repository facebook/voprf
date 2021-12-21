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
use generic_array::typenum::Unsigned;

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
        let scalar_len = G::ScalarLen::USIZE;
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
        let scalar_len = G::ScalarLen::USIZE;
        let elem_len = G::ElemLen::USIZE;
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
        let scalar_len = G::ScalarLen::USIZE;
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
        let scalar_len = G::ScalarLen::USIZE;
        let elem_len = G::ElemLen::USIZE;
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
        let scalar_len = G::ScalarLen::USIZE;
        if input.len() != scalar_len + scalar_len {
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
        let elem_len = G::ElemLen::USIZE;
        if input.len() != elem_len {
            return Err(InternalError::SizeError);
        }
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
        let elem_len = G::ElemLen::USIZE;
        if input.len() != elem_len {
            return Err(InternalError::SizeError);
        }
        Ok(Self {
            value: G::from_element_slice(input)?,
            hash: PhantomData,
        })
    }
}

/////////////////////////////////////////////
// Serde implementation for High-Level API //
// ======================================= //
/////////////////////////////////////////////

/// Macro used for deriving `serde`'s `Serialize` and `Deserialize` traits.
macro_rules! impl_serialize_and_deserialize_for {
    ($item:ident) => {
        #[cfg(feature = "serde")]
        impl<G: Group, H: BlockInput + Digest> serde::Serialize for $item<G, H> {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                serializer.serialize_bytes(&self.serialize())
            }
        }

        #[cfg(feature = "serde")]
        impl<'de, G: Group, H: BlockInput + Digest> serde::Deserialize<'de> for $item<G, H> {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                use serde::de::Error;

                struct ByteVisitor<G: Group, H: BlockInput + Digest>(core::marker::PhantomData<(G, H)>);

                impl<'de, G: Group, H: BlockInput + Digest> serde::de::Visitor<'de> for ByteVisitor<G, H> {
                    type Value = $item<G, H>;

                    fn expecting(
                        &self,
                        formatter: &mut core::fmt::Formatter,
                    ) -> core::fmt::Result {
                        formatter.write_str(core::concat!(
                            "the byte representation of a ",
                            core::stringify!($item)
                        ))
                    }

                    fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E>
                    where
                        E: Error,
                    {
                        $item::<G, H>::deserialize(value).map_err(|_| {
                            Error::invalid_value(
                                serde::de::Unexpected::Bytes(value),
                                &core::concat!(
                                    "invalid byte sequence for ",
                                    core::stringify!($item)
                                ),
                            )
                        })
                    }
                }

                deserializer
                    .deserialize_bytes(ByteVisitor::<G, H>(core::marker::PhantomData))
                    .map_err(Error::custom)
            }
        }
    };
}

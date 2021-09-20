// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! Handles the serialization of each of the components used
//! in the VOPRF protocol

use crate::{
    ciphersuite::CipherSuite,
    errors::InternalError,
    group::Group,
    voprf::{
        BlindedElement, EvaluationElement, NonVerifiableClient, NonVerifiableServer, Proof,
        VerifiableClient, VerifiableServer,
    },
};
use alloc::vec::Vec;
use generic_array::{typenum::Unsigned, GenericArray};

/// Inner macro used for deriving `serde`'s `Serialize` and `Deserialize` traits.
macro_rules! impl_serialize_and_deserialize_for {
    ($t:ident) => {
        #[cfg(feature = "serialize")]
        impl<CS: CipherSuite> serde::Serialize for $t<CS> {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                if serializer.is_human_readable() {
                    serializer.serialize_str(&base64::encode(&self.serialize()))
                } else {
                    serializer.serialize_bytes(&self.serialize())
                }
            }
        }

        #[cfg(feature = "serialize")]
        impl<'de, CS: CipherSuite> serde::Deserialize<'de> for $t<CS> {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                if deserializer.is_human_readable() {
                    let s = <&str>::deserialize(deserializer)?;
                    $t::<CS>::deserialize(&base64::decode(s).map_err(serde::de::Error::custom)?)
                        .map_err(serde::de::Error::custom)
                } else {
                    struct ByteVisitor<CS: CipherSuite> {
                        marker: core::marker::PhantomData<CS>,
                    }
                    impl<'de, CS: CipherSuite> serde::de::Visitor<'de> for ByteVisitor<CS> {
                        type Value = $t<CS>;
                        fn expecting(
                            &self,
                            formatter: &mut core::fmt::Formatter,
                        ) -> core::fmt::Result {
                            formatter.write_str(core::concat!(
                                "the byte representation of a ",
                                core::stringify!($t)
                            ))
                        }

                        fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E>
                        where
                            E: serde::de::Error,
                        {
                            $t::<CS>::deserialize(value).map_err(|_| {
                                serde::de::Error::invalid_value(
                                    serde::de::Unexpected::Bytes(value),
                                    &core::concat!(
                                        "invalid byte sequence for ",
                                        core::stringify!($t)
                                    ),
                                )
                            })
                        }
                    }
                    deserializer.deserialize_bytes(ByteVisitor::<CS> {
                        marker: core::marker::PhantomData,
                    })
                }
            }
        }
    };
}

//////////////////////////////////////////////////////////
// Serialization and Deserialization for High-Level API //
// ==================================================== //
//////////////////////////////////////////////////////////

impl_serialize_and_deserialize_for!(NonVerifiableClient);

impl<CS: CipherSuite> NonVerifiableClient<CS> {
    /// Serialization into bytes
    pub fn serialize(&self) -> Vec<u8> {
        [
            CS::Group::scalar_as_bytes(self.blind).to_vec(),
            self.data.clone(),
        ]
        .concat()
    }

    /// Deserialization from bytes
    pub fn deserialize(input: &[u8]) -> Result<Self, InternalError> {
        let scalar_len = <CS::Group as Group>::ScalarLen::USIZE;
        if input.len() < scalar_len {
            return Err(InternalError::SizeError);
        }

        let blind = CS::Group::from_scalar_slice(GenericArray::from_slice(&input[..scalar_len]))?;
        let data = input[scalar_len..].to_vec();

        Ok(Self { blind, data })
    }
}

impl_serialize_and_deserialize_for!(VerifiableClient);

impl<CS: CipherSuite> VerifiableClient<CS> {
    /// Serialization into bytes
    pub fn serialize(&self) -> Vec<u8> {
        [
            CS::Group::scalar_as_bytes(self.blind).to_vec(),
            self.blinded_element.to_arr().to_vec(),
            self.data.clone(),
        ]
        .concat()
    }

    /// Deserialization from bytes
    pub fn deserialize(input: &[u8]) -> Result<Self, InternalError> {
        let scalar_len = <CS::Group as Group>::ScalarLen::USIZE;
        let elem_len = <CS::Group as Group>::ElemLen::USIZE;
        if input.len() < scalar_len + elem_len {
            return Err(InternalError::SizeError);
        }

        let blind = CS::Group::from_scalar_slice(GenericArray::from_slice(&input[..scalar_len]))?;
        let blinded_element = CS::Group::from_element_slice(GenericArray::from_slice(
            &input[scalar_len..scalar_len + elem_len],
        ))?;
        let data = input[scalar_len + elem_len..].to_vec();

        Ok(Self {
            blind,
            blinded_element,
            data,
        })
    }
}

impl_serialize_and_deserialize_for!(NonVerifiableServer);

impl<CS: CipherSuite> NonVerifiableServer<CS> {
    /// Serialization into bytes
    pub fn serialize(&self) -> Vec<u8> {
        CS::Group::scalar_as_bytes(self.sk).to_vec()
    }

    /// Deserialization from bytes
    pub fn deserialize(input: &[u8]) -> Result<Self, InternalError> {
        let scalar_len = <CS::Group as Group>::ScalarLen::USIZE;
        if input.len() != scalar_len {
            return Err(InternalError::SizeError);
        }

        let sk = CS::Group::from_scalar_slice(GenericArray::from_slice(input))?;

        Ok(Self { sk })
    }
}

impl_serialize_and_deserialize_for!(VerifiableServer);

impl<CS: CipherSuite> VerifiableServer<CS> {
    /// Serialization into bytes
    pub fn serialize(&self) -> Vec<u8> {
        [
            CS::Group::scalar_as_bytes(self.sk).to_vec(),
            self.pk.to_arr().to_vec(),
        ]
        .concat()
    }

    /// Deserialization from bytes
    pub fn deserialize(input: &[u8]) -> Result<Self, InternalError> {
        let scalar_len = <CS::Group as Group>::ScalarLen::USIZE;
        let elem_len = <CS::Group as Group>::ElemLen::USIZE;
        if input.len() != scalar_len + elem_len {
            return Err(InternalError::SizeError);
        }

        let sk = CS::Group::from_scalar_slice(GenericArray::from_slice(&input[..scalar_len]))?;
        let pk = CS::Group::from_element_slice(GenericArray::from_slice(&input[scalar_len..]))?;

        Ok(Self { sk, pk })
    }
}

impl_serialize_and_deserialize_for!(Proof);

impl<CS: CipherSuite> Proof<CS> {
    /// Serialization into bytes
    pub fn serialize(&self) -> Vec<u8> {
        [
            CS::Group::scalar_as_bytes(self.c_scalar),
            CS::Group::scalar_as_bytes(self.s_scalar),
        ]
        .concat()
    }

    /// Deserialization from bytes
    pub fn deserialize(input: &[u8]) -> Result<Self, InternalError> {
        let scalar_len = <CS::Group as Group>::ScalarLen::USIZE;
        if input.len() < scalar_len + scalar_len {
            return Err(InternalError::SizeError);
        }
        Ok(Proof {
            c_scalar: CS::Group::from_scalar_slice(GenericArray::from_slice(&input[..scalar_len]))?,
            s_scalar: CS::Group::from_scalar_slice(GenericArray::from_slice(&input[scalar_len..]))?,
        })
    }
}

impl_serialize_and_deserialize_for!(BlindedElement);

impl<CS: CipherSuite> BlindedElement<CS> {
    /// Serialization into bytes
    pub fn serialize(&self) -> Vec<u8> {
        self.0.to_arr().to_vec()
    }

    /// Deserialization from bytes
    pub fn deserialize(input: &[u8]) -> Result<Self, InternalError> {
        Ok(Self(CS::Group::from_element_slice(
            GenericArray::from_slice(input),
        )?))
    }
}

impl_serialize_and_deserialize_for!(EvaluationElement);

impl<CS: CipherSuite> EvaluationElement<CS> {
    /// Serialization into bytes
    pub fn serialize(&self) -> Vec<u8> {
        self.0.to_arr().to_vec()
    }

    /// Deserialization from bytes
    pub fn deserialize(input: &[u8]) -> Result<Self, InternalError> {
        Ok(Self(CS::Group::from_element_slice(
            GenericArray::from_slice(input),
        )?))
    }
}

//////////////////////
// Helper Functions //
// ================ //
//////////////////////

// Corresponds to the I2OSP() function from RFC8017
pub(crate) fn i2osp(input: usize, length: usize) -> Result<alloc::vec::Vec<u8>, InternalError> {
    let sizeof_usize = core::mem::size_of::<usize>();

    // Check if input >= 256^length
    if (sizeof_usize as u32 - input.leading_zeros() / 8) > length as u32 {
        return Err(InternalError::SerializationError);
    }

    if length <= sizeof_usize {
        return Ok((&input.to_be_bytes()[sizeof_usize - length..]).to_vec());
    }

    let mut output = alloc::vec![0u8; length];
    output.splice(
        length - sizeof_usize..length,
        input.to_be_bytes().iter().cloned(),
    );
    Ok(output)
}

// Computes I2OSP(len(input), max_bytes) || input
pub(crate) fn serialize(input: &[u8], max_bytes: usize) -> Result<Vec<u8>, InternalError> {
    Ok([&i2osp(input.len(), max_bytes)?, input].concat())
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    // Test the error condition for I2OSP
    #[test]
    fn test_i2osp_err_check() {
        assert!(i2osp(0, 1).is_ok());

        assert!(i2osp(255, 1).is_ok());
        assert!(i2osp(256, 1).is_err());
        assert!(i2osp(257, 1).is_err());

        assert!(i2osp(256 * 256 - 1, 2).is_ok());
        assert!(i2osp(256 * 256, 2).is_err());
        assert!(i2osp(256 * 256 + 1, 2).is_err());
    }
}

// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Helper functions

use core::convert::TryFrom;

use generic_array::typenum::{IsLess, U1, U2, U256};
use generic_array::{ArrayLength, GenericArray};

use crate::InternalError;

pub(crate) fn i2osp_1(input: usize) -> Result<GenericArray<u8, U1>, InternalError> {
    u8::try_from(input)
        .map(|input| input.to_be_bytes().into())
        .map_err(|_| InternalError::I2osp)
}

pub(crate) fn i2osp_2(input: usize) -> Result<GenericArray<u8, U2>, InternalError> {
    u16::try_from(input)
        .map(|input| input.to_be_bytes().into())
        .map_err(|_| InternalError::I2osp)
}

pub(crate) fn i2osp_2_array<L: ArrayLength<u8> + IsLess<U256>>(
    _: &GenericArray<u8, L>,
) -> GenericArray<u8, U2> {
    L::U16.to_be_bytes().into()
}

#[cfg(test)]
mod unit_tests {
    use proptest::collection::vec;
    use proptest::prelude::*;

    use crate::{
        BlindedElement, EvaluationElement, NonVerifiableClient, NonVerifiableServer, Proof,
        VerifiableClient, VerifiableServer,
    };

    macro_rules! test_deserialize {
        ($item:ident, $bytes:ident) => {
            #[cfg(feature = "ristretto255")]
            {
                let _ = $item::<crate::Ristretto255>::deserialize(&$bytes[..]);
            }

            let _ = $item::<p256::NistP256>::deserialize(&$bytes[..]);
        };
    }

    proptest! {
        #[test]
        fn test_nocrash_nonverifiable_client(bytes in vec(any::<u8>(), 0..200)) {
            test_deserialize!(NonVerifiableClient, bytes);
        }

        #[test]
        fn test_nocrash_verifiable_client(bytes in vec(any::<u8>(), 0..200)) {
            test_deserialize!(VerifiableClient, bytes);
        }

        #[test]
        fn test_nocrash_nonverifiable_server(bytes in vec(any::<u8>(), 0..200)) {
            test_deserialize!(NonVerifiableServer, bytes);
        }

        #[test]
        fn test_nocrash_verifiable_server(bytes in vec(any::<u8>(), 0..200)) {
            test_deserialize!(VerifiableServer, bytes);
        }

        #[test]
        fn test_nocrash_blinded_element(bytes in vec(any::<u8>(), 0..200)) {
            test_deserialize!(BlindedElement, bytes);
        }

        #[test]
        fn test_nocrash_evaluation_element(bytes in vec(any::<u8>(), 0..200)) {
            test_deserialize!(EvaluationElement, bytes);
        }

        #[test]
        fn test_nocrash_proof(bytes in vec(any::<u8>(), 0..200)) {
            test_deserialize!(Proof, bytes);
        }
    }
}

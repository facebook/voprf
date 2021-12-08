// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Helper functions

use crate::errors::InternalError;
use core::array::IntoIter;
use generic_array::{typenum::U0, ArrayLength, GenericArray};

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

/// Simplifies handling of [`serialize()`] output and implements [`Iterator`].
pub(crate) struct Serialized<'a, L1: ArrayLength<u8>, L2: ArrayLength<u8>> {
    octet: GenericArray<u8, L1>,
    input: Input<'a, L2>,
}

enum Input<'a, L: ArrayLength<u8>> {
    Owned(GenericArray<u8, L>),
    Borrowed(&'a [u8]),
}

impl<'a, L1: ArrayLength<u8>, L2: ArrayLength<u8>> IntoIterator for &'a Serialized<'a, L1, L2> {
    type Item = &'a [u8];

    type IntoIter = IntoIter<&'a [u8], 2>;

    fn into_iter(self) -> Self::IntoIter {
        // MSRV: array `into_iter` isn't available in 1.51
        #[allow(deprecated)]
        IntoIter::new([
            &self.octet,
            match self.input {
                Input::Owned(ref bytes) => bytes,
                Input::Borrowed(bytes) => bytes,
            },
        ])
    }
}

// Computes I2OSP(len(input), max_bytes) || input
pub(crate) fn serialize<L: ArrayLength<u8>>(
    input: &[u8],
) -> Result<Serialized<L, U0>, InternalError> {
    Ok(Serialized {
        octet: i2osp::<L>(input.len())?,
        input: Input::Borrowed(input),
    })
}

// Variation of `serialize` that takes an owned `input`
pub(crate) fn serialize_owned<L1: ArrayLength<u8>, L2: ArrayLength<u8>>(
    input: GenericArray<u8, L2>,
) -> Result<Serialized<'static, L1, L2>, InternalError> {
    Ok(Serialized {
        octet: i2osp::<L1>(input.len())?,
        input: Input::Owned(input),
    })
}

macro_rules! chain_name {
    ($var:ident, $mod:ident) => {
        $mod
    };
    ($var:ident) => {
        $var
    };
}

macro_rules! chain_skip {
    ($var:ident, $feed:expr) => {
        $feed
    };
    ($var:ident) => {
        &$var
    };
}

/// The purpose of this macro is to simplify [`concat`](alloc::slice::Concat::concat)ing
/// slices into an [`Iterator`] to avoid allocation
macro_rules! chain {
    (
        $var:ident,
        $item1:expr $(=> |$mod1:ident| $feed1:expr)?,
        $($item2:expr $(=> |$mod2:ident| $feed2:expr)?),+$(,)?
    ) => {
        let chain_name!(__temp$(, $mod1)?) = $item1;
        let $var = (chain_skip!(__temp$(, $feed1)?)).into_iter();
        $(
            let chain_name!(__temp$(, $mod2)?) = $item2;
            let $var = $var.chain(chain_skip!(__temp$(, $feed2)?));
        )+
    };
}

#[cfg(test)]
mod unit_tests {
    use super::*;
    use crate::voprf::{
        BlindedElement, EvaluationElement, NonVerifiableClient, NonVerifiableServer, Proof,
        VerifiableClient, VerifiableServer,
    };
    use curve25519_dalek::ristretto::RistrettoPoint;
    use generic_array::typenum::{U1, U2};
    use proptest::{collection::vec, prelude::*};
    use sha2::Sha512;

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

    proptest! {
        #[test]
        fn test_nocrash_nonverifiable_client(bytes in vec(any::<u8>(), 0..200)) {
            NonVerifiableClient::<RistrettoPoint, Sha512>::deserialize(&bytes[..]).map_or(true, |_| true);
        }

        #[test]
        fn test_nocrash_verifiable_client(bytes in vec(any::<u8>(), 0..200)) {
            VerifiableClient::<RistrettoPoint, Sha512>::deserialize(&bytes[..]).map_or(true, |_| true);
        }

        #[test]
        fn test_nocrash_nonverifiable_server(bytes in vec(any::<u8>(), 0..200)) {
            NonVerifiableServer::<RistrettoPoint, Sha512>::deserialize(&bytes[..]).map_or(true, |_| true);
        }

        #[test]
        fn test_nocrash_verifiable_server(bytes in vec(any::<u8>(), 0..200)) {
            VerifiableServer::<RistrettoPoint, Sha512>::deserialize(&bytes[..]).map_or(true, |_| true);
        }

        #[test]
        fn test_nocrash_blinded_element(bytes in vec(any::<u8>(), 0..200)) {
            BlindedElement::<RistrettoPoint, Sha512>::deserialize(&bytes[..]).map_or(true, |_| true);
        }

        #[test]
        fn test_nocrash_evaluation_element(bytes in vec(any::<u8>(), 0..200)) {
            EvaluationElement::<RistrettoPoint, Sha512>::deserialize(&bytes[..]).map_or(true, |_| true);
        }

        #[test]
        fn test_nocrash_proof(bytes in vec(any::<u8>(), 0..200)) {
            Proof::<RistrettoPoint, Sha512>::deserialize(&bytes[..]).map_or(true, |_| true);
        }
    }
}

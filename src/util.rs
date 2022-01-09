// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Helper functions

use core::array::IntoIter;

use generic_array::typenum::U0;
use generic_array::{ArrayLength, GenericArray};

use crate::{Error, Result};

// Corresponds to the I2OSP() function from RFC8017
pub(crate) fn i2osp<L: ArrayLength<u8>>(input: usize) -> Result<GenericArray<u8, L>> {
    const SIZEOF_USIZE: usize = core::mem::size_of::<usize>();

    // Make sure input fits in output.
    if (SIZEOF_USIZE as u32 - input.leading_zeros() / 8) > L::U32 {
        return Err(Error::SerializationError);
    }

    let mut output = GenericArray::default();
    output[L::USIZE.saturating_sub(SIZEOF_USIZE)..]
        .copy_from_slice(&input.to_be_bytes()[SIZEOF_USIZE.saturating_sub(L::USIZE)..]);
    Ok(output)
}

/// Computes `I2OSP(len(input), max_bytes) || input` and helps hold output
/// without allocation.
pub(crate) struct Serialize<'a, L1: ArrayLength<u8>, L2: ArrayLength<u8> = U0> {
    octet: GenericArray<u8, L1>,
    input: Input<'a, L2>,
}

enum Input<'a, L: ArrayLength<u8>> {
    Owned(GenericArray<u8, L>),
    Borrowed(&'a [u8]),
}

impl<'a, L1: ArrayLength<u8>, L2: ArrayLength<u8>> IntoIterator for &'a Serialize<'a, L1, L2> {
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

impl<'a, L1: ArrayLength<u8>, L2: ArrayLength<u8>> Serialize<'a, L1, L2> {
    // Variation of `serialize` that takes a borrowed `input.
    pub(crate) fn from(input: &[u8]) -> Result<Serialize<L1>> {
        Ok(Serialize {
            octet: i2osp::<L1>(input.len())?,
            input: Input::Borrowed(input),
        })
    }

    pub(crate) fn from_owned(input: GenericArray<u8, L2>) -> Result<Serialize<'static, L1, L2>> {
        Ok(Serialize {
            octet: i2osp::<L1>(input.len())?,
            input: Input::Owned(input),
        })
    }
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

/// The purpose of this macro is to replace
/// [`concat`](alloc::slice::Concat::concat)ing slices into an [`Iterator`] to
/// avoid allocation
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
    use generic_array::typenum::{U1, U2};
    use proptest::collection::vec;
    use proptest::prelude::*;

    use super::*;
    use crate::{
        BlindedElement, EvaluationElement, NonVerifiableClient, NonVerifiableServer, Proof,
        VerifiableClient, VerifiableServer,
    };

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

    macro_rules! test_deserialize {
        ($item:ident, $bytes:ident) => {
            #[cfg(feature = "ristretto255")]
            {
                let _ = $item::<crate::Ristretto255, sha2::Sha512>::deserialize(&$bytes[..]);
            }
            #[cfg(feature = "p256")]
            {
                let _ = $item::<p256_::NistP256, sha2::Sha256>::deserialize(&$bytes[..]);
            }
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

// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Contains the main OPRF API

use core::iter::{self, Map, Repeat, Zip};

use derive_where::derive_where;
use digest::core_api::BlockSizeUser;
use digest::{Digest, Output, OutputSizeUser};
use generic_array::typenum::{IsLess, IsLessOrEqual, Unsigned, U256, U8};
use generic_array::GenericArray;
use rand_core::{CryptoRng, RngCore};

#[cfg(feature = "serde")]
use crate::serialization::serde::Scalar;
use crate::util::{derive_keypair, i2osp_2, BlindedElement, EvaluationElement, Mode, STR_FINALIZE};
use crate::{CipherSuite, Error, Group, Result};

///////////////
// Constants //
// ========= //
///////////////

////////////////////////////
// High-level API Structs //
// ====================== //
////////////////////////////

/// A client which engages with a [OPRFServer] in base mode, meaning
/// that the OPRF outputs are not verifiable.
#[derive_where(Clone, ZeroizeOnDrop)]
#[derive_where(Debug, Eq, Hash, Ord, PartialEq, PartialOrd; <CS::Group as Group>::Scalar)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(crate = "serde", bound = "")
)]
pub struct OprfClient<CS: CipherSuite>
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
{
    #[cfg_attr(feature = "serde", serde(with = "Scalar::<CS::Group>"))]
    pub(crate) blind: <CS::Group as Group>::Scalar,
}

/// A server which engages with a [OprfClient] in base mode, meaning
/// that the OPRF outputs are not verifiable.
#[derive_where(Clone, ZeroizeOnDrop)]
#[derive_where(Debug, Eq, Hash, Ord, PartialEq, PartialOrd; <CS::Group as Group>::Scalar)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(crate = "serde", bound = "")
)]
pub struct OprfServer<CS: CipherSuite>
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
{
    #[cfg_attr(feature = "serde", serde(with = "Scalar::<CS::Group>"))]
    pub(crate) sk: <CS::Group as Group>::Scalar,
}

/////////////////////////
// API Implementations //
// =================== //
/////////////////////////

impl<CS: CipherSuite> OprfClient<CS>
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
{
    /// Computes the first step for the multiplicative blinding version of
    /// DH-OPRF.
    ///
    /// # Errors
    /// [`Error::Input`] if the `input` is empty or longer then [`u16::MAX`].
    pub fn blind<R: RngCore + CryptoRng>(
        input: &[u8],
        blinding_factor_rng: &mut R,
    ) -> Result<OprfClientBlindResult<CS>> {
        let blind = CS::Group::random_scalar(blinding_factor_rng);
        Self::deterministic_blind_unchecked_inner(input, blind)
    }

    #[cfg(any(feature = "danger", test))]
    /// Computes the first step for the multiplicative blinding version of
    /// DH-OPRF, taking a blinding factor scalar as input instead of sampling
    /// from an RNG.
    ///
    /// # Caution
    ///
    /// This should be used with caution, since it does not perform any checks
    /// on the validity of the blinding factor!
    ///
    /// # Errors
    /// [`Error::Input`] if the `input` is empty or longer then [`u16::MAX`].
    pub fn deterministic_blind_unchecked(
        input: &[u8],
        blind: <CS::Group as Group>::Scalar,
    ) -> Result<OprfClientBlindResult<CS>> {
        Self::deterministic_blind_unchecked_inner(input, blind)
    }

    /// Inner function for computing blind output
    ///
    /// # Errors
    /// [`Error::Input`] if the `input` is empty or longer then [`u16::MAX`].
    fn deterministic_blind_unchecked_inner(
        input: &[u8],
        blind: <CS::Group as Group>::Scalar,
    ) -> Result<OprfClientBlindResult<CS>> {
        let blinded_element =
            crate::util::deterministic_blind_unchecked::<CS>(input, &blind, Mode::Oprf)?;
        Ok(OprfClientBlindResult {
            state: Self { blind },
            message: BlindedElement(blinded_element),
        })
    }

    /// Computes the third step for the multiplicative blinding version of
    /// DH-OPRF, in which the client unblinds the server's message.
    ///
    /// # Errors
    /// - [`Error::Input`] if the `input` is empty or longer then [`u16::MAX`].
    pub fn finalize(
        &self,
        input: &[u8],
        evaluation_element: &EvaluationElement<CS>,
    ) -> Result<Output<CS::Hash>> {
        let unblinded_element = evaluation_element.0 * &CS::Group::invert_scalar(self.blind);
        let mut outputs = finalize_after_unblind::<CS, _, _>(
            iter::once((input, unblinded_element)),
            &[],
        );
        outputs.next().unwrap()
    }

    #[cfg(test)]
    /// Only used for test functions
    pub fn from_blind(blind: <CS::Group as Group>::Scalar) -> Self {
        Self { blind }
    }

    #[cfg(feature = "danger")]
    /// Exposes the blind group element
    pub fn get_blind(&self) -> <CS::Group as Group>::Scalar {
        self.blind
    }
}

impl<CS: CipherSuite> OprfServer<CS>
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
{
    /// Produces a new instance of a [OPRFServer] using a supplied RNG
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut seed = Output::<CS::Hash>::default();
        rng.fill_bytes(&mut seed);
        // This can't fail as the hash output is type constrained.
        Self::new_from_seed(&seed, &[]).unwrap()
    }

    /// Produces a new instance of a [OPRFServer] using a supplied set
    /// of bytes to represent the server's private key
    ///
    /// # Errors
    /// [`Error::Deserialization`] if the private key is not a valid point on
    /// the group or zero.
    pub fn new_with_key(private_key_bytes: &[u8]) -> Result<Self> {
        let sk = CS::Group::deserialize_scalar(private_key_bytes)?;
        Ok(Self { sk })
    }

    /// Produces a new instance of a [OPRFServer] using a supplied set
    /// of bytes which are used as a seed to derive the server's private key.
    ///
    /// Corresponds to DeriveKeyPair() function from the VOPRF specification.
    ///
    /// # Errors
    /// [`Error::Seed`] if the `seed` is empty or longer then [`u16::MAX`].
    pub fn new_from_seed(seed: &[u8], info: &[u8]) -> Result<Self> {
        let (sk, _) = derive_keypair::<CS>(seed, info, Mode::Oprf).map_err(|_| Error::Seed)?;
        Ok(Self { sk })
    }

    // Only used for tests
    #[cfg(test)]
    pub fn get_private_key(&self) -> <CS::Group as Group>::Scalar {
        self.sk
    }

    /// Computes the second step for the multiplicative blinding version of
    /// DH-OPRF. This message is sent from the server (who holds the OPRF key)
    /// to the client.
    ///
    /// # Errors
    /// - [`Error::Protocol`] if the protocol fails and can't be completed.
    pub fn evaluate(&self, blinded_element: &BlindedElement<CS>) -> Result<EvaluationElement<CS>> {
        Ok(EvaluationElement(blinded_element.0 * &self.sk))
    }
}

/////////////////////////
// Convenience Structs //
//==================== //
/////////////////////////

/// Contains the fields that are returned by a non-verifiable client blind
#[derive_where(Debug; <CS::Group as Group>::Scalar, <CS::Group as Group>::Elem)]
pub struct OprfClientBlindResult<CS: CipherSuite>
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
{
    /// The state to be persisted on the client
    pub state: OprfClient<CS>,
    /// The message to send to the server
    pub message: BlindedElement<CS>,
}

/////////////////////
// Inner functions //
// =============== //
/////////////////////

type FinalizeAfterUnblindResult<'a, C, I, IE> = Map<
    Zip<IE, Repeat<GenericArray<u8, U8>>>,
    fn(
        (
            (I, <<C as CipherSuite>::Group as Group>::Elem),
            GenericArray<u8, U8>,
        ),
    ) -> Result<Output<<C as CipherSuite>::Hash>>,
>;

fn finalize_after_unblind<
    'a,
    CS: CipherSuite,
    I: AsRef<[u8]>,
    IE: 'a + Iterator<Item = (I, <CS::Group as Group>::Elem)>,
>(
    inputs_and_unblinded_elements: IE,
    _unused: &'a [u8],
) -> FinalizeAfterUnblindResult<CS, I, IE>
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
{
    let finalize_dst = GenericArray::from(STR_FINALIZE);

    inputs_and_unblinded_elements
        // To make a return type possible, we have to convert to a `fn` pointer,
        // which isn't possible if we `move` from context.
        .zip(iter::repeat(finalize_dst))
        .map(|((input, unblinded_element), finalize_dst)| {
            let elem_len = <CS::Group as Group>::ElemLen::U16.to_be_bytes();

            // hashInput = I2OSP(len(input), 2) || input ||
            //             I2OSP(len(unblindedElement), 2) || unblindedElement ||
            //             "Finalize"
            // return Hash(hashInput)
            Ok(CS::Hash::new()
                .chain_update(i2osp_2(input.as_ref().len()).map_err(|_| Error::Input)?)
                .chain_update(input.as_ref())
                .chain_update(elem_len)
                .chain_update(CS::Group::serialize_elem(unblinded_element))
                .chain_update(finalize_dst)
                .finalize())
        })
}

///////////
// Tests //
// ===== //
///////////

#[cfg(test)]
mod tests {
    use core::ptr;

    use rand::rngs::OsRng;

    use super::*;
    use crate::Group;

    fn prf<CS: CipherSuite>(
        input: &[u8],
        key: <CS::Group as Group>::Scalar,
        info: &[u8],
        mode: Mode,
    ) -> Output<CS::Hash>
    where
        <CS::Hash as OutputSizeUser>::OutputSize:
            IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
    {
        let point = CS::Group::hash_to_curve::<CS>(&[input], mode).unwrap();

        let res = point * &key;

        finalize_after_unblind::<CS, _, _>(iter::once((input, res)), info)
            .next()
            .unwrap()
            .unwrap()
    }

    fn base_retrieval<CS: CipherSuite>()
    where
        <CS::Hash as OutputSizeUser>::OutputSize:
            IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
    {
        let input = b"input";
        let mut rng = OsRng;
        let client_blind_result = OprfClient::<CS>::blind(input, &mut rng).unwrap();
        let server = OprfServer::<CS>::new(&mut rng);
        let message = server.evaluate(&client_blind_result.message).unwrap();
        let client_finalize_result = client_blind_result
            .state
            .finalize(input, &message)
            .unwrap();
        let res2 = prf::<CS>(input, server.get_private_key(), &[], Mode::Oprf);
        assert_eq!(client_finalize_result, res2);
    }

    fn base_inversion_unsalted<CS: CipherSuite>()
    where
        <CS::Hash as OutputSizeUser>::OutputSize:
            IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
    {
        let mut rng = OsRng;
        let mut input = [0u8; 64];
        rng.fill_bytes(&mut input);
        let client_blind_result = OprfClient::<CS>::blind(&input, &mut rng).unwrap();
        let client_finalize_result = client_blind_result
            .state
            .finalize(
                &input,
                &EvaluationElement(client_blind_result.message.0),
            )
            .unwrap();

        let point = CS::Group::hash_to_curve::<CS>(&[&input], Mode::Oprf).unwrap();
        let res2 = finalize_after_unblind::<CS, _, _>(iter::once((input.as_ref(), point)), &[])
            .next()
            .unwrap()
            .unwrap();

        assert_eq!(client_finalize_result, res2);
    }

    fn zeroize_oprf_client<CS: CipherSuite>()
    where
        <CS::Hash as OutputSizeUser>::OutputSize:
            IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
    {
        let input = b"input";
        let mut rng = OsRng;
        let client_blind_result = OprfClient::<CS>::blind(input, &mut rng).unwrap();

        let mut state = client_blind_result.state;
        unsafe { ptr::drop_in_place(&mut state) };
        assert!(state.serialize().iter().all(|&x| x == 0));

        let mut message = client_blind_result.message;
        unsafe { ptr::drop_in_place(&mut message) };
        assert!(message.serialize().iter().all(|&x| x == 0));
    }

    fn zeroize_oprf_server<CS: CipherSuite>()
    where
        <CS::Hash as OutputSizeUser>::OutputSize:
            IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
    {
        let input = b"input";
        let mut rng = OsRng;
        let client_blind_result = OprfClient::<CS>::blind(input, &mut rng).unwrap();
        let server = OprfServer::<CS>::new(&mut rng);
        let mut message = server.evaluate(&client_blind_result.message).unwrap();

        let mut state = server;
        unsafe { ptr::drop_in_place(&mut state) };
        assert!(state.serialize().iter().all(|&x| x == 0));

        unsafe { ptr::drop_in_place(&mut message) };
        assert!(message.serialize().iter().all(|&x| x == 0));
    }

    #[test]
    fn test_functionality() -> Result<()> {
        use p256::NistP256;

        #[cfg(feature = "ristretto255")]
        {
            use crate::Ristretto255;

            base_retrieval::<Ristretto255>();
            base_inversion_unsalted::<Ristretto255>();

            zeroize_oprf_client::<Ristretto255>();
            zeroize_oprf_server::<Ristretto255>();
        }

        base_retrieval::<NistP256>();
        base_inversion_unsalted::<NistP256>();

        zeroize_oprf_client::<NistP256>();
        zeroize_oprf_server::<NistP256>();

        Ok(())
    }
}

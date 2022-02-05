// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Contains the main OPRF API

#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use core::iter::{self, Map, Repeat, Zip};

use derive_where::derive_where;
use digest::core_api::BlockSizeUser;
use digest::{Digest, Output, OutputSizeUser};
use generic_array::sequence::Concat;
use generic_array::typenum::{IsLess, IsLessOrEqual, Unsigned, U11, U256, U8};
use generic_array::GenericArray;
use rand_core::{CryptoRng, RngCore};

#[cfg(feature = "serde")]
use crate::serialization::serde::Scalar;
use crate::util::{
    i2osp_1, i2osp_2, BlindedElement, EvaluationElement, Mode, STR_DERIVE_KEYPAIR, STR_FINALIZE,
    STR_VOPRF,
};
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
        let (blind, blinded_element) = blind::<CS, _>(input, blinding_factor_rng, Mode::Oprf)?;
        Ok(OprfClientBlindResult {
            state: Self { blind },
            message: BlindedElement(blinded_element),
        })
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
        let blinded_element = deterministic_blind_unchecked::<CS>(input, &blind, Mode::Oprf)?;
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
    /// - [`Error::Metadata`] if the `metadata` is longer then `u16::MAX - 21`.
    pub fn finalize(
        &self,
        input: &[u8],
        evaluation_element: &EvaluationElement<CS>,
        metadata: Option<&[u8]>, // FIXME: not used
    ) -> Result<Output<CS::Hash>> {
        let unblinded_element = evaluation_element.0 * &CS::Group::invert_scalar(self.blind);
        let mut outputs = finalize_after_unblind::<CS, _, _>(
            iter::once((input, unblinded_element)),
            metadata.unwrap_or_default(),
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

impl<CS: CipherSuite> BlindedElement<CS>
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
{
    #[cfg(feature = "danger")]
    /// Creates a [BlindedElement] from a raw group element.
    ///
    /// # Caution
    ///
    /// This should be used with caution, since it does not perform any checks
    /// on the validity of the value itself!
    pub fn from_value_unchecked(value: <CS::Group as Group>::Elem) -> Self {
        Self(value)
    }

    #[cfg(feature = "danger")]
    /// Exposes the internal value
    pub fn value(&self) -> <CS::Group as Group>::Elem {
        self.0
    }
}

impl<CS: CipherSuite> EvaluationElement<CS>
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
{
    #[cfg(feature = "danger")]
    /// Creates an [EvaluationElement] from a raw group element.
    ///
    /// # Caution
    ///
    /// This should be used with caution, since it does not perform any checks
    /// on the validity of the value itself!
    pub fn from_value_unchecked(value: <CS::Group as Group>::Elem) -> Self {
        Self(value)
    }

    #[cfg(feature = "danger")]
    /// Exposes the internal value
    pub fn value(&self) -> <CS::Group as Group>::Elem {
        self.0
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

#[allow(clippy::type_complexity)]
pub(crate) fn derive_keypair<CS: CipherSuite>(
    seed: &[u8],
    info: &[u8],
    mode: Mode,
) -> Result<(<CS::Group as Group>::Scalar, <CS::Group as Group>::Elem), Error>
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
{
    let context_string = create_context_string::<CS>(mode);
    let dst = GenericArray::from(STR_DERIVE_KEYPAIR).concat(context_string);

    // deriveInput = seed || I2OSP(len(info), 2) || info
    let info_len = i2osp_2(info.len()).map_err(|_| Error::Metadata)?;

    let mut counter: usize = 0;

    loop {
        if counter > 255 {
            break Err(Error::DeriveKeyPair);
        }

        // skS = G.HashToScalar(deriveInput || I2OSP(counter, 1), DST = "DeriveKeyPair"
        // || contextString)
        let counter_i2osp = i2osp_1(counter).map_err(|_| Error::DeriveKeyPair)?;
        let sk_s = <CS::Group as Group>::hash_to_scalar_with_dst::<CS>(
            &[seed, info_len.as_slice(), info, counter_i2osp.as_slice()],
            &dst,
        )
        .map_err(|_| Error::DeriveKeyPair)?;

        if !bool::from(CS::Group::is_zero_scalar(sk_s)) {
            let pk_s = CS::Group::base_elem() * &sk_s;
            break Ok((sk_s, pk_s));
        }
        counter += 1;
    }
}

type BlindResult<C> = (
    <<C as CipherSuite>::Group as Group>::Scalar,
    <<C as CipherSuite>::Group as Group>::Elem,
);

// Inner function for blind. Returns the blind scalar and the blinded element
//
// Can only fail with [`Error::Input`].
fn blind<CS: CipherSuite, R: RngCore + CryptoRng>(
    input: &[u8],
    blinding_factor_rng: &mut R,
    mode: Mode,
) -> Result<BlindResult<CS>>
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
{
    // Choose a random scalar that must be non-zero
    let blind = CS::Group::random_scalar(blinding_factor_rng);
    let blinded_element = deterministic_blind_unchecked::<CS>(input, &blind, mode)?;
    Ok((blind, blinded_element))
}

// Inner function for blind that assumes that the blinding factor has already
// been chosen, and therefore takes it as input. Does not check if the blinding
// factor is non-zero.
//
// Can only fail with [`Error::Input`].
fn deterministic_blind_unchecked<CS: CipherSuite>(
    input: &[u8],
    blind: &<CS::Group as Group>::Scalar,
    mode: Mode,
) -> Result<<CS::Group as Group>::Elem>
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
{
    let hashed_point = CS::Group::hash_to_curve::<CS>(&[input], mode).map_err(|_| Error::Input)?;
    Ok(hashed_point * blind)
}

type FinalizeAfterUnblindResult<'a, C, I, IE> = Map<
    Zip<IE, Repeat<GenericArray<u8, U8>>>,
    fn(
        (
            (I, <<C as CipherSuite>::Group as Group>::Elem),
            GenericArray<u8, U8>,
        ),
    ) -> Result<Output<<C as CipherSuite>::Hash>>,
>;

// Returned values can only fail with [`Error::Input`] or [`Error::Metadata`].
fn finalize_after_unblind<
    'a,
    CS: CipherSuite,
    I: AsRef<[u8]>,
    IE: 'a + Iterator<Item = (I, <CS::Group as Group>::Elem)>,
>(
    inputs_and_unblinded_elements: IE,
    _info: &'a [u8],
) -> FinalizeAfterUnblindResult<CS, I, IE>
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
{
    // https://www.ietf.org/archive/id/draft-irtf-cfrg-voprf-08.html#section-3.3.3.2-2
    // https://www.ietf.org/archive/id/draft-irtf-cfrg-voprf-08.html#section-3.3.4.3-1

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

/// Generates the contextString parameter as defined in
/// <https://www.ietf.org/archive/id/draft-irtf-cfrg-voprf-08.html>
pub(crate) fn create_context_string<CS: CipherSuite>(mode: Mode) -> GenericArray<u8, U11>
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
{
    GenericArray::from(STR_VOPRF)
        .concat([mode.to_u8()].into())
        .concat(CS::ID.to_be_bytes().into())
}

///////////
// Tests //
// ===== //
///////////

#[cfg(test)]
mod tests {
    use core::ops::Add;
    use core::ptr;

    use ::alloc::vec;
    use ::alloc::vec::Vec;
    use generic_array::typenum::Sum;
    use generic_array::ArrayLength;
    use rand::rngs::OsRng;

    use super::*;
    use crate::serde::{Deserialize, Serialize};
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
        let info = b"info";
        let mut rng = OsRng;
        let client_blind_result = OprfClient::<CS>::blind(input, &mut rng).unwrap();
        let server = OprfServer::<CS>::new(&mut rng);
        let message = server.evaluate(&client_blind_result.message).unwrap();
        let client_finalize_result = client_blind_result
            .state
            .finalize(input, &message, Some(info))
            .unwrap();
        let res2 = prf::<CS>(input, server.get_private_key(), info, Mode::Oprf);
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
        let info = b"info";
        let client_blind_result = OprfClient::<CS>::blind(&input, &mut rng).unwrap();
        let client_finalize_result = client_blind_result
            .state
            .finalize(
                &input,
                &EvaluationElement(client_blind_result.message.0),
                Some(info),
            )
            .unwrap();

        let point = CS::Group::hash_to_curve::<CS>(&[&input], Mode::Oprf).unwrap();
        let res2 = finalize_after_unblind::<CS, _, _>(iter::once((input.as_ref(), point)), info)
            .next()
            .unwrap()
            .unwrap();

        assert_eq!(client_finalize_result, res2);
    }

    fn zeroize_base_client<CS: CipherSuite>()
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

    fn zeroize_base_server<CS: CipherSuite>()
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

            zeroize_base_client::<Ristretto255>();
            zeroize_base_server::<Ristretto255>();
        }

        base_retrieval::<NistP256>();
        base_inversion_unsalted::<NistP256>();

        zeroize_base_client::<NistP256>();
        zeroize_base_server::<NistP256>();

        Ok(())
    }
}

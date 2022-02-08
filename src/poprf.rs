// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Contains the main POPRF API

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use derive_where::derive_where;
use digest::core_api::BlockSizeUser;
use digest::{Digest, Output, OutputSizeUser};
use generic_array::typenum::{IsLess, IsLessOrEqual, Unsigned, U256};
use generic_array::GenericArray;
use rand_core::{CryptoRng, RngCore};

#[cfg(feature = "serde")]
use crate::serialization::serde::{Element, Scalar};
use crate::util::{
    derive_keypair, generate_proof, i2osp_2, verify_proof, BlindedElement, EvaluationElement, Mode,
    Proof, ProofElement, STR_FINALIZE, STR_INFO,
};
use crate::{CipherSuite, Error, Group, Result};

////////////////////////////
// High-level API Structs //
// ====================== //
////////////////////////////

/// A client which engages with a [PoprfServer] in verifiable mode, meaning
/// that the OPRF outputs can be checked against a server public key.
#[derive_where(Clone, ZeroizeOnDrop)]
#[derive_where(Debug, Eq, Hash, Ord, PartialEq, PartialOrd; <CS::Group as Group>::Scalar, <CS::Group as Group>::Elem)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(crate = "serde", bound = "")
)]
pub struct PoprfClient<CS: CipherSuite>
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
{
    #[cfg_attr(feature = "serde", serde(with = "Scalar::<CS::Group>"))]
    pub(crate) blind: <CS::Group as Group>::Scalar,
    #[cfg_attr(feature = "serde", serde(with = "Element::<CS::Group>"))]
    pub(crate) blinded_element: <CS::Group as Group>::Elem,
}

/// A server which engages with a [PoprfClient] in verifiable mode, meaning
/// that the OPRF outputs can be checked against a server public key.
#[derive_where(Clone, ZeroizeOnDrop)]
#[derive_where(Debug, Eq, Hash, Ord, PartialEq, PartialOrd; <CS::Group as Group>::Scalar, <CS::Group as Group>::Elem)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(crate = "serde", bound = "")
)]
pub struct PoprfServer<CS: CipherSuite>
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
{
    #[cfg_attr(feature = "serde", serde(with = "Scalar::<CS::Group>"))]
    pub(crate) sk: <CS::Group as Group>::Scalar,
    #[cfg_attr(feature = "serde", serde(with = "Element::<CS::Group>"))]
    pub(crate) pk: <CS::Group as Group>::Elem,
}

/////////////////////////
// API Implementations //
// =================== //
/////////////////////////

impl<CS: CipherSuite> PoprfClient<CS>
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
{
    /// Computes the first step for the multiplicative blinding version of
    /// DH-OPRF.
    ///
    /// # Errors
    /// [`Error::Input`] if the `input` is empty or longer than [`u16::MAX`].
    pub fn blind<R: RngCore + CryptoRng>(
        blinding_factor_rng: &mut R,
        input: &[u8],
    ) -> Result<PoprfClientBlindResult<CS>> {
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
    /// [`Error::Input`] if the `input` is empty or longer than [`u16::MAX`].
    pub fn deterministic_blind_unchecked(
        input: &[u8],
        blind: <CS::Group as Group>::Scalar,
    ) -> Result<PoprfClientBlindResult<CS>> {
        Self::deterministic_blind_unchecked_inner(input, blind)
    }

    /// Inner function for computing blind output
    ///
    /// # Errors
    /// [`Error::Input`] if the `input` is empty or longer than [`u16::MAX`].
    fn deterministic_blind_unchecked_inner(
        input: &[u8],
        blind: <CS::Group as Group>::Scalar,
    ) -> Result<PoprfClientBlindResult<CS>> {
        let blinded_element =
            crate::util::deterministic_blind_unchecked::<CS>(input, &blind, Mode::Poprf)?;
        Ok(PoprfClientBlindResult {
            state: Self {
                blind,
                blinded_element,
            },
            message: BlindedElement(blinded_element),
        })
    }

    /// Computes the third step for the multiplicative blinding version of
    /// DH-OPRF, in which the client unblinds the server's message.
    ///
    /// # Errors
    /// - [`Error::Input`] if the `input` is empty or longer than [`u16::MAX`].
    /// - [`Error::Info`] if the `info` is longer than `u16::MAX`.
    /// - [`Error::ProofVerification`] if the `proof` failed to verify.
    pub fn finalize(
        &self,
        input: &[u8],
        evaluation_element: &EvaluationElement<CS>,
        proof: &Proof<CS>,
        pk: <CS::Group as Group>::Elem,
        info: Option<&[u8]>,
    ) -> Result<Output<CS::Hash>> {
        let inputs = core::array::from_ref(&input);
        let clients = core::array::from_ref(self);
        let messages = core::array::from_ref(evaluation_element);

        let batch_result = Self::batch_finalize(inputs, clients, messages, proof, pk, info)?;
        Ok(batch_result.first().unwrap().clone())
    }

    /// Allows for batching of the finalization of multiple [PoprfClient]
    /// and [EvaluationElement] pairs
    ///
    /// # Errors
    /// - [`Error::Info`] if the `info` is longer than `u16::MAX`.
    /// - [`Error::Batch`] if the number of `clients` and `messages` don't match
    ///   or is longer than [`u16::MAX`].
    /// - [`Error::ProofVerification`] if the `proof` failed to verify.
    ///
    /// The resulting messages can each fail individually with [`Error::Input`]
    /// if the `input` is empty or longer than [`u16::MAX`].
    pub fn batch_finalize(
        inputs: &[&[u8]],
        clients: &[PoprfClient<CS>],
        messages: &[EvaluationElement<CS>],
        proof: &Proof<CS>,
        pk: <CS::Group as Group>::Elem,
        info: Option<&[u8]>,
    ) -> Result<Vec<Output<<CS as CipherSuite>::Hash>>> {
        let unblinded_elements = poprf_unblind(clients, messages, pk, proof, info)?;

        let mut inputs_and_unblinded_elements = alloc::vec![];
        for (input, unblinded_element) in inputs.iter().cloned().zip(unblinded_elements) {
            inputs_and_unblinded_elements.push((input, unblinded_element));
        }

        finalize_after_unblind::<CS>(&inputs_and_unblinded_elements, info)
    }

    #[cfg(test)]
    /// Only used for test functions
    pub fn get_blind(&self) -> <CS::Group as Group>::Scalar {
        self.blind
    }
}

impl<CS: CipherSuite> PoprfServer<CS>
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
{
    /// Produces a new instance of a [PoprfServer] using a supplied RNG
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut seed = Output::<CS::Hash>::default();
        rng.fill_bytes(&mut seed);
        // This can't fail as the hash output is type constrained.
        Self::new_from_seed(&seed, &[]).unwrap()
    }

    /// Produces a new instance of a [PoprfServer] using a supplied set of
    /// bytes to represent the server's private key
    ///
    /// # Errors
    /// [`Error::Deserialization`] if the private key is not a valid point on
    /// the group or zero.
    pub fn new_with_key(key: &[u8]) -> Result<Self> {
        let sk = CS::Group::deserialize_scalar(key)?;
        let pk = CS::Group::base_elem() * &sk;
        Ok(Self { sk, pk })
    }

    /// Produces a new instance of a [PoprfServer] using a supplied set of
    /// bytes which are used as a seed to derive the server's private key.
    ///
    /// Corresponds to DeriveKeyPair() function from the VOPRF specification.
    ///
    /// # Errors
    /// [`Error::Seed`] if the `seed` is empty or longer than [`u16::MAX`].
    pub fn new_from_seed(seed: &[u8], info: &[u8]) -> Result<Self> {
        let (sk, pk) = derive_keypair::<CS>(seed, info, Mode::Poprf).map_err(|_| Error::Seed)?;
        Ok(Self { sk, pk })
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
    /// - [`Error::Info`] if the `info` is longer than `u16::MAX`.
    /// - [`Error::Protocol`] if the protocol fails and can't be completed.
    pub fn evaluate<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        blinded_element: &BlindedElement<CS>,
        info: Option<&[u8]>,
    ) -> Result<PoprfServerEvaluateResult<CS>> {
        let batch_evaluate_result =
            self.batch_evaluate(rng, std::vec![blinded_element.clone()], info)?;
        Ok(PoprfServerEvaluateResult {
            message: batch_evaluate_result.messages.get(0).unwrap().clone(),
            proof: batch_evaluate_result.proof,
        })
    }

    /// Allows for batching of the evaluation of multiple [BlindedElement]
    /// messages from a [PoprfClient]
    ///
    /// # Errors
    /// - [`Error::Info`] if the `info` is longer than `u16::MAX`.
    /// - [`Error::Protocol`] if the protocol fails and can't be completed.
    pub fn batch_evaluate<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        blinded_elements: Vec<BlindedElement<CS>>,
        info: Option<&[u8]>,
    ) -> Result<PoprfServerBatchEvaluateResult<CS>> {
        let g = CS::Group::base_elem();
        let tweak = compute_tweak::<CS>(self.sk, info)?;
        let tweaked_key = g * &tweak;

        // evaluatedElement = G.ScalarInverse(t) * blindedElement
        let evaluation_elements: Vec<EvaluationElement<CS>> = blinded_elements
            .iter()
            .map(|blinded_element| {
                EvaluationElement(blinded_element.0 * &CS::Group::invert_scalar(tweak))
            })
            .collect();

        let messages = evaluation_elements.clone();

        let proof = generate_proof(
            rng,
            tweak,
            g,
            tweaked_key,
            evaluation_elements
                .into_iter()
                .map(|element: EvaluationElement<CS>| ProofElement(element.0)),
            blinded_elements
                .into_iter()
                .map(|element| ProofElement(element.0)),
            Mode::Poprf,
        )?;

        Ok(PoprfServerBatchEvaluateResult { messages, proof })
    }

    /// Retrieves the server's public key
    pub fn get_public_key(&self) -> <CS::Group as Group>::Elem {
        self.pk
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

/// Contains the fields that are returned by a verifiable client blind
#[derive_where(Debug; <CS::Group as Group>::Scalar, <CS::Group as Group>::Elem)]
pub struct PoprfClientBlindResult<CS: CipherSuite>
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
{
    /// The state to be persisted on the client
    pub state: PoprfClient<CS>,
    /// The message to send to the server
    pub message: BlindedElement<CS>,
}

/// Contains the fields that are returned by a verifiable server evaluate
#[derive_where(Debug; <CS::Group as Group>::Scalar, <CS::Group as Group>::Elem)]
pub struct PoprfServerEvaluateResult<CS: CipherSuite>
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
{
    /// The message to send to the client
    pub message: EvaluationElement<CS>,
    /// The proof for the client to verify
    pub proof: Proof<CS>,
}

/// Contains the fields that are returned by a verifiable server batch evaluate
#[derive_where(Debug; <CS::Group as Group>::Scalar, <CS::Group as Group>::Elem)]
#[cfg(feature = "alloc")]
pub struct PoprfServerBatchEvaluateResult<CS: CipherSuite>
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
{
    /// The messages to send to the client
    pub messages: alloc::vec::Vec<EvaluationElement<CS>>,
    /// The proof for the client to verify
    pub proof: Proof<CS>,
}

/////////////////////
// Inner functions //
// =============== //
/////////////////////

// Inner function for POPRF blind. Computes the tweaked key from the server
// public key and info.
fn compute_tweaked_key<CS: CipherSuite>(
    pk: <CS::Group as Group>::Elem,
    info: Option<&[u8]>,
) -> Result<<CS::Group as Group>::Elem>
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
{
    // None for info is treated the same as empty bytes
    let info = info.unwrap_or_default();

    // framedInfo = "Info" || I2OSP(len(info), 2) || info
    // m = G.HashToScalar(framedInfo)
    // T = G.ScalarBaseMult(m)
    // tweakedKey = T + pkS
    // if tweakedKey == G.Identity():
    //   raise InvalidInputError
    let info_len = i2osp_2(info.len()).map_err(|_| Error::Input)?;
    let framed_info = [&STR_INFO, info_len.as_slice(), info];

    // This can't fail, the size of the `input` is known.
    let m = CS::Group::hash_to_scalar::<CS>(&framed_info, Mode::Poprf).unwrap();

    let t = CS::Group::base_elem() * &m;
    let tweaked_key = t + &pk;

    // Check if resulting element
    match bool::from(CS::Group::is_identity_elem(tweaked_key)) {
        true => Err(Error::Input),
        false => Ok(tweaked_key),
    }
}

// Inner function for POPRF evaluate. Computes the tweak from the server
// private key and info.
fn compute_tweak<CS: CipherSuite>(
    sk: <CS::Group as Group>::Scalar,
    info: Option<&[u8]>,
) -> Result<<CS::Group as Group>::Scalar>
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
{
    // None for info is treated the same as empty bytes
    let info = info.unwrap_or_default();

    // framedInfo = "Info" || I2OSP(len(info), 2) || info
    // m = G.HashToScalar(framedInfo)
    // t = skS + m
    // if t == 0:
    //   raise InverseError
    let info_len = i2osp_2(info.len()).map_err(|_| Error::Input)?;
    let framed_info = [&STR_INFO, info_len.as_slice(), info];

    // This can't fail, the size of the `input` is known.
    let m = CS::Group::hash_to_scalar::<CS>(&framed_info, Mode::Poprf).unwrap();

    let t = sk + &m;

    // Check if resulting element is equal to zero
    match bool::from(CS::Group::is_zero_scalar(t)) {
        true => Err(Error::Input),
        false => Ok(t),
    }
}

// Can only fail with [`Error::Info`], [`Error::Batch] or
// [`Error::ProofVerification`].
fn poprf_unblind<CS: CipherSuite>(
    clients: &[PoprfClient<CS>],
    messages: &[EvaluationElement<CS>],
    pk: <CS::Group as Group>::Elem,
    proof: &Proof<CS>,
    info: Option<&[u8]>,
) -> Result<Vec<<CS::Group as Group>::Elem>>
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
{
    let info = info.unwrap_or_default();
    let tweaked_key = compute_tweaked_key::<CS>(pk, Some(info))?;

    let g = CS::Group::base_elem();

    let blinds = clients
        .iter()
        // Convert to `fn` pointer to make a return type possible.
        .map(<fn(&PoprfClient<CS>) -> _>::from(|x| x.blind));
    let evaluation_elements = messages.iter().map(|element| ProofElement(element.0));
    let blinded_elements = clients
        .iter()
        .map(|client| ProofElement(client.blinded_element));

    verify_proof(
        g,
        tweaked_key,
        evaluation_elements,
        blinded_elements,
        proof,
        Mode::Poprf,
    )?;

    Ok(blinds
        .zip(messages.iter())
        .map(|(blind, x)| x.0 * &CS::Group::invert_scalar(blind))
        .collect())
}

// Returned values can only fail with [`Error::Input`] or [`Error::Info`].
fn finalize_after_unblind<CS: CipherSuite>(
    inputs_and_unblinded_elements: &[(&[u8], <CS::Group as Group>::Elem)],
    info: Option<&[u8]>,
) -> Result<Vec<Output<<CS as CipherSuite>::Hash>>>
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
{
    let mut outputs = alloc::vec![];

    let info = info.unwrap_or_default();
    let elem_len = <CS::Group as Group>::ElemLen::U16.to_be_bytes();
    let finalize_dst = GenericArray::from(STR_FINALIZE);

    for (input, unblinded_element) in inputs_and_unblinded_elements.iter().cloned() {
        // hashInput = I2OSP(len(input), 2) || input ||
        //             I2OSP(len(info), 2) || info ||
        //             I2OSP(len(unblindedElement), 2) || unblindedElement ||
        //             "Finalize"
        // return Hash(hashInput)
        let output = CS::Hash::new()
            .chain_update(i2osp_2(input.as_ref().len()).map_err(|_| Error::Input)?)
            .chain_update(input.as_ref())
            .chain_update(i2osp_2(info.as_ref().len()).map_err(|_| Error::Input)?)
            .chain_update(info.as_ref())
            .chain_update(elem_len)
            .chain_update(CS::Group::serialize_elem(unblinded_element))
            .chain_update(finalize_dst)
            .finalize();
        outputs.push(output);
    }

    Ok(outputs)
}

///////////
// Tests //
// ===== //
///////////

#[cfg(test)]
mod tests {
    use core::ops::Add;
    use core::ptr;

    use generic_array::typenum::Sum;
    use generic_array::ArrayLength;
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
        let t = compute_tweak::<CS>(key, Some(info)).unwrap();

        let point = CS::Group::hash_to_curve::<CS>(&[input], mode).unwrap();

        // evaluatedElement = G.ScalarInverse(t) * blindedElement
        let res = point * &CS::Group::invert_scalar(t);

        finalize_after_unblind::<CS>(&[(input, res)], Some(info))
            .unwrap()
            .first()
            .unwrap()
            .clone()
    }

    fn verifiable_retrieval<CS: CipherSuite>()
    where
        <CS::Hash as OutputSizeUser>::OutputSize:
            IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
    {
        let input = b"input";
        let info = b"info";
        let mut rng = OsRng;
        let server = PoprfServer::<CS>::new(&mut rng);
        let client_blind_result = PoprfClient::<CS>::blind(&mut rng, input).unwrap();
        let server_result = server
            .evaluate(&mut rng, &client_blind_result.message, Some(info))
            .unwrap();
        let client_finalize_result = client_blind_result
            .state
            .finalize(
                input,
                &server_result.message,
                &server_result.proof,
                server.get_public_key(),
                Some(info),
            )
            .unwrap();
        let res2 = prf::<CS>(input, server.get_private_key(), info, Mode::Poprf);
        assert_eq!(client_finalize_result, res2);
    }

    fn verifiable_bad_public_key<CS: CipherSuite>()
    where
        <CS::Hash as OutputSizeUser>::OutputSize:
            IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
    {
        let input = b"input";
        let info = b"info";
        let mut rng = OsRng;
        let server = PoprfServer::<CS>::new(&mut rng);
        let client_blind_result = PoprfClient::<CS>::blind(&mut rng, input).unwrap();
        let server_result = server
            .evaluate(&mut rng, &client_blind_result.message, Some(info))
            .unwrap();
        let wrong_pk = {
            // Choose a group element that is unlikely to be the right public key
            CS::Group::hash_to_curve::<CS>(&[b"msg"], Mode::Oprf).unwrap()
        };
        let client_finalize_result = client_blind_result.state.finalize(
            input,
            &server_result.message,
            &server_result.proof,
            wrong_pk,
            Some(info),
        );
        assert!(client_finalize_result.is_err());
    }

    fn zeroize_verifiable_client<CS: CipherSuite>()
    where
        <CS::Hash as OutputSizeUser>::OutputSize:
            IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
        <CS::Group as Group>::ScalarLen: Add<<CS::Group as Group>::ElemLen>,
        Sum<<CS::Group as Group>::ScalarLen, <CS::Group as Group>::ElemLen>: ArrayLength<u8>,
    {
        let input = b"input";
        let mut rng = OsRng;
        let client_blind_result = PoprfClient::<CS>::blind(&mut rng, input).unwrap();

        let mut state = client_blind_result.state;
        unsafe { ptr::drop_in_place(&mut state) };
        assert!(state.serialize().iter().all(|&x| x == 0));

        let mut message = client_blind_result.message;
        unsafe { ptr::drop_in_place(&mut message) };
        assert!(message.serialize().iter().all(|&x| x == 0));
    }

    fn zeroize_verifiable_server<CS: CipherSuite>()
    where
        <CS::Hash as OutputSizeUser>::OutputSize:
            IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
        <CS::Group as Group>::ScalarLen: Add<<CS::Group as Group>::ElemLen>,
        Sum<<CS::Group as Group>::ScalarLen, <CS::Group as Group>::ElemLen>: ArrayLength<u8>,
        <CS::Group as Group>::ScalarLen: Add<<CS::Group as Group>::ScalarLen>,
        Sum<<CS::Group as Group>::ScalarLen, <CS::Group as Group>::ScalarLen>: ArrayLength<u8>,
    {
        let input = b"input";
        let info = b"info";
        let mut rng = OsRng;
        let server = PoprfServer::<CS>::new(&mut rng);
        let client_blind_result = PoprfClient::<CS>::blind(&mut rng, input).unwrap();
        let server_result = server
            .evaluate(&mut rng, &client_blind_result.message, Some(info))
            .unwrap();

        let mut state = server;
        unsafe { ptr::drop_in_place(&mut state) };
        assert!(state.serialize().iter().all(|&x| x == 0));

        let mut message = server_result.message;
        unsafe { ptr::drop_in_place(&mut message) };
        assert!(message.serialize().iter().all(|&x| x == 0));

        let mut proof = server_result.proof;
        unsafe { ptr::drop_in_place(&mut proof) };
        assert!(proof.serialize().iter().all(|&x| x == 0));
    }

    #[test]
    fn test_functionality() -> Result<()> {
        use p256::NistP256;

        #[cfg(feature = "ristretto255")]
        {
            use crate::Ristretto255;

            verifiable_retrieval::<Ristretto255>();
            verifiable_bad_public_key::<Ristretto255>();

            zeroize_verifiable_client::<Ristretto255>();
            zeroize_verifiable_server::<Ristretto255>();
        }

        verifiable_retrieval::<NistP256>();
        verifiable_bad_public_key::<NistP256>();

        zeroize_verifiable_client::<NistP256>();
        zeroize_verifiable_server::<NistP256>();

        Ok(())
    }
}

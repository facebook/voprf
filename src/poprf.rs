// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Contains the main POPRF API

#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use core::iter::{self, Map, Repeat, Zip};

use derive_where::derive_where;
use digest::core_api::BlockSizeUser;
use digest::{Digest, Output, OutputSizeUser};
use generic_array::sequence::Concat;
use generic_array::typenum::{IsLess, IsLessOrEqual, Unsigned, U256, U8};
use generic_array::GenericArray;
use rand_core::{CryptoRng, RngCore};

#[cfg(feature = "serde")]
use crate::serialization::serde::{Element, Scalar};
use crate::util::{
    create_context_string, generate_proof, i2osp_1, i2osp_2, verify_proof, BlindedElement,
    EvaluationElement, Mode, Proof, STR_CONTEXT, STR_DERIVE_KEYPAIR, STR_FINALIZE,
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
    /// [`Error::Input`] if the `input` is empty or longer then [`u16::MAX`].
    pub fn blind<R: RngCore + CryptoRng>(
        input: &[u8],
        blinding_factor_rng: &mut R,
    ) -> Result<PoprfClientBlindResult<CS>> {
        let (blind, blinded_element) = blind::<CS, _>(input, blinding_factor_rng, Mode::Poprf)?;
        Ok(PoprfClientBlindResult {
            state: Self {
                blind,
                blinded_element,
            },
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
    ) -> Result<PoprfClientBlindResult<CS>> {
        let blinded_element = deterministic_blind_unchecked::<CS>(input, &blind, Mode::Poprf)?;
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
    /// - [`Error::Input`] if the `input` is empty or longer then [`u16::MAX`].
    /// - [`Error::Metadata`] if the `metadata` is longer then `u16::MAX - 21`.
    /// - [`Error::ProofVerification`] if the `proof` failed to verify.
    pub fn finalize(
        &self,
        input: &[u8],
        evaluation_element: &EvaluationElement<CS>,
        proof: &Proof<CS>,
        pk: <CS::Group as Group>::Elem,
        metadata: Option<&[u8]>,
    ) -> Result<Output<CS::Hash>> {
        let inputs = core::array::from_ref(&input);
        let clients = core::array::from_ref(self);
        let messages = core::array::from_ref(evaluation_element);

        let mut batch_result =
            Self::batch_finalize(inputs, clients, messages, proof, pk, metadata)?;
        batch_result.next().unwrap()
    }

    /// Allows for batching of the finalization of multiple [PoprfClient]
    /// and [EvaluationElement] pairs
    ///
    /// # Errors
    /// - [`Error::Metadata`] if the `metadata` is longer then `u16::MAX - 21`.
    /// - [`Error::Batch`] if the number of `clients` and `messages` don't match
    ///   or is longer then [`u16::MAX`].
    /// - [`Error::ProofVerification`] if the `proof` failed to verify.
    ///
    /// The resulting messages can each fail individually with [`Error::Input`]
    /// if the `input` is empty or longer then [`u16::MAX`].
    pub fn batch_finalize<'a, I: 'a, II, IC, IM>(
        inputs: &'a II,
        clients: &'a IC,
        messages: &'a IM,
        proof: &Proof<CS>,
        pk: <CS::Group as Group>::Elem,
        metadata: Option<&'a [u8]>,
    ) -> Result<PoprfClientBatchFinalizeResult<'a, CS, I, II, IC, IM>>
    where
        CS: 'a,
        I: AsRef<[u8]>,
        &'a II: 'a + IntoIterator<Item = I>,
        <&'a II as IntoIterator>::IntoIter: ExactSizeIterator,
        &'a IC: 'a + IntoIterator<Item = &'a PoprfClient<CS>>,
        <&'a IC as IntoIterator>::IntoIter: ExactSizeIterator,
        &'a IM: 'a + IntoIterator<Item = &'a EvaluationElement<CS>>,
        <&'a IM as IntoIterator>::IntoIter: ExactSizeIterator,
    {
        let metadata = metadata.unwrap_or_default();

        let unblinded_elements = verifiable_unblind(clients, messages, pk, proof, metadata)?;

        let inputs_and_unblinded_elements = inputs.into_iter().zip(unblinded_elements);

        Ok(finalize_after_unblind::<CS, _, _>(
            inputs_and_unblinded_elements,
            metadata,
        ))
    }

    #[cfg(test)]
    /// Only used for test functions
    pub fn from_blind_and_element(
        blind: <CS::Group as Group>::Scalar,
        blinded_element: <CS::Group as Group>::Elem,
    ) -> Self {
        Self {
            blind,
            blinded_element,
        }
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
    /// [`Error::Seed`] if the `seed` is empty or longer then [`u16::MAX`].
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
    /// - [`Error::Metadata`] if the `metadata` is longer then `u16::MAX - 21`.
    /// - [`Error::Protocol`] if the protocol fails and can't be completed.
    pub fn evaluate<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        blinded_element: &BlindedElement<CS>,
        metadata: Option<&[u8]>,
    ) -> Result<PoprfServerEvaluateResult<CS>> {
        let batch_evaluate_result = self.batch_evaluate(rng, std::vec![blinded_element.clone()])?;
        Ok(PoprfServerEvaluateResult {
            message: batch_evaluate_result
                .messages
                .iter()
                .next()
                .unwrap()
                .clone(),
            proof: batch_evaluate_result.proof,
        })
    }

    /// Allows for batching of the evaluation of multiple [BlindedElement]
    /// messages from a [PoprfClient]
    ///
    /// # Errors
    /// - [`Error::Metadata`] if the `metadata` is longer then `u16::MAX - 21`.
    /// - [`Error::Protocol`] if the protocol fails and can't be completed.
    pub fn batch_evaluate<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        blinded_elements: Vec<BlindedElement<CS>>,
    ) -> Result<PoprfServerBatchEvaluateResult<CS>> {
        let evaluation_elements: Vec<EvaluationElement<CS>> = blinded_elements
            .iter()
            .map(|blinded_element| EvaluationElement(blinded_element.0 * &self.sk))
            .collect();

        let messages = evaluation_elements.clone();

        let g = CS::Group::base_elem();
        let proof = generate_proof(
            rng,
            self.sk,
            g,
            self.pk,
            blinded_elements.into_iter().map(|element| element.0),
            evaluation_elements
                .into_iter()
                .map(|element: EvaluationElement<CS>| element.0.clone()),
        )?;

        Ok(PoprfServerBatchEvaluateResult { messages, proof })
    }

    /// Alternative version of [`batch_evaluate`](Self::batch_evaluate) without
    /// memory allocation. Returned [`PreparedEvaluationElement`] have to be
    /// [`collect`](Iterator::collect)ed and passed into
    /// [`batch_evaluate_finish`](Self::batch_evaluate_finish).
    ///
    /// # Errors
    /// - [`Error::Metadata`] if the `metadata` is longer then `u16::MAX - 21`.
    /// - [`Error::Protocol`] if the protocol fails and can't be completed.
    pub fn batch_evaluate_prepare<'a, I: Iterator<Item = &'a BlindedElement<CS>>>(
        &self,
        blinded_elements: I,
        metadata: Option<&[u8]>,
    ) -> Result<PoprfServerBatchEvaluatePrepareResult<'a, CS, I>> {
        // https://www.ietf.org/archive/id/draft-irtf-cfrg-voprf-08.html#section-3.3.2.1-1

        let context_string = create_context_string::<CS>(Mode::Poprf);
        let metadata = metadata.unwrap_or_default();

        // context = "Context-" || contextString || I2OSP(len(info), 2) || info
        let context = GenericArray::from(STR_CONTEXT)
            .concat(context_string)
            .concat(i2osp_2(metadata.len()).map_err(|_| Error::Metadata)?);
        let context = [&context, metadata];

        let m =
            CS::Group::hash_to_scalar::<CS>(&context, Mode::Poprf).map_err(|_| Error::Metadata)?;
        let t = self.sk + &m;

        // if t == 0:
        if bool::from(CS::Group::is_zero_scalar(t)) {
            // raise InverseError
            return Err(Error::Protocol);
        }

        let evaluation_elements = blinded_elements
            // To make a return type possible, we have to convert to a `fn` pointer, which isn't
            // possible if we `move` from context.
            .zip(iter::repeat(CS::Group::invert_scalar(t)))
            .map(<fn((&BlindedElement<CS>, _)) -> _>::from(|(x, t)| {
                PreparedEvaluationElement(EvaluationElement(x.0 * &t))
            }));

        Ok(PoprfServerBatchEvaluatePrepareResult {
            prepared_evaluation_elements: evaluation_elements,
            t: PreparedTscalar(t),
        })
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

/// Concrete return type for [`PoprfClient::batch_finalize`].
pub type PoprfClientBatchFinalizeResult<'a, C, I, II, IC, IM> = FinalizeAfterUnblindResult<
    'a,
    C,
    I,
    Zip<<&'a II as IntoIterator>::IntoIter, VerifiableUnblindResult<'a, C, IC, IM>>,
>;

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

/// Contains prepared [`EvaluationElement`]s by a verifiable server batch
/// evaluate preparation.
#[derive_where(Clone, ZeroizeOnDrop)]
#[derive_where(Debug, Eq, Hash, Ord, PartialEq, PartialOrd; <CS::Group as Group>::Elem)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(crate = "serde", bound = "")
)]
pub struct PreparedEvaluationElement<CS: CipherSuite>(EvaluationElement<CS>)
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>;

/// Contains the prepared `t` by a verifiable server batch evaluate preparation.
#[derive_where(Clone, ZeroizeOnDrop)]
#[derive_where(Debug, Eq, Hash, Ord, PartialEq, PartialOrd; <CS::Group as Group>::Scalar)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(crate = "serde", bound = "")
)]
pub struct PreparedTscalar<CS: CipherSuite>(
    #[cfg_attr(feature = "serde", serde(with = "Scalar::<CS::Group>"))]
    <CS::Group as Group>::Scalar,
)
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>;

/// Concrete type of [`EvaluationElement`]s in
/// [`PoprfServerBatchEvaluatePrepareResult`].
pub type PoprfServerBatchEvaluatePreparedEvaluationElements<CS, I> = Map<
    Zip<I, Repeat<<<CS as CipherSuite>::Group as Group>::Scalar>>,
    fn(
        (
            &BlindedElement<CS>,
            <<CS as CipherSuite>::Group as Group>::Scalar,
        ),
    ) -> PreparedEvaluationElement<CS>,
>;

/// Contains the fields that are returned by a verifiable server batch evaluate
/// preparation.
#[derive_where(Debug; I, <CS::Group as Group>::Scalar)]
pub struct PoprfServerBatchEvaluatePrepareResult<
    'a,
    CS: 'a + CipherSuite,
    I: Iterator<Item = &'a BlindedElement<CS>>,
> where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
{
    /// Prepared [`EvaluationElement`]s that will become messages.
    pub prepared_evaluation_elements: PoprfServerBatchEvaluatePreparedEvaluationElements<CS, I>,
    /// Prepared `t` needed to finish the verifiable server batch evaluation.
    pub t: PreparedTscalar<CS>,
}

/// Concrete type of [`EvaluationElement`]s in
/// [`PoprfServerBatchEvaluateWithoutAllocMessages`].
pub type PoprfServerBatchEvaluateWithoutAllocMessages<CS, I> = Map<
    Zip<I, Repeat<<<CS as CipherSuite>::Group as Group>::Scalar>>,
    fn(
        (
            &BlindedElement<CS>,
            <<CS as CipherSuite>::Group as Group>::Scalar,
        ),
    ) -> EvaluationElement<CS>,
>;

/// Contains the fields that are returned by a verifiable server batch evaluate.
#[derive_where(Debug; I, <CS::Group as Group>::Scalar)]
pub struct PoprfServerBatchEvaluateWithoutAllocResult<'a, CS: 'a + CipherSuite, I>
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
    I: IntoIterator<Item = &'a BlindedElement<CS>>,
{
    /// The [`EvaluationElement`]s to send to the client
    pub messages: PoprfServerBatchEvaluateWithoutAllocMessages<CS, I>,
    /// The proof for the client to verify
    pub proof: Proof<CS>,
}

/// Concrete type of [`EvaluationElement`]s in
/// [`PoprfServerBatchEvaluateFinishResult`].
pub type PoprfServerBatchEvaluateFinishedMessages<'a, CS, I> =
    Map<<&'a I as IntoIterator>::IntoIter, fn(&BlindedElement<CS>) -> EvaluationElement<CS>>;

/// Contains the fields that are returned by a verifiable server batch evaluate
/// finish.
#[derive_where(Debug; <&'a I as core::iter::IntoIterator>::IntoIter, <CS::Group as Group>::Scalar)]
pub struct PoprfServerBatchEvaluateFinishResult<'a, CS: 'a + CipherSuite, I>
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
    &'a I: IntoIterator<Item = &'a BlindedElement<CS>>,
{
    /// The [`EvaluationElement`]s to send to the client
    pub messages: PoprfServerBatchEvaluateFinishedMessages<'a, CS, I>,
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

type VerifiableUnblindResult<'a, CS, IC, IM> = Map<
    Zip<
        Map<
            <&'a IC as IntoIterator>::IntoIter,
            fn(&PoprfClient<CS>) -> <<CS as CipherSuite>::Group as Group>::Scalar,
        >,
        <&'a IM as IntoIterator>::IntoIter,
    >,
    fn(
        (
            <<CS as CipherSuite>::Group as Group>::Scalar,
            &EvaluationElement<CS>,
        ),
    ) -> <<CS as CipherSuite>::Group as Group>::Elem,
>;

// Can only fail with [`Error::Metadata`], [`Error::Batch] or
// [`Error::ProofVerification`].
fn verifiable_unblind<'a, CS: 'a + CipherSuite, IC, IM>(
    clients: &'a IC,
    messages: &'a IM,
    pk: <CS::Group as Group>::Elem,
    proof: &Proof<CS>,
    info: &[u8],
) -> Result<VerifiableUnblindResult<'a, CS, IC, IM>>
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
    &'a IC: 'a + IntoIterator<Item = &'a PoprfClient<CS>>,
    <&'a IC as IntoIterator>::IntoIter: ExactSizeIterator,
    &'a IM: 'a + IntoIterator<Item = &'a EvaluationElement<CS>>,
    <&'a IM as IntoIterator>::IntoIter: ExactSizeIterator,
{
    // https://www.ietf.org/archive/id/draft-irtf-cfrg-voprf-08.html#section-3.3.4.2-2

    let context_string = create_context_string::<CS>(Mode::Poprf);

    // context = "Context-" || contextString || I2OSP(len(info), 2) || info
    let context = GenericArray::from(STR_CONTEXT)
        .concat(context_string)
        .concat(i2osp_2(info.len()).map_err(|_| Error::Metadata)?);
    let context = [&context, info];

    // The `input` used here is the metadata.
    let m = CS::Group::hash_to_scalar::<CS>(&context, Mode::Poprf).map_err(|_| Error::Metadata)?;

    let g = CS::Group::base_elem();
    let t = g * &m;
    let u = t + &pk;

    let blinds = clients
        .into_iter()
        // Convert to `fn` pointer to make a return type possible.
        .map(<fn(&PoprfClient<CS>) -> _>::from(|x| x.blind));
    let evaluation_elements = messages.into_iter().map(|element| element.0);
    let blinded_elements = clients.into_iter().map(|client| client.blinded_element);

    verify_proof(g, pk, blinded_elements, evaluation_elements, proof)?;

    Ok(blinds
        .zip(messages.into_iter())
        .map(|(blind, x)| x.0 * &CS::Group::invert_scalar(blind)))
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

    fn verifiable_retrieval<CS: CipherSuite>()
    where
        <CS::Hash as OutputSizeUser>::OutputSize:
            IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
    {
        let input = b"input";
        let info = b"info";
        let mut rng = OsRng;
        let client_blind_result = PoprfClient::<CS>::blind(input, &mut rng).unwrap();
        let server = PoprfServer::<CS>::new(&mut rng);
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
        let client_blind_result = PoprfClient::<CS>::blind(input, &mut rng).unwrap();
        let server = PoprfServer::<CS>::new(&mut rng);
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
        let client_blind_result = PoprfClient::<CS>::blind(input, &mut rng).unwrap();

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
        let client_blind_result = PoprfClient::<CS>::blind(input, &mut rng).unwrap();
        let server = PoprfServer::<CS>::new(&mut rng);
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

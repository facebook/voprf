// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Contains the main VOPRF API

#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use core::iter::{self, Map, Repeat, Zip};

use derive_where::DeriveWhere;
use digest::core_api::BlockSizeUser;
use digest::{Digest, Output, OutputSizeUser};
use generic_array::sequence::Concat;
use generic_array::typenum::{IsLess, IsLessOrEqual, Unsigned, U11, U20, U256};
use generic_array::GenericArray;
use rand_core::{CryptoRng, RngCore};
use subtle::ConstantTimeEq;

use crate::util::{i2osp_2, i2osp_2_array};
use crate::{CipherSuite, Error, Group, Result};

///////////////
// Constants //
// ========= //
///////////////

const STR_FINALIZE: [u8; 9] = *b"Finalize-";
const STR_SEED: [u8; 5] = *b"Seed-";
const STR_CONTEXT: [u8; 8] = *b"Context-";
const STR_COMPOSITE: [u8; 10] = *b"Composite-";
const STR_CHALLENGE: [u8; 10] = *b"Challenge-";
const STR_VOPRF: [u8; 8] = *b"VOPRF08-";

/// Determines the mode of operation (either base mode or verifiable mode). This
/// is only used for custom implementations for [`Group`].
#[derive(Clone, Copy)]
pub enum Mode {
    /// Non-verifiable mode.
    Base,
    /// Verifiable mode.
    Verifiable,
}

impl Mode {
    /// Mode as it is represented in a context string.
    pub fn to_u8(self) -> u8 {
        match self {
            Mode::Base => 0,
            Mode::Verifiable => 1,
        }
    }
}

////////////////////////////
// High-level API Structs //
// ====================== //
////////////////////////////

/// A client which engages with a [NonVerifiableServer] in base mode, meaning
/// that the OPRF outputs are not verifiable.
#[derive(DeriveWhere)]
#[derive_where(Clone, Zeroize(drop))]
#[derive_where(Debug, Eq, Hash, Ord, PartialEq, PartialOrd; <CS::Group as Group>::Scalar)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(bound(
        deserialize = "<CS::Group as Group>::Scalar: serde::Deserialize<'de>",
        serialize = "<CS::Group as Group>::Scalar: serde::Serialize"
    ))
)]
pub struct NonVerifiableClient<CS: CipherSuite>
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
{
    pub(crate) blind: <CS::Group as Group>::Scalar,
}

/// A client which engages with a [VerifiableServer] in verifiable mode, meaning
/// that the OPRF outputs can be checked against a server public key.
#[derive(DeriveWhere)]
#[derive_where(Clone, Zeroize(drop))]
#[derive_where(Debug, Eq, Hash, Ord, PartialEq, PartialOrd; <CS::Group as Group>::Scalar, <CS::Group as Group>::Elem)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(bound(
        deserialize = "<CS::Group as Group>::Scalar: serde::Deserialize<'de>, <CS::Group as \
                       Group>::Elem: serde::Deserialize<'de>",
        serialize = "<CS::Group as Group>::Scalar: serde::Serialize, <CS::Group as Group>::Elem: \
                     serde::Serialize"
    ))
)]
pub struct VerifiableClient<CS: CipherSuite>
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
{
    pub(crate) blind: <CS::Group as Group>::Scalar,
    pub(crate) blinded_element: <CS::Group as Group>::Elem,
}

/// A server which engages with a [NonVerifiableClient] in base mode, meaning
/// that the OPRF outputs are not verifiable.
#[derive(DeriveWhere)]
#[derive_where(Clone, Zeroize(drop))]
#[derive_where(Debug, Eq, Hash, Ord, PartialEq, PartialOrd; <CS::Group as Group>::Scalar)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(bound(
        deserialize = "<CS::Group as Group>::Scalar: serde::Deserialize<'de>",
        serialize = "<CS::Group as Group>::Scalar: serde::Serialize"
    ))
)]
pub struct NonVerifiableServer<CS: CipherSuite>
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
{
    pub(crate) sk: <CS::Group as Group>::Scalar,
}

/// A server which engages with a [VerifiableClient] in verifiable mode, meaning
/// that the OPRF outputs can be checked against a server public key.
#[derive(DeriveWhere)]
#[derive_where(Clone, Zeroize(drop))]
#[derive_where(Debug, Eq, Hash, Ord, PartialEq, PartialOrd; <CS::Group as Group>::Scalar, <CS::Group as Group>::Elem)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(bound(
        deserialize = "<CS::Group as Group>::Scalar: serde::Deserialize<'de>, <CS::Group as \
                       Group>::Elem: serde::Deserialize<'de>",
        serialize = "<CS::Group as Group>::Scalar: serde::Serialize, <CS::Group as Group>::Elem: \
                     serde::Serialize"
    ))
)]
pub struct VerifiableServer<CS: CipherSuite>
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
{
    pub(crate) sk: <CS::Group as Group>::Scalar,
    pub(crate) pk: <CS::Group as Group>::Elem,
}

/// A proof produced by a [VerifiableServer] that the OPRF output matches
/// against a server public key.
#[derive(DeriveWhere)]
#[derive_where(Clone, Zeroize(drop))]
#[derive_where(Debug, Eq, Hash, Ord, PartialEq, PartialOrd; <CS::Group as Group>::Scalar)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(bound(
        deserialize = "<CS::Group as Group>::Scalar: serde::Deserialize<'de>",
        serialize = "<CS::Group as Group>::Scalar: serde::Serialize"
    ))
)]
pub struct Proof<CS: CipherSuite>
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
{
    pub(crate) c_scalar: <CS::Group as Group>::Scalar,
    pub(crate) s_scalar: <CS::Group as Group>::Scalar,
}

/// The first client message sent from a client (either verifiable or not) to a
/// server (either verifiable or not).
#[derive(DeriveWhere)]
#[derive_where(Clone, Zeroize(drop))]
#[derive_where(Debug, Eq, Hash, Ord, PartialEq, PartialOrd; <CS::Group as Group>::Elem)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(bound(
        deserialize = "<CS::Group as Group>::Elem: serde::Deserialize<'de>",
        serialize = "<CS::Group as Group>::Elem: serde::Serialize"
    ))
)]
pub struct BlindedElement<CS: CipherSuite>(pub(crate) <CS::Group as Group>::Elem)
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>;

/// The server's response to the [BlindedElement] message from a client (either
/// verifiable or not) to a server (either verifiable or not).
#[derive(DeriveWhere)]
#[derive_where(Clone, Zeroize(drop))]
#[derive_where(Debug, Eq, Hash, Ord, PartialEq, PartialOrd; <CS::Group as Group>::Elem)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(bound(
        deserialize = "<CS::Group as Group>::Elem: serde::Deserialize<'de>",
        serialize = "<CS::Group as Group>::Elem: serde::Serialize"
    ))
)]
pub struct EvaluationElement<CS: CipherSuite>(pub(crate) <CS::Group as Group>::Elem)
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>;

/////////////////////////
// API Implementations //
// =================== //
/////////////////////////

impl<CS: CipherSuite> NonVerifiableClient<CS>
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
{
    /// Computes the first step for the multiplicative blinding version of
    /// DH-OPRF.
    pub fn blind<R: RngCore + CryptoRng>(
        input: &[u8],
        blinding_factor_rng: &mut R,
    ) -> Result<NonVerifiableClientBlindResult<CS>> {
        let (blind, blinded_element) = blind::<CS, _>(input, blinding_factor_rng, Mode::Base)?;
        Ok(NonVerifiableClientBlindResult {
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
    pub fn deterministic_blind_unchecked(
        input: &[u8],
        blind: <CS::Group as Group>::Scalar,
    ) -> Result<NonVerifiableClientBlindResult<CS>> {
        let blinded_element = deterministic_blind_unchecked::<CS>(input, &blind, Mode::Base)?;
        Ok(NonVerifiableClientBlindResult {
            state: Self { blind },
            message: BlindedElement(blinded_element),
        })
    }

    /// Computes the third step for the multiplicative blinding version of
    /// DH-OPRF, in which the client unblinds the server's message.
    pub fn finalize(
        &self,
        input: &[u8],
        evaluation_element: &EvaluationElement<CS>,
        metadata: Option<&[u8]>,
    ) -> Result<Output<CS::Hash>> {
        let unblinded_element = evaluation_element.0 * &CS::Group::invert_scalar(self.blind);
        let mut outputs = finalize_after_unblind::<CS, _, _>(
            Some((input, unblinded_element)).into_iter(),
            metadata.unwrap_or_default(),
            Mode::Base,
        )?;
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

impl<CS: CipherSuite> VerifiableClient<CS>
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
{
    /// Computes the first step for the multiplicative blinding version of
    /// DH-OPRF.
    pub fn blind<R: RngCore + CryptoRng>(
        input: &[u8],
        blinding_factor_rng: &mut R,
    ) -> Result<VerifiableClientBlindResult<CS>> {
        let (blind, blinded_element) =
            blind::<CS, _>(input, blinding_factor_rng, Mode::Verifiable)?;
        Ok(VerifiableClientBlindResult {
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
    pub fn deterministic_blind_unchecked(
        input: &[u8],
        blind: <CS::Group as Group>::Scalar,
    ) -> Result<VerifiableClientBlindResult<CS>> {
        let blinded_element = deterministic_blind_unchecked::<CS>(input, &blind, Mode::Verifiable)?;
        Ok(VerifiableClientBlindResult {
            state: Self {
                blind,
                blinded_element,
            },
            message: BlindedElement(blinded_element),
        })
    }

    /// Computes the third step for the multiplicative blinding version of
    /// DH-OPRF, in which the client unblinds the server's message.
    pub fn finalize(
        &self,
        input: &[u8],
        evaluation_element: &EvaluationElement<CS>,
        proof: &Proof<CS>,
        pk: <CS::Group as Group>::Elem,
        metadata: Option<&[u8]>,
    ) -> Result<Output<CS::Hash>> {
        let inputs: &[&[u8]; 1] = core::array::from_ref(&input);
        let clients: &[Self; 1] = core::array::from_ref(self);
        let messages: &[EvaluationElement<CS>; 1] = core::array::from_ref(evaluation_element);

        let mut batch_result =
            Self::batch_finalize(inputs, clients, messages, proof, pk, metadata)?;
        batch_result.next().unwrap()
    }

    /// Allows for batching of the finalization of multiple [VerifiableClient]
    /// and [EvaluationElement] pairs
    pub fn batch_finalize<'a, I: 'a, II, IC, IM>(
        inputs: &'a II,
        clients: &'a IC,
        messages: &'a IM,
        proof: &Proof<CS>,
        pk: <CS::Group as Group>::Elem,
        metadata: Option<&'a [u8]>,
    ) -> Result<VerifiableClientBatchFinalizeResult<'a, CS, I, II, IC, IM>>
    where
        CS: 'a,
        I: AsRef<[u8]>,
        &'a II: 'a + IntoIterator<Item = I>,
        <&'a II as IntoIterator>::IntoIter: ExactSizeIterator,
        &'a IC: 'a + IntoIterator<Item = &'a VerifiableClient<CS>>,
        <&'a IC as IntoIterator>::IntoIter: ExactSizeIterator,
        &'a IM: 'a + IntoIterator<Item = &'a EvaluationElement<CS>>,
        <&'a IM as IntoIterator>::IntoIter: ExactSizeIterator,
    {
        let metadata = metadata.unwrap_or_default();

        let unblinded_elements = verifiable_unblind(clients, messages, pk, proof, metadata)?;

        let inputs_and_unblinded_elements = inputs.into_iter().zip(unblinded_elements);

        finalize_after_unblind::<CS, _, _>(
            inputs_and_unblinded_elements,
            metadata,
            Mode::Verifiable,
        )
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

impl<CS: CipherSuite> NonVerifiableServer<CS>
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
{
    /// Produces a new instance of a [NonVerifiableServer] using a supplied RNG
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Result<Self> {
        let mut seed = Output::<CS::Hash>::default();
        rng.fill_bytes(&mut seed);
        Self::new_from_seed(&seed)
    }

    /// Produces a new instance of a [NonVerifiableServer] using a supplied set
    /// of bytes to represent the server's private key
    pub fn new_with_key(private_key_bytes: &[u8]) -> Result<Self> {
        let sk = CS::Group::deserialize_scalar(private_key_bytes.into())?;
        Ok(Self { sk })
    }

    /// Produces a new instance of a [NonVerifiableServer] using a supplied set
    /// of bytes which are used as a seed to derive the server's private key.
    ///
    /// Corresponds to DeriveKeyPair() function from the VOPRF specification.
    pub fn new_from_seed(seed: &[u8]) -> Result<Self> {
        let sk = CS::Group::hash_to_scalar::<CS::Hash>(&[seed], Mode::Base)?;
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
    pub fn evaluate(
        &self,
        blinded_element: &BlindedElement<CS>,
        metadata: Option<&[u8]>,
    ) -> Result<NonVerifiableServerEvaluateResult<CS>> {
        // https://www.ietf.org/archive/id/draft-irtf-cfrg-voprf-08.html#section-3.3.1.1-1

        let context_string = get_context_string::<CS::Group>(Mode::Base);
        let metadata = metadata.unwrap_or_default();

        // context = "Context-" || contextString || I2OSP(len(info), 2) || info
        let context = GenericArray::from(STR_CONTEXT)
            .concat(context_string)
            .concat(i2osp_2(metadata.len())?);
        let context = [&context, metadata];

        // m = GG.HashToScalar(context)
        let m = CS::Group::hash_to_scalar::<CS::Hash>(&context, Mode::Base)?;
        // t = skS + m
        let t = self.sk + &m;
        // Z = t^(-1) * R
        let z = blinded_element.0 * &CS::Group::invert_scalar(t);

        Ok(NonVerifiableServerEvaluateResult {
            message: EvaluationElement(z),
        })
    }
}

impl<CS: CipherSuite> VerifiableServer<CS>
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
{
    /// Produces a new instance of a [VerifiableServer] using a supplied RNG
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Result<Self> {
        let mut seed = Output::<CS::Hash>::default();
        rng.fill_bytes(&mut seed);
        Self::new_from_seed(&seed)
    }

    /// Produces a new instance of a [VerifiableServer] using a supplied set of
    /// bytes to represent the server's private key
    pub fn new_with_key(key: &[u8]) -> Result<Self> {
        let sk = CS::Group::deserialize_scalar(key.into())?;
        let pk = CS::Group::base_elem() * &sk;
        Ok(Self { sk, pk })
    }

    /// Produces a new instance of a [VerifiableServer] using a supplied set of
    /// bytes which are used as a seed to derive the server's private key.
    ///
    /// Corresponds to DeriveKeyPair() function from the VOPRF specification.
    pub fn new_from_seed(seed: &[u8]) -> Result<Self> {
        let sk = CS::Group::hash_to_scalar::<CS::Hash>(&[seed], Mode::Verifiable)?;
        let pk = CS::Group::base_elem() * &sk;
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
    pub fn evaluate<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        blinded_element: &BlindedElement<CS>,
        metadata: Option<&[u8]>,
    ) -> Result<VerifiableServerEvaluateResult<CS>> {
        let VerifiableServerBatchEvaluatePrepareResult {
            prepared_evaluation_elements: mut evaluation_elements,
            t,
        } = self.batch_evaluate_prepare(Some(blinded_element).into_iter(), metadata)?;

        let prepared_element = [evaluation_elements.next().unwrap()];

        let VerifiableServerBatchEvaluateFinishResult {
            mut messages,
            proof,
        } = Self::batch_evaluate_finish(
            rng,
            Some(blinded_element).into_iter(),
            &prepared_element,
            &t,
        )?;

        let message = messages.next().unwrap();

        //let batch_result = self.batch_evaluate(rng, blinded_elements, metadata)?;
        Ok(VerifiableServerEvaluateResult { message, proof })
    }

    /// Allows for batching of the evaluation of multiple [BlindedElement]
    /// messages from a [VerifiableClient]
    #[cfg(feature = "alloc")]
    pub fn batch_evaluate<'a, R: RngCore + CryptoRng, I>(
        &self,
        rng: &mut R,
        blinded_elements: &'a I,
        metadata: Option<&[u8]>,
    ) -> Result<VerifiableServerBatchEvaluateResult<CS>>
    where
        CS: 'a,
        &'a I: IntoIterator<Item = &'a BlindedElement<CS>>,
        <&'a I as IntoIterator>::IntoIter: ExactSizeIterator,
    {
        let VerifiableServerBatchEvaluatePrepareResult {
            prepared_evaluation_elements: evaluation_elements,
            t,
        } = self.batch_evaluate_prepare(blinded_elements.into_iter(), metadata)?;

        let prepared_elements = evaluation_elements.collect();

        let VerifiableServerBatchEvaluateFinishResult { messages, proof } =
            Self::batch_evaluate_finish::<_, _, Vec<_>>(
                rng,
                blinded_elements.into_iter(),
                &prepared_elements,
                &t,
            )?;

        Ok(VerifiableServerBatchEvaluateResult {
            messages: messages.collect(),
            proof,
        })
    }

    /// Alternative version of [`batch_evaluate`](Self::batch_evaluate) without
    /// memory allocation. Returned [`PreparedEvaluationElement`] have to be
    /// [`collect`](Iterator::collect)ed and passed into
    /// [`batch_evaluate_finish`](Self::batch_evaluate_finish).
    pub fn batch_evaluate_prepare<'a, I: Iterator<Item = &'a BlindedElement<CS>>>(
        &self,
        blinded_elements: I,
        metadata: Option<&[u8]>,
    ) -> Result<VerifiableServerBatchEvaluatePrepareResult<'a, CS, I>> {
        // https://www.ietf.org/archive/id/draft-irtf-cfrg-voprf-08.html#section-3.3.2.1-1

        let context_string = get_context_string::<CS::Group>(Mode::Verifiable);
        let metadata = metadata.unwrap_or_default();

        // context = "Context-" || contextString || I2OSP(len(info), 2) || info
        let context = GenericArray::from(STR_CONTEXT)
            .concat(context_string)
            .concat(i2osp_2(metadata.len())?);
        let context = [&context, metadata];

        let m = CS::Group::hash_to_scalar::<CS::Hash>(&context, Mode::Verifiable)?;
        let t = self.sk + &m;
        let evaluation_elements = blinded_elements
            // To make a return type possible, we have to convert to a `fn` pointer, which isn't
            // possible if we `move` from context.
            .zip(iter::repeat(CS::Group::invert_scalar(t)))
            .map(<fn((&BlindedElement<CS>, _)) -> _>::from(|(x, t)| {
                PreparedEvaluationElement(EvaluationElement(x.0 * &t))
            }));

        Ok(VerifiableServerBatchEvaluatePrepareResult {
            prepared_evaluation_elements: evaluation_elements,
            t: PreparedTscalar(t),
        })
    }

    /// See [`batch_evaluate_prepare`](Self::batch_evaluate_prepare) for more
    /// details.
    pub fn batch_evaluate_finish<'a, 'b, R: RngCore + CryptoRng, IB, IE>(
        rng: &mut R,
        blinded_elements: IB,
        evaluation_elements: &'b IE,
        PreparedTscalar(t): &PreparedTscalar<CS>,
    ) -> Result<VerifiableServerBatchEvaluateFinishResult<'b, CS, IE>>
    where
        CS: 'a + 'b,
        IB: Iterator<Item = &'a BlindedElement<CS>> + ExactSizeIterator,
        &'b IE: IntoIterator<Item = &'b PreparedEvaluationElement<CS>>,
        <&'b IE as IntoIterator>::IntoIter: ExactSizeIterator,
    {
        let g = CS::Group::base_elem();
        let u = g * t;

        let proof = generate_proof(
            rng,
            *t,
            g,
            u,
            evaluation_elements
                .into_iter()
                .map(|element| element.0.copy()),
            blinded_elements.map(BlindedElement::copy),
        )?;
        let messages =
            evaluation_elements
                .into_iter()
                .map(<fn(&PreparedEvaluationElement<CS>) -> _>::from(|element| {
                    element.0.copy()
                }));

        Ok(VerifiableServerBatchEvaluateFinishResult { messages, proof })
    }

    /// Retrieves the server's public key
    pub fn get_public_key(&self) -> <CS::Group as Group>::Elem {
        self.pk
    }
}

/////////////////////////
// Convenience Structs //
//==================== //
/////////////////////////

/// Contains the fields that are returned by a non-verifiable client blind
pub struct NonVerifiableClientBlindResult<CS: CipherSuite>
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
{
    /// The state to be persisted on the client
    pub state: NonVerifiableClient<CS>,
    /// The message to send to the server
    pub message: BlindedElement<CS>,
}

/// Contains the fields that are returned by a non-verifiable server evaluate
pub struct NonVerifiableServerEvaluateResult<CS: CipherSuite>
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
{
    /// The message to send to the client
    pub message: EvaluationElement<CS>,
}

/// Contains the fields that are returned by a verifiable client blind
pub struct VerifiableClientBlindResult<CS: CipherSuite>
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
{
    /// The state to be persisted on the client
    pub state: VerifiableClient<CS>,
    /// The message to send to the server
    pub message: BlindedElement<CS>,
}

/// Concrete return type for [`VerifiableClient::batch_finalize`].
pub type VerifiableClientBatchFinalizeResult<'a, C, I, II, IC, IM> = FinalizeAfterUnblindResult<
    'a,
    C,
    I,
    Zip<<&'a II as IntoIterator>::IntoIter, VerifiableUnblindResult<'a, C, IC, IM>>,
>;

/// Contains the fields that are returned by a verifiable server evaluate
pub struct VerifiableServerEvaluateResult<CS: CipherSuite>
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
pub struct PreparedEvaluationElement<CS: CipherSuite>(EvaluationElement<CS>)
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>;

/// Contains the prepared `t` by a verifiable server batch evaluate preparation.
#[derive(DeriveWhere)]
#[derive_where(Zeroize(drop))]
pub struct PreparedTscalar<CS: CipherSuite>(<CS::Group as Group>::Scalar)
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>;

/// Contains the fields that are returned by a verifiable server batch evaluate
/// preparation.
pub struct VerifiableServerBatchEvaluatePrepareResult<
    'a,
    CS: 'a + CipherSuite,
    I: Iterator<Item = &'a BlindedElement<CS>>,
> where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
{
    /// Prepared [`EvaluationElement`]s that will become messages.
    #[allow(clippy::type_complexity)]
    pub prepared_evaluation_elements: Map<
        Zip<I, Repeat<<CS::Group as Group>::Scalar>>,
        fn((&BlindedElement<CS>, <CS::Group as Group>::Scalar)) -> PreparedEvaluationElement<CS>,
    >,
    /// Prepared `t` needed to finish the verifiable server batch evaluation.
    pub t: PreparedTscalar<CS>,
}

/// Contains the fields that are returned by a verifiable server batch evaluate
/// finish.
pub struct VerifiableServerBatchEvaluateFinishResult<'a, CS: 'a + CipherSuite, I>
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
    &'a I: IntoIterator<Item = &'a PreparedEvaluationElement<CS>>,
{
    /// The messages to send to the client
    #[allow(clippy::type_complexity)]
    pub messages: Map<
        <&'a I as IntoIterator>::IntoIter,
        fn(&PreparedEvaluationElement<CS>) -> EvaluationElement<CS>,
    >,
    /// The proof for the client to verify
    pub proof: Proof<CS>,
}

/// Contains the fields that are returned by a verifiable server batch evaluate
#[cfg(feature = "alloc")]
pub struct VerifiableServerBatchEvaluateResult<CS: CipherSuite>
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
{
    /// The messages to send to the client
    pub messages: alloc::vec::Vec<EvaluationElement<CS>>,
    /// The proof for the client to verify
    pub proof: Proof<CS>,
}

///////////////////////////////////////////////
// Inner functions and Trait Implementations //
// ========================================= //
///////////////////////////////////////////////

impl<CS: CipherSuite> BlindedElement<CS>
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
{
    /// Only used to easier validate allocation
    fn copy(&self) -> Self {
        Self(self.0)
    }

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
    /// Only used to easier validate allocation
    fn copy(&self) -> Self {
        Self(self.0)
    }

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

// Inner function for blind. Returns the blind scalar and the blinded element
fn blind<CS: CipherSuite, R: RngCore + CryptoRng>(
    input: &[u8],
    blinding_factor_rng: &mut R,
    mode: Mode,
) -> Result<(<CS::Group as Group>::Scalar, <CS::Group as Group>::Elem)>
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
fn deterministic_blind_unchecked<CS: CipherSuite>(
    input: &[u8],
    blind: &<CS::Group as Group>::Scalar,
    mode: Mode,
) -> Result<<CS::Group as Group>::Elem>
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
{
    let hashed_point = CS::Group::hash_to_curve::<CS::Hash>(&[input], mode)?;
    Ok(hashed_point * blind)
}

type VerifiableUnblindResult<'a, CS, IC, IM> = Map<
    Zip<
        Map<
            <&'a IC as IntoIterator>::IntoIter,
            fn(&VerifiableClient<CS>) -> <<CS as CipherSuite>::Group as Group>::Scalar,
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
    &'a IC: 'a + IntoIterator<Item = &'a VerifiableClient<CS>>,
    <&'a IC as IntoIterator>::IntoIter: ExactSizeIterator,
    &'a IM: 'a + IntoIterator<Item = &'a EvaluationElement<CS>>,
    <&'a IM as IntoIterator>::IntoIter: ExactSizeIterator,
{
    // https://www.ietf.org/archive/id/draft-irtf-cfrg-voprf-08.html#section-3.3.4.2-2

    let context_string = get_context_string::<CS::Group>(Mode::Verifiable);

    // context = "Context-" || contextString || I2OSP(len(info), 2) || info
    let context = GenericArray::from(STR_CONTEXT)
        .concat(context_string)
        .concat(i2osp_2(info.len())?);
    let context = [&context, info];

    let m = CS::Group::hash_to_scalar::<CS::Hash>(&context, Mode::Verifiable)?;

    let g = CS::Group::base_elem();
    let t = g * &m;
    let u = t + &pk;

    let blinds = clients
        .into_iter()
        // Convert to `fn` pointer to make a return type possible.
        .map(<fn(&VerifiableClient<CS>) -> _>::from(|x| x.blind));
    let evaluation_elements = messages.into_iter().map(EvaluationElement::copy);
    let blinded_elements = clients
        .into_iter()
        .map(|client| BlindedElement(client.blinded_element));

    verify_proof(g, u, evaluation_elements, blinded_elements, proof)?;

    Ok(blinds
        .zip(messages.into_iter())
        .map(|(blind, x)| x.0 * &CS::Group::invert_scalar(blind)))
}

#[allow(clippy::many_single_char_names)]
fn generate_proof<CS: CipherSuite, R: RngCore + CryptoRng>(
    rng: &mut R,
    k: <CS::Group as Group>::Scalar,
    a: <CS::Group as Group>::Elem,
    b: <CS::Group as Group>::Elem,
    cs: impl Iterator<Item = EvaluationElement<CS>> + ExactSizeIterator,
    ds: impl Iterator<Item = BlindedElement<CS>> + ExactSizeIterator,
) -> Result<Proof<CS>>
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
{
    // https://www.ietf.org/archive/id/draft-irtf-cfrg-voprf-08.html#section-3.3.2.2-1

    let (m, z) = compute_composites(Some(k), b, cs, ds)?;

    let r = CS::Group::random_scalar(rng);
    let t2 = a * &r;
    let t3 = m * &r;

    // Bm = GG.SerializeElement(B)
    let bm = CS::Group::serialize_elem(b);
    // a0 = GG.SerializeElement(M)
    let a0 = CS::Group::serialize_elem(m);
    // a1 = GG.SerializeElement(Z)
    let a1 = CS::Group::serialize_elem(z);
    // a2 = GG.SerializeElement(t2)
    let a2 = CS::Group::serialize_elem(t2);
    // a3 = GG.SerializeElement(t3)
    let a3 = CS::Group::serialize_elem(t3);

    let elem_len = <CS::Group as Group>::ElemLen::U16.to_be_bytes();

    // challengeDST = "Challenge-" || contextString
    let challenge_dst =
        GenericArray::from(STR_CHALLENGE).concat(get_context_string::<CS::Group>(Mode::Verifiable));
    let challenge_dst_len = i2osp_2_array(challenge_dst);
    // h2Input = I2OSP(len(Bm), 2) || Bm ||
    //           I2OSP(len(a0), 2) || a0 ||
    //           I2OSP(len(a1), 2) || a1 ||
    //           I2OSP(len(a2), 2) || a2 ||
    //           I2OSP(len(a3), 2) || a3 ||
    //           I2OSP(len(challengeDST), 2) || challengeDST
    let h2_input = [
        &elem_len,
        bm.as_slice(),
        &elem_len,
        &a0,
        &elem_len,
        &a1,
        &elem_len,
        &a2,
        &elem_len,
        &a3,
        &challenge_dst_len,
        &challenge_dst,
    ];

    let c_scalar = CS::Group::hash_to_scalar::<CS::Hash>(&h2_input, Mode::Verifiable)?;
    let s_scalar = r - &(c_scalar * &k);

    Ok(Proof { c_scalar, s_scalar })
}

#[allow(clippy::many_single_char_names)]
fn verify_proof<CS: CipherSuite>(
    a: <CS::Group as Group>::Elem,
    b: <CS::Group as Group>::Elem,
    cs: impl Iterator<Item = EvaluationElement<CS>> + ExactSizeIterator,
    ds: impl Iterator<Item = BlindedElement<CS>> + ExactSizeIterator,
    proof: &Proof<CS>,
) -> Result<()>
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
{
    // https://www.ietf.org/archive/id/draft-irtf-cfrg-voprf-08.html#section-3.3.4.1-2
    let (m, z) = compute_composites(None, b, cs, ds)?;
    let t2 = (a * &proof.s_scalar) + &(b * &proof.c_scalar);
    let t3 = (m * &proof.s_scalar) + &(z * &proof.c_scalar);

    // Bm = GG.SerializeElement(B)
    let bm = CS::Group::serialize_elem(b);
    // a0 = GG.SerializeElement(M)
    let a0 = CS::Group::serialize_elem(m);
    // a1 = GG.SerializeElement(Z)
    let a1 = CS::Group::serialize_elem(z);
    // a2 = GG.SerializeElement(t2)
    let a2 = CS::Group::serialize_elem(t2);
    // a3 = GG.SerializeElement(t3)
    let a3 = CS::Group::serialize_elem(t3);

    let elem_len = <CS::Group as Group>::ElemLen::U16.to_be_bytes();

    // challengeDST = "Challenge-" || contextString
    let challenge_dst =
        GenericArray::from(STR_CHALLENGE).concat(get_context_string::<CS::Group>(Mode::Verifiable));
    let challenge_dst_len = i2osp_2_array(challenge_dst);
    // h2Input = I2OSP(len(Bm), 2) || Bm ||
    //           I2OSP(len(a0), 2) || a0 ||
    //           I2OSP(len(a1), 2) || a1 ||
    //           I2OSP(len(a2), 2) || a2 ||
    //           I2OSP(len(a3), 2) || a3 ||
    //           I2OSP(len(challengeDST), 2) || challengeDST
    let h2_input = [
        &elem_len,
        bm.as_slice(),
        &elem_len,
        &a0,
        &elem_len,
        &a1,
        &elem_len,
        &a2,
        &elem_len,
        &a3,
        &challenge_dst_len,
        &challenge_dst,
    ];

    let c = CS::Group::hash_to_scalar::<CS::Hash>(&h2_input, Mode::Verifiable)?;

    match c.ct_eq(&proof.c_scalar).into() {
        true => Ok(()),
        false => Err(Error::ProofVerificationError),
    }
}

type FinalizeAfterUnblindResult<'a, C, I, IE> = Map<
    Zip<IE, Repeat<(&'a [u8], GenericArray<u8, U20>)>>,
    fn(
        (
            (I, <<C as CipherSuite>::Group as Group>::Elem),
            (&'a [u8], GenericArray<u8, U20>),
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
    info: &'a [u8],
    mode: Mode,
) -> Result<FinalizeAfterUnblindResult<CS, I, IE>>
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
{
    // https://www.ietf.org/archive/id/draft-irtf-cfrg-voprf-08.html#section-3.3.3.2-2
    // https://www.ietf.org/archive/id/draft-irtf-cfrg-voprf-08.html#section-3.3.4.3-1

    // finalizeDST = "Finalize-" || contextString
    let finalize_dst =
        GenericArray::from(STR_FINALIZE).concat(get_context_string::<CS::Group>(mode));

    Ok(inputs_and_unblinded_elements
        // To make a return type possible, we have to convert to a `fn` pointer,
        // which isn't possible if we `move` from context.
        .zip(iter::repeat((info, finalize_dst)))
        .map(|((input, unblinded_element), (info, finalize_dst))| {
            let finalize_dst_len = i2osp_2_array(finalize_dst);
            let elem_len = <CS::Group as Group>::ElemLen::U16.to_be_bytes();

            // hashInput = I2OSP(len(input), 2) || input ||
            //             I2OSP(len(info), 2) || info ||
            //             I2OSP(len(unblindedElement), 2) || unblindedElement ||
            //             I2OSP(len(finalizeDST), 2) || finalizeDST
            // return Hash(hashInput)
            Ok(CS::Hash::new()
                .chain_update(i2osp_2(input.as_ref().len())?)
                .chain_update(input.as_ref())
                .chain_update(i2osp_2(info.len())?)
                .chain_update(info)
                .chain_update(elem_len)
                .chain_update(CS::Group::serialize_elem(unblinded_element))
                .chain_update(finalize_dst_len)
                .chain_update(finalize_dst)
                .finalize())
        }))
}

fn compute_composites<CS: CipherSuite>(
    k_option: Option<<CS::Group as Group>::Scalar>,
    b: <CS::Group as Group>::Elem,
    c_slice: impl Iterator<Item = EvaluationElement<CS>> + ExactSizeIterator,
    d_slice: impl Iterator<Item = BlindedElement<CS>> + ExactSizeIterator,
) -> Result<(<CS::Group as Group>::Elem, <CS::Group as Group>::Elem)>
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
{
    // https://www.ietf.org/archive/id/draft-irtf-cfrg-voprf-08.html#section-3.3.2.3-2

    let elem_len = <CS::Group as Group>::ElemLen::U16.to_be_bytes();

    if c_slice.len() != d_slice.len() {
        return Err(Error::MismatchedLengthsForCompositeInputs);
    }

    let len = u16::try_from(c_slice.len()).map_err(|_| Error::SerializationError)?;

    let seed_dst =
        GenericArray::from(STR_SEED).concat(get_context_string::<CS::Group>(Mode::Verifiable));
    let composite_dst =
        GenericArray::from(STR_COMPOSITE).concat(get_context_string::<CS::Group>(Mode::Verifiable));
    let composite_dst_len = i2osp_2_array(composite_dst);

    let seed = CS::Hash::new()
        .chain_update(&elem_len)
        .chain_update(CS::Group::serialize_elem(b))
        .chain_update(i2osp_2_array(seed_dst))
        .chain_update(seed_dst)
        .finalize();
    let seed_len = i2osp_2(seed.len())?;

    let mut m = CS::Group::identity_elem();
    let mut z = CS::Group::identity_elem();

    for (i, (c, d)) in (0..len).zip(c_slice.zip(d_slice)) {
        // Ci = GG.SerializeElement(Cs[i])
        let ci = CS::Group::serialize_elem(c.0);
        // Di = GG.SerializeElement(Ds[i])
        let di = CS::Group::serialize_elem(d.0);
        // h2Input = I2OSP(len(seed), 2) || seed || I2OSP(i, 2) ||
        //           I2OSP(len(Ci), 2) || Ci ||
        //           I2OSP(len(Di), 2) || Di ||
        //           I2OSP(len(compositeDST), 2) || compositeDST
        let h2_input = [
            &seed_len,
            seed.as_slice(),
            &i.to_be_bytes(),
            &elem_len,
            &ci,
            &elem_len,
            &di,
            &composite_dst_len,
            &composite_dst,
        ];
        let di = CS::Group::hash_to_scalar::<CS::Hash>(&h2_input, Mode::Verifiable)?;
        m = c.0 * &di + &m;
        z = match k_option {
            Some(_) => z,
            None => d.0 * &di + &z,
        };
    }

    z = match k_option {
        Some(k) => m * &k,
        None => z,
    };

    Ok((m, z))
}

/// Generates the contextString parameter as defined in
/// <https://www.ietf.org/archive/id/draft-irtf-cfrg-voprf-08.html>
pub(crate) fn get_context_string<G: Group>(mode: Mode) -> GenericArray<u8, U11> {
    GenericArray::from(STR_VOPRF)
        .concat([mode.to_u8()].into())
        .concat(G::SUITE_ID.to_be_bytes().into())
}

///////////
// Tests //
// ===== //
///////////

#[cfg(test)]
mod tests {
    use core::ops::Add;

    use ::alloc::vec;
    use ::alloc::vec::Vec;
    use generic_array::typenum::Sum;
    use generic_array::ArrayLength;
    use rand::rngs::OsRng;
    use zeroize::Zeroize;

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
        let point = CS::Group::hash_to_curve::<CS::Hash>(&[input], mode).unwrap();

        let context_string = get_context_string::<CS::Group>(mode);
        let info_len = i2osp_2(info.len()).unwrap();
        let context = [&STR_CONTEXT, context_string.as_slice(), &info_len, info];

        let m = CS::Group::hash_to_scalar::<CS::Hash>(&context, mode).unwrap();

        let res = point * &CS::Group::invert_scalar(key + &m);

        finalize_after_unblind::<CS, _, _>(Some((input, res)).into_iter(), info, mode)
            .unwrap()
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
        let client_blind_result = NonVerifiableClient::<CS>::blind(input, &mut rng).unwrap();
        let server = NonVerifiableServer::<CS>::new(&mut rng).unwrap();
        let server_result = server
            .evaluate(&client_blind_result.message, Some(info))
            .unwrap();
        let client_finalize_result = client_blind_result
            .state
            .finalize(input, &server_result.message, Some(info))
            .unwrap();
        let res2 = prf::<CS>(input, server.get_private_key(), info, Mode::Base);
        assert_eq!(client_finalize_result, res2);
    }

    fn verifiable_retrieval<CS: CipherSuite>()
    where
        <CS::Hash as OutputSizeUser>::OutputSize:
            IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
    {
        let input = b"input";
        let info = b"info";
        let mut rng = OsRng;
        let client_blind_result = VerifiableClient::<CS>::blind(input, &mut rng).unwrap();
        let server = VerifiableServer::<CS>::new(&mut rng).unwrap();
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
        let res2 = prf::<CS>(input, server.get_private_key(), info, Mode::Verifiable);
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
        let client_blind_result = VerifiableClient::<CS>::blind(input, &mut rng).unwrap();
        let server = VerifiableServer::<CS>::new(&mut rng).unwrap();
        let server_result = server
            .evaluate(&mut rng, &client_blind_result.message, Some(info))
            .unwrap();
        let wrong_pk = {
            // Choose a group element that is unlikely to be the right public key
            CS::Group::hash_to_curve::<CS::Hash>(&[b"msg"], Mode::Base).unwrap()
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

    fn verifiable_batch_retrieval<CS: CipherSuite>()
    where
        <CS::Hash as OutputSizeUser>::OutputSize:
            IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
    {
        let info = b"info";
        let mut rng = OsRng;
        let mut inputs = vec![];
        let mut client_states = vec![];
        let mut client_messages = vec![];
        let num_iterations = 10;
        for _ in 0..num_iterations {
            let mut input = [0u8; 32];
            rng.fill_bytes(&mut input);
            let client_blind_result = VerifiableClient::<CS>::blind(&input, &mut rng).unwrap();
            inputs.push(input);
            client_states.push(client_blind_result.state);
            client_messages.push(client_blind_result.message);
        }
        let server = VerifiableServer::<CS>::new(&mut rng).unwrap();
        let VerifiableServerBatchEvaluatePrepareResult {
            prepared_evaluation_elements,
            t,
        } = server
            .batch_evaluate_prepare(client_messages.iter(), Some(info))
            .unwrap();
        let prepared_elements: Vec<_> = prepared_evaluation_elements.collect();
        let VerifiableServerBatchEvaluateFinishResult { messages, proof } =
            VerifiableServer::batch_evaluate_finish(
                &mut rng,
                client_messages.iter(),
                &prepared_elements,
                &t,
            )
            .unwrap();
        let messages: Vec<_> = messages.collect();
        let client_finalize_result = VerifiableClient::batch_finalize(
            &inputs,
            &client_states,
            &messages,
            &proof,
            server.get_public_key(),
            Some(info),
        )
        .unwrap()
        .collect::<Result<Vec<_>>>()
        .unwrap();
        let mut res2 = vec![];
        for input in inputs.iter().take(num_iterations) {
            let output = prf::<CS>(input, server.get_private_key(), info, Mode::Verifiable);
            res2.push(output);
        }
        assert_eq!(client_finalize_result, res2);
    }

    fn verifiable_batch_bad_public_key<CS: CipherSuite>()
    where
        <CS::Hash as OutputSizeUser>::OutputSize:
            IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
    {
        let info = b"info";
        let mut rng = OsRng;
        let mut inputs = vec![];
        let mut client_states = vec![];
        let mut client_messages = vec![];
        let num_iterations = 10;
        for _ in 0..num_iterations {
            let mut input = [0u8; 32];
            rng.fill_bytes(&mut input);
            let client_blind_result = VerifiableClient::<CS>::blind(&input, &mut rng).unwrap();
            inputs.push(input);
            client_states.push(client_blind_result.state);
            client_messages.push(client_blind_result.message);
        }
        let server = VerifiableServer::<CS>::new(&mut rng).unwrap();
        let VerifiableServerBatchEvaluatePrepareResult {
            prepared_evaluation_elements,
            t,
        } = server
            .batch_evaluate_prepare(client_messages.iter(), Some(info))
            .unwrap();
        let prepared_elements: Vec<_> = prepared_evaluation_elements.collect();
        let VerifiableServerBatchEvaluateFinishResult { messages, proof } =
            VerifiableServer::batch_evaluate_finish(
                &mut rng,
                client_messages.iter(),
                &prepared_elements,
                &t,
            )
            .unwrap();
        let messages: Vec<_> = messages.collect();
        let wrong_pk = {
            // Choose a group element that is unlikely to be the right public key
            CS::Group::hash_to_curve::<CS::Hash>(&[b"msg"], Mode::Base).unwrap()
        };
        let client_finalize_result = VerifiableClient::batch_finalize(
            &inputs,
            &client_states,
            &messages,
            &proof,
            wrong_pk,
            Some(info),
        );
        assert!(client_finalize_result.is_err());
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
        let client_blind_result = NonVerifiableClient::<CS>::blind(&input, &mut rng).unwrap();
        let client_finalize_result = client_blind_result
            .state
            .finalize(
                &input,
                &EvaluationElement(client_blind_result.message.0),
                Some(info),
            )
            .unwrap();

        let point = CS::Group::hash_to_curve::<CS::Hash>(&[&input], Mode::Base).unwrap();
        let res2 = finalize_after_unblind::<CS, _, _>(
            Some((input.as_ref(), point)).into_iter(),
            info,
            Mode::Base,
        )
        .unwrap()
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
        let client_blind_result = NonVerifiableClient::<CS>::blind(input, &mut rng).unwrap();

        let mut state = client_blind_result.state;
        Zeroize::zeroize(&mut state);
        assert!(state.serialize().iter().all(|&x| x == 0));

        let mut message = client_blind_result.message;
        Zeroize::zeroize(&mut message);
        assert!(message.serialize().iter().all(|&x| x == 0));
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
        let client_blind_result = VerifiableClient::<CS>::blind(input, &mut rng).unwrap();

        let mut state = client_blind_result.state;
        Zeroize::zeroize(&mut state);
        assert!(state.serialize().iter().all(|&x| x == 0));

        let mut message = client_blind_result.message;
        Zeroize::zeroize(&mut message);
        assert!(message.serialize().iter().all(|&x| x == 0));
    }

    fn zeroize_base_server<CS: CipherSuite>()
    where
        <CS::Hash as OutputSizeUser>::OutputSize:
            IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
    {
        let input = b"input";
        let info = b"info";
        let mut rng = OsRng;
        let client_blind_result = NonVerifiableClient::<CS>::blind(input, &mut rng).unwrap();
        let server = NonVerifiableServer::<CS>::new(&mut rng).unwrap();
        let server_result = server
            .evaluate(&client_blind_result.message, Some(info))
            .unwrap();

        let mut state = server;
        Zeroize::zeroize(&mut state);
        assert!(state.serialize().iter().all(|&x| x == 0));

        let mut message = server_result.message;
        Zeroize::zeroize(&mut message);
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
        let client_blind_result = VerifiableClient::<CS>::blind(input, &mut rng).unwrap();
        let server = VerifiableServer::<CS>::new(&mut rng).unwrap();
        let server_result = server
            .evaluate(&mut rng, &client_blind_result.message, Some(info))
            .unwrap();

        let mut state = server;
        Zeroize::zeroize(&mut state);
        assert!(state.serialize().iter().all(|&x| x == 0));

        let mut message = server_result.message;
        Zeroize::zeroize(&mut message);
        assert!(message.serialize().iter().all(|&x| x == 0));

        let mut proof = server_result.proof;
        Zeroize::zeroize(&mut proof);
        assert!(proof.serialize().iter().all(|&x| x == 0));
    }

    #[test]
    fn test_functionality() -> Result<()> {
        #[cfg(feature = "ristretto255")]
        {
            use crate::Ristretto255;

            base_retrieval::<Ristretto255>();
            base_inversion_unsalted::<Ristretto255>();
            verifiable_retrieval::<Ristretto255>();
            verifiable_batch_retrieval::<Ristretto255>();
            verifiable_bad_public_key::<Ristretto255>();
            verifiable_batch_bad_public_key::<Ristretto255>();

            zeroize_base_client::<Ristretto255>();
            zeroize_base_server::<Ristretto255>();
            zeroize_verifiable_client::<Ristretto255>();
            zeroize_verifiable_server::<Ristretto255>();
        }

        #[cfg(feature = "p256")]
        {
            use p256::NistP256;

            base_retrieval::<NistP256>();
            base_inversion_unsalted::<NistP256>();
            verifiable_retrieval::<NistP256>();
            verifiable_batch_retrieval::<NistP256>();
            verifiable_bad_public_key::<NistP256>();
            verifiable_batch_bad_public_key::<NistP256>();

            zeroize_base_client::<NistP256>();
            zeroize_base_server::<NistP256>();
            zeroize_verifiable_client::<NistP256>();
            zeroize_verifiable_server::<NistP256>();
        }

        Ok(())
    }
}

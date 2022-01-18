// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Contains the main VOPRF API

#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use core::convert::{TryFrom, TryInto};
use core::iter::{self, Map, Repeat, Zip};
use core::marker::PhantomData;

use derive_where::DeriveWhere;
use digest::core_api::BlockSizeUser;
use digest::{Digest, Output};
use generic_array::sequence::Concat;
use generic_array::typenum::{IsLess, IsLessOrEqual, Unsigned, U11, U20, U256};
use generic_array::GenericArray;
use rand_core::{CryptoRng, RngCore};
use subtle::ConstantTimeEq;

use crate::util::{i2osp_2, i2osp_2_array};
use crate::{Error, Group, Result};

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
#[derive_where(Debug, Eq, Hash, Ord, PartialEq, PartialOrd; G::Scalar)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(bound(
        deserialize = "G::Scalar: serde::Deserialize<'de>",
        serialize = "G::Scalar: serde::Serialize"
    ))
)]
pub struct NonVerifiableClient<G: Group, H: BlockSizeUser + Digest>
where
    H::OutputSize: IsLess<U256> + IsLessOrEqual<H::BlockSize>,
{
    pub(crate) blind: G::Scalar,
    #[derive_where(skip(Zeroize))]
    pub(crate) hash: PhantomData<H>,
}

/// A client which engages with a [VerifiableServer] in verifiable mode, meaning
/// that the OPRF outputs can be checked against a server public key.
#[derive(DeriveWhere)]
#[derive_where(Clone, Zeroize(drop))]
#[derive_where(Debug, Eq, Hash, Ord, PartialEq, PartialOrd; G::Elem, G::Scalar)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(bound(
        deserialize = "G::Scalar: serde::Deserialize<'de>, G::Elem: serde::Deserialize<'de>",
        serialize = "G::Scalar: serde::Serialize, G::Elem: serde::Serialize"
    ))
)]
pub struct VerifiableClient<G: Group, H: BlockSizeUser + Digest>
where
    H::OutputSize: IsLess<U256> + IsLessOrEqual<H::BlockSize>,
{
    pub(crate) blind: G::Scalar,
    pub(crate) blinded_element: G::Elem,
    #[derive_where(skip(Zeroize))]
    pub(crate) hash: PhantomData<H>,
}

/// A server which engages with a [NonVerifiableClient] in base mode, meaning
/// that the OPRF outputs are not verifiable.
#[derive(DeriveWhere)]
#[derive_where(Clone, Zeroize(drop))]
#[derive_where(Debug, Eq, Hash, Ord, PartialEq, PartialOrd; G::Scalar)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(bound(
        deserialize = "G::Scalar: serde::Deserialize<'de>",
        serialize = "G::Scalar: serde::Serialize"
    ))
)]
pub struct NonVerifiableServer<G: Group, H: BlockSizeUser + Digest>
where
    H::OutputSize: IsLess<U256> + IsLessOrEqual<H::BlockSize>,
{
    pub(crate) sk: G::Scalar,
    #[derive_where(skip(Zeroize))]
    pub(crate) hash: PhantomData<H>,
}

/// A server which engages with a [VerifiableClient] in verifiable mode, meaning
/// that the OPRF outputs can be checked against a server public key.
#[derive(DeriveWhere)]
#[derive_where(Clone, Zeroize(drop))]
#[derive_where(Debug, Eq, Hash, Ord, PartialEq, PartialOrd; G::Elem, G::Scalar)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(bound(
        deserialize = "G::Scalar: serde::Deserialize<'de>, G::Elem: serde::Deserialize<'de>",
        serialize = "G::Scalar: serde::Serialize, G::Elem: serde::Serialize"
    ))
)]
pub struct VerifiableServer<G: Group, H: BlockSizeUser + Digest>
where
    H::OutputSize: IsLess<U256> + IsLessOrEqual<H::BlockSize>,
{
    pub(crate) sk: G::Scalar,
    pub(crate) pk: G::Elem,
    #[derive_where(skip(Zeroize))]
    pub(crate) hash: PhantomData<H>,
}

/// A proof produced by a [VerifiableServer] that the OPRF output matches
/// against a server public key.
#[derive(DeriveWhere)]
#[derive_where(Clone, Zeroize(drop))]
#[derive_where(Debug, Eq, Hash, Ord, PartialEq, PartialOrd; G::Scalar)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(bound(
        deserialize = "G::Scalar: serde::Deserialize<'de>",
        serialize = "G::Scalar: serde::Serialize"
    ))
)]
pub struct Proof<G: Group, H: BlockSizeUser + Digest>
where
    H::OutputSize: IsLess<U256> + IsLessOrEqual<H::BlockSize>,
{
    pub(crate) c_scalar: G::Scalar,
    pub(crate) s_scalar: G::Scalar,
    #[derive_where(skip(Zeroize))]
    pub(crate) hash: PhantomData<H>,
}

/// The first client message sent from a client (either verifiable or not) to a
/// server (either verifiable or not).
#[derive(DeriveWhere)]
#[derive_where(Clone, Zeroize(drop))]
#[derive_where(Debug, Eq, Hash, Ord, PartialEq, PartialOrd; G::Elem)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(bound(
        deserialize = "G::Elem: serde::Deserialize<'de>",
        serialize = "G::Elem: serde::Serialize"
    ))
)]
pub struct BlindedElement<G: Group, H: BlockSizeUser + Digest>
where
    H::OutputSize: IsLess<U256> + IsLessOrEqual<H::BlockSize>,
{
    pub(crate) value: G::Elem,
    #[derive_where(skip(Zeroize))]
    pub(crate) hash: PhantomData<H>,
}

/// The server's response to the [BlindedElement] message from a client (either
/// verifiable or not) to a server (either verifiable or not).
#[derive(DeriveWhere)]
#[derive_where(Clone, Zeroize(drop))]
#[derive_where(Debug, Eq, Hash, Ord, PartialEq, PartialOrd; G::Elem)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(bound(
        deserialize = "G::Elem: serde::Deserialize<'de>",
        serialize = "G::Elem: serde::Serialize"
    ))
)]
pub struct EvaluationElement<G: Group, H: BlockSizeUser + Digest>
where
    H::OutputSize: IsLess<U256> + IsLessOrEqual<H::BlockSize>,
{
    pub(crate) value: G::Elem,
    #[derive_where(skip(Zeroize))]
    pub(crate) hash: PhantomData<H>,
}

/////////////////////////
// API Implementations //
// =================== //
/////////////////////////

impl<G: Group, H: BlockSizeUser + Digest> NonVerifiableClient<G, H>
where
    H::OutputSize: IsLess<U256> + IsLessOrEqual<H::BlockSize>,
{
    /// Computes the first step for the multiplicative blinding version of
    /// DH-OPRF.
    pub fn blind<R: RngCore + CryptoRng>(
        input: &[u8],
        blinding_factor_rng: &mut R,
    ) -> Result<NonVerifiableClientBlindResult<G, H>> {
        let (blind, blinded_element) = blind::<G, H, _>(input, blinding_factor_rng, Mode::Base)?;
        Ok(NonVerifiableClientBlindResult {
            state: Self {
                blind,
                hash: PhantomData,
            },
            message: BlindedElement {
                value: blinded_element,
                hash: PhantomData,
            },
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
        blind: G::Scalar,
    ) -> Result<NonVerifiableClientBlindResult<G, H>> {
        let blinded_element = deterministic_blind_unchecked::<G, H>(input, &blind, Mode::Base)?;
        Ok(NonVerifiableClientBlindResult {
            state: Self {
                blind,
                hash: PhantomData,
            },
            message: BlindedElement {
                value: blinded_element,
                hash: PhantomData,
            },
        })
    }

    /// Computes the third step for the multiplicative blinding version of
    /// DH-OPRF, in which the client unblinds the server's message.
    pub fn finalize(
        &self,
        input: &[u8],
        evaluation_element: &EvaluationElement<G, H>,
        metadata: Option<&[u8]>,
    ) -> Result<Output<H>> {
        let unblinded_element = evaluation_element.value * &G::invert_scalar(self.blind);
        let mut outputs = finalize_after_unblind::<G, H, _, _>(
            Some((input, unblinded_element)).into_iter(),
            metadata.unwrap_or_default(),
            Mode::Base,
        )?;
        outputs.next().unwrap()
    }

    #[cfg(test)]
    /// Only used for test functions
    pub fn from_blind(blind: G::Scalar) -> Self {
        Self {
            blind,
            hash: PhantomData,
        }
    }

    #[cfg(feature = "danger")]
    /// Exposes the blind group element
    pub fn get_blind(&self) -> G::Scalar {
        self.blind
    }
}

impl<G: Group, H: BlockSizeUser + Digest> VerifiableClient<G, H>
where
    H::OutputSize: IsLess<U256> + IsLessOrEqual<H::BlockSize>,
{
    /// Computes the first step for the multiplicative blinding version of
    /// DH-OPRF.
    pub fn blind<R: RngCore + CryptoRng>(
        input: &[u8],
        blinding_factor_rng: &mut R,
    ) -> Result<VerifiableClientBlindResult<G, H>> {
        let (blind, blinded_element) =
            blind::<G, H, _>(input, blinding_factor_rng, Mode::Verifiable)?;
        Ok(VerifiableClientBlindResult {
            state: Self {
                blind,
                blinded_element,
                hash: PhantomData,
            },
            message: BlindedElement {
                value: blinded_element,
                hash: PhantomData,
            },
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
        blind: G::Scalar,
    ) -> Result<VerifiableClientBlindResult<G, H>> {
        let blinded_element =
            deterministic_blind_unchecked::<G, H>(input, &blind, Mode::Verifiable)?;
        Ok(VerifiableClientBlindResult {
            state: Self {
                blind,
                blinded_element,
                hash: PhantomData,
            },
            message: BlindedElement {
                value: blinded_element,
                hash: PhantomData,
            },
        })
    }

    /// Computes the third step for the multiplicative blinding version of
    /// DH-OPRF, in which the client unblinds the server's message.
    pub fn finalize(
        &self,
        input: &[u8],
        evaluation_element: &EvaluationElement<G, H>,
        proof: &Proof<G, H>,
        pk: G::Elem,
        metadata: Option<&[u8]>,
    ) -> Result<Output<H>> {
        // `core::array::from_ref` needs a MSRV of 1.53
        let inputs: &[&[u8]; 1] = core::slice::from_ref(&input).try_into().unwrap();
        let clients: &[Self; 1] = core::slice::from_ref(self).try_into().unwrap();
        let messages: &[EvaluationElement<G, H>; 1] = core::slice::from_ref(evaluation_element)
            .try_into()
            .unwrap();

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
        proof: &Proof<G, H>,
        pk: G::Elem,
        metadata: Option<&'a [u8]>,
    ) -> Result<VerifiableClientBatchFinalizeResult<'a, G, H, I, II, IC, IM>>
    where
        G: 'a,
        H: 'a,
        I: AsRef<[u8]>,
        &'a II: 'a + IntoIterator<Item = I>,
        <&'a II as IntoIterator>::IntoIter: ExactSizeIterator,
        &'a IC: 'a + IntoIterator<Item = &'a VerifiableClient<G, H>>,
        <&'a IC as IntoIterator>::IntoIter: ExactSizeIterator,
        &'a IM: 'a + IntoIterator<Item = &'a EvaluationElement<G, H>>,
        <&'a IM as IntoIterator>::IntoIter: ExactSizeIterator,
    {
        let metadata = metadata.unwrap_or_default();

        let unblinded_elements = verifiable_unblind(clients, messages, pk, proof, metadata)?;

        let inputs_and_unblinded_elements = inputs.into_iter().zip(unblinded_elements);

        finalize_after_unblind::<G, H, _, _>(
            inputs_and_unblinded_elements,
            metadata,
            Mode::Verifiable,
        )
    }

    #[cfg(test)]
    /// Only used for test functions
    pub fn from_blind_and_element(blind: G::Scalar, blinded_element: G::Elem) -> Self {
        Self {
            blind,
            blinded_element,
            hash: PhantomData,
        }
    }

    #[cfg(test)]
    /// Only used for test functions
    pub fn get_blind(&self) -> G::Scalar {
        self.blind
    }
}

impl<G: Group, H: BlockSizeUser + Digest> NonVerifiableServer<G, H>
where
    H::OutputSize: IsLess<U256> + IsLessOrEqual<H::BlockSize>,
{
    /// Produces a new instance of a [NonVerifiableServer] using a supplied RNG
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Result<Self> {
        let mut seed = Output::<H>::default();
        rng.fill_bytes(&mut seed);
        Self::new_from_seed(&seed)
    }

    /// Produces a new instance of a [NonVerifiableServer] using a supplied set
    /// of bytes to represent the server's private key
    pub fn new_with_key(private_key_bytes: &[u8]) -> Result<Self> {
        let sk = G::deserialize_scalar(private_key_bytes.into())?;
        Ok(Self {
            sk,
            hash: PhantomData,
        })
    }

    /// Produces a new instance of a [NonVerifiableServer] using a supplied set
    /// of bytes which are used as a seed to derive the server's private key.
    ///
    /// Corresponds to DeriveKeyPair() function from the VOPRF specification.
    pub fn new_from_seed(seed: &[u8]) -> Result<Self> {
        let sk = G::hash_to_scalar::<H>(&[seed], Mode::Base)?;
        Ok(Self {
            sk,
            hash: PhantomData,
        })
    }

    // Only used for tests
    #[cfg(test)]
    pub fn get_private_key(&self) -> <G>::Scalar {
        self.sk
    }

    /// Computes the second step for the multiplicative blinding version of
    /// DH-OPRF. This message is sent from the server (who holds the OPRF key)
    /// to the client.
    pub fn evaluate(
        &self,
        blinded_element: &BlindedElement<G, H>,
        metadata: Option<&[u8]>,
    ) -> Result<NonVerifiableServerEvaluateResult<G, H>> {
        // https://www.ietf.org/archive/id/draft-irtf-cfrg-voprf-08.html#section-3.3.1.1-1

        let context_string = get_context_string::<G>(Mode::Base);
        let metadata = metadata.unwrap_or_default();

        // context = "Context-" || contextString || I2OSP(len(info), 2) || info
        let context = GenericArray::from(STR_CONTEXT)
            .concat(context_string)
            .concat(i2osp_2(metadata.len())?);
        let context = [&context, metadata];

        // m = GG.HashToScalar(context)
        let m = G::hash_to_scalar::<H>(&context, Mode::Base)?;
        // t = skS + m
        let t = self.sk + &m;
        // Z = t^(-1) * R
        let z = blinded_element.value * &G::invert_scalar(t);

        Ok(NonVerifiableServerEvaluateResult {
            message: EvaluationElement {
                value: z,
                hash: PhantomData,
            },
        })
    }
}

impl<G: Group, H: BlockSizeUser + Digest> VerifiableServer<G, H>
where
    H::OutputSize: IsLess<U256> + IsLessOrEqual<H::BlockSize>,
{
    /// Produces a new instance of a [VerifiableServer] using a supplied RNG
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Result<Self> {
        let mut seed = Output::<H>::default();
        rng.fill_bytes(&mut seed);
        Self::new_from_seed(&seed)
    }

    /// Produces a new instance of a [VerifiableServer] using a supplied set of
    /// bytes to represent the server's private key
    pub fn new_with_key(key: &[u8]) -> Result<Self> {
        let sk = G::deserialize_scalar(key.into())?;
        let pk = G::base_elem() * &sk;
        Ok(Self {
            sk,
            pk,
            hash: PhantomData,
        })
    }

    /// Produces a new instance of a [VerifiableServer] using a supplied set of
    /// bytes which are used as a seed to derive the server's private key.
    ///
    /// Corresponds to DeriveKeyPair() function from the VOPRF specification.
    pub fn new_from_seed(seed: &[u8]) -> Result<Self> {
        let sk = G::hash_to_scalar::<H>(&[seed], Mode::Verifiable)?;
        let pk = G::base_elem() * &sk;
        Ok(Self {
            sk,
            pk,
            hash: PhantomData,
        })
    }

    // Only used for tests
    #[cfg(test)]
    pub fn get_private_key(&self) -> G::Scalar {
        self.sk
    }

    /// Computes the second step for the multiplicative blinding version of
    /// DH-OPRF. This message is sent from the server (who holds the OPRF key)
    /// to the client.
    pub fn evaluate<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        blinded_element: &BlindedElement<G, H>,
        metadata: Option<&[u8]>,
    ) -> Result<VerifiableServerEvaluateResult<G, H>> {
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
    ) -> Result<VerifiableServerBatchEvaluateResult<G, H>>
    where
        G: 'a,
        H: 'a,
        &'a I: IntoIterator<Item = &'a BlindedElement<G, H>>,
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
    pub fn batch_evaluate_prepare<'a, I: Iterator<Item = &'a BlindedElement<G, H>>>(
        &self,
        blinded_elements: I,
        metadata: Option<&[u8]>,
    ) -> Result<VerifiableServerBatchEvaluatePrepareResult<'a, G, H, I>> {
        // https://www.ietf.org/archive/id/draft-irtf-cfrg-voprf-08.html#section-3.3.2.1-1

        let context_string = get_context_string::<G>(Mode::Verifiable);
        let metadata = metadata.unwrap_or_default();

        // context = "Context-" || contextString || I2OSP(len(info), 2) || info
        let context = GenericArray::from(STR_CONTEXT)
            .concat(context_string)
            .concat(i2osp_2(metadata.len())?);
        let context = [&context, metadata];

        let m = G::hash_to_scalar::<H>(&context, Mode::Verifiable)?;
        let t = self.sk + &m;
        let evaluation_elements = blinded_elements
            // To make a return type possible, we have to convert to a `fn` pointer, which isn't
            // possible if we `move` from context.
            .zip(iter::repeat(G::invert_scalar(t)))
            .map(<fn((&BlindedElement<G, H>, _)) -> _>::from(|(x, t)| {
                PreparedEvaluationElement(EvaluationElement {
                    value: x.value * &t,
                    hash: PhantomData,
                })
            }));

        Ok(VerifiableServerBatchEvaluatePrepareResult {
            prepared_evaluation_elements: evaluation_elements,
            t: PreparedTscalar {
                t,
                hash: PhantomData,
            },
        })
    }

    /// See [`batch_evaluate_prepare`](Self::batch_evaluate_prepare) for more
    /// details.
    pub fn batch_evaluate_finish<'a, 'b, R: RngCore + CryptoRng, IB, IE>(
        rng: &mut R,
        blinded_elements: IB,
        evaluation_elements: &'b IE,
        PreparedTscalar { t, .. }: &PreparedTscalar<G, H>,
    ) -> Result<VerifiableServerBatchEvaluateFinishResult<'b, G, H, IE>>
    where
        G: 'a + 'b,
        H: 'a + 'b,
        IB: Iterator<Item = &'a BlindedElement<G, H>> + ExactSizeIterator,
        &'b IE: IntoIterator<Item = &'b PreparedEvaluationElement<G, H>>,
        <&'b IE as IntoIterator>::IntoIter: ExactSizeIterator,
    {
        let g = G::base_elem();
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
                .map(<fn(&PreparedEvaluationElement<G, H>) -> _>::from(
                    |element| element.0.copy(),
                ));

        Ok(VerifiableServerBatchEvaluateFinishResult { messages, proof })
    }

    /// Retrieves the server's public key
    pub fn get_public_key(&self) -> G::Elem {
        self.pk
    }
}

/////////////////////////
// Convenience Structs //
//==================== //
/////////////////////////

/// Contains the fields that are returned by a non-verifiable client blind
pub struct NonVerifiableClientBlindResult<G: Group, H: BlockSizeUser + Digest>
where
    H::OutputSize: IsLess<U256> + IsLessOrEqual<H::BlockSize>,
{
    /// The state to be persisted on the client
    pub state: NonVerifiableClient<G, H>,
    /// The message to send to the server
    pub message: BlindedElement<G, H>,
}

/// Contains the fields that are returned by a non-verifiable server evaluate
pub struct NonVerifiableServerEvaluateResult<G: Group, H: BlockSizeUser + Digest>
where
    H::OutputSize: IsLess<U256> + IsLessOrEqual<H::BlockSize>,
{
    /// The message to send to the client
    pub message: EvaluationElement<G, H>,
}

/// Contains the fields that are returned by a verifiable client blind
pub struct VerifiableClientBlindResult<G: Group, H: BlockSizeUser + Digest>
where
    H::OutputSize: IsLess<U256> + IsLessOrEqual<H::BlockSize>,
{
    /// The state to be persisted on the client
    pub state: VerifiableClient<G, H>,
    /// The message to send to the server
    pub message: BlindedElement<G, H>,
}

/// Concrete return type for [`VerifiableClient::batch_finalize`].
pub type VerifiableClientBatchFinalizeResult<'a, G, H, I, II, IC, IM> = FinalizeAfterUnblindResult<
    'a,
    G,
    H,
    I,
    Zip<<&'a II as IntoIterator>::IntoIter, VerifiableUnblindResult<'a, G, H, IC, IM>>,
>;

/// Contains the fields that are returned by a verifiable server evaluate
pub struct VerifiableServerEvaluateResult<G: Group, H: BlockSizeUser + Digest>
where
    H::OutputSize: IsLess<U256> + IsLessOrEqual<H::BlockSize>,
{
    /// The message to send to the client
    pub message: EvaluationElement<G, H>,
    /// The proof for the client to verify
    pub proof: Proof<G, H>,
}

/// Contains prepared [`EvaluationElement`]s by a verifiable server batch
/// evaluate preparation.
pub struct PreparedEvaluationElement<G: Group, H: BlockSizeUser + Digest>(EvaluationElement<G, H>)
where
    H::OutputSize: IsLess<U256> + IsLessOrEqual<H::BlockSize>;

/// Contains the prepared `t` by a verifiable server batch evaluate preparation.
#[derive(DeriveWhere)]
#[derive_where(Zeroize(drop))]
pub struct PreparedTscalar<G: Group, H: BlockSizeUser + Digest>
where
    H::OutputSize: IsLess<U256> + IsLessOrEqual<H::BlockSize>,
{
    t: G::Scalar,
    #[derive_where(skip)]
    hash: PhantomData<H>,
}

/// Contains the fields that are returned by a verifiable server batch evaluate
/// preparation.
pub struct VerifiableServerBatchEvaluatePrepareResult<
    'a,
    G: 'a + Group,
    H: 'a + BlockSizeUser + Digest,
    I: Iterator<Item = &'a BlindedElement<G, H>>,
> where
    H::OutputSize: IsLess<U256> + IsLessOrEqual<H::BlockSize>,
{
    /// Prepared [`EvaluationElement`]s that will become messages.
    #[allow(clippy::type_complexity)]
    pub prepared_evaluation_elements: Map<
        Zip<I, Repeat<G::Scalar>>,
        fn((&BlindedElement<G, H>, G::Scalar)) -> PreparedEvaluationElement<G, H>,
    >,
    /// Prepared `t` needed to finish the verifiable server batch evaluation.
    pub t: PreparedTscalar<G, H>,
}

/// Contains the fields that are returned by a verifiable server batch evaluate
/// finish.
pub struct VerifiableServerBatchEvaluateFinishResult<
    'a,
    G: 'a + Group,
    H: 'a + BlockSizeUser + Digest,
    I,
> where
    H::OutputSize: IsLess<U256> + IsLessOrEqual<H::BlockSize>,
    &'a I: IntoIterator<Item = &'a PreparedEvaluationElement<G, H>>,
{
    /// The messages to send to the client
    #[allow(clippy::type_complexity)]
    pub messages: Map<
        <&'a I as IntoIterator>::IntoIter,
        fn(&PreparedEvaluationElement<G, H>) -> EvaluationElement<G, H>,
    >,
    /// The proof for the client to verify
    pub proof: Proof<G, H>,
}

/// Contains the fields that are returned by a verifiable server batch evaluate
#[cfg(feature = "alloc")]
pub struct VerifiableServerBatchEvaluateResult<G: Group, H: BlockSizeUser + Digest>
where
    H::OutputSize: IsLess<U256> + IsLessOrEqual<H::BlockSize>,
{
    /// The messages to send to the client
    pub messages: alloc::vec::Vec<EvaluationElement<G, H>>,
    /// The proof for the client to verify
    pub proof: Proof<G, H>,
}

///////////////////////////////////////////////
// Inner functions and Trait Implementations //
// ========================================= //
///////////////////////////////////////////////

impl<G: Group, H: BlockSizeUser + Digest> BlindedElement<G, H>
where
    H::OutputSize: IsLess<U256> + IsLessOrEqual<H::BlockSize>,
{
    /// Only used to easier validate allocation
    fn copy(&self) -> Self {
        Self {
            value: self.value,
            hash: PhantomData,
        }
    }

    #[cfg(feature = "danger")]
    /// Creates a [BlindedElement] from a raw group element.
    ///
    /// # Caution
    ///
    /// This should be used with caution, since it does not perform any checks
    /// on the validity of the value itself!
    pub fn from_value_unchecked(value: G::Elem) -> Self {
        Self {
            value,
            hash: PhantomData,
        }
    }

    #[cfg(feature = "danger")]
    /// Exposes the internal value
    pub fn value(&self) -> G::Elem {
        self.value
    }
}

impl<G: Group, H: BlockSizeUser + Digest> EvaluationElement<G, H>
where
    H::OutputSize: IsLess<U256> + IsLessOrEqual<H::BlockSize>,
{
    /// Only used to easier validate allocation
    fn copy(&self) -> Self {
        Self {
            value: self.value,
            hash: PhantomData,
        }
    }

    #[cfg(feature = "danger")]
    /// Creates an [EvaluationElement] from a raw group element.
    ///
    /// # Caution
    ///
    /// This should be used with caution, since it does not perform any checks
    /// on the validity of the value itself!
    pub fn from_value_unchecked(value: G::Elem) -> Self {
        Self {
            value,
            hash: PhantomData,
        }
    }

    #[cfg(feature = "danger")]
    /// Exposes the internal value
    pub fn value(&self) -> G::Elem {
        self.value
    }
}

// Inner function for blind. Returns the blind scalar and the blinded element
fn blind<G: Group, H: BlockSizeUser + Digest, R: RngCore + CryptoRng>(
    input: &[u8],
    blinding_factor_rng: &mut R,
    mode: Mode,
) -> Result<(G::Scalar, G::Elem)>
where
    H::OutputSize: IsLess<U256> + IsLessOrEqual<H::BlockSize>,
{
    // Choose a random scalar that must be non-zero
    let blind = G::random_scalar(blinding_factor_rng);
    let blinded_element = deterministic_blind_unchecked::<G, H>(input, &blind, mode)?;
    Ok((blind, blinded_element))
}

// Inner function for blind that assumes that the blinding factor has already
// been chosen, and therefore takes it as input. Does not check if the blinding
// factor is non-zero.
fn deterministic_blind_unchecked<G: Group, H: BlockSizeUser + Digest>(
    input: &[u8],
    blind: &G::Scalar,
    mode: Mode,
) -> Result<G::Elem>
where
    H::OutputSize: IsLess<U256> + IsLessOrEqual<H::BlockSize>,
{
    let hashed_point = G::hash_to_curve::<H>(&[input], mode)?;
    Ok(hashed_point * blind)
}

type VerifiableUnblindResult<'a, G, H, IC, IM> = Map<
    Zip<
        Map<
            <&'a IC as IntoIterator>::IntoIter,
            fn(&VerifiableClient<G, H>) -> <G as Group>::Scalar,
        >,
        <&'a IM as IntoIterator>::IntoIter,
    >,
    fn((<G as Group>::Scalar, &EvaluationElement<G, H>)) -> <G as Group>::Elem,
>;

fn verifiable_unblind<'a, G: 'a + Group, H: 'a + BlockSizeUser + Digest, IC, IM>(
    clients: &'a IC,
    messages: &'a IM,
    pk: G::Elem,
    proof: &Proof<G, H>,
    info: &[u8],
) -> Result<VerifiableUnblindResult<'a, G, H, IC, IM>>
where
    H::OutputSize: IsLess<U256> + IsLessOrEqual<H::BlockSize>,
    &'a IC: 'a + IntoIterator<Item = &'a VerifiableClient<G, H>>,
    <&'a IC as IntoIterator>::IntoIter: ExactSizeIterator,
    &'a IM: 'a + IntoIterator<Item = &'a EvaluationElement<G, H>>,
    <&'a IM as IntoIterator>::IntoIter: ExactSizeIterator,
{
    // https://www.ietf.org/archive/id/draft-irtf-cfrg-voprf-08.html#section-3.3.4.2-2

    let context_string = get_context_string::<G>(Mode::Verifiable);

    // context = "Context-" || contextString || I2OSP(len(info), 2) || info
    let context = GenericArray::from(STR_CONTEXT)
        .concat(context_string)
        .concat(i2osp_2(info.len())?);
    let context = [&context, info];

    let m = G::hash_to_scalar::<H>(&context, Mode::Verifiable)?;

    let g = G::base_elem();
    let t = g * &m;
    let u = t + &pk;

    let blinds = clients
        .into_iter()
        // Convert to `fn` pointer to make a return type possible.
        .map(<fn(&VerifiableClient<G, H>) -> _>::from(|x| x.blind));
    let evaluation_elements = messages.into_iter().map(EvaluationElement::copy);
    let blinded_elements = clients.into_iter().map(|client| BlindedElement {
        value: client.blinded_element,
        hash: PhantomData,
    });

    verify_proof(g, u, evaluation_elements, blinded_elements, proof)?;

    Ok(blinds
        .zip(messages.into_iter())
        .map(|(blind, x)| x.value * &G::invert_scalar(blind)))
}

#[allow(clippy::many_single_char_names)]
fn generate_proof<G: Group, H: BlockSizeUser + Digest, R: RngCore + CryptoRng>(
    rng: &mut R,
    k: G::Scalar,
    a: G::Elem,
    b: G::Elem,
    cs: impl Iterator<Item = EvaluationElement<G, H>> + ExactSizeIterator,
    ds: impl Iterator<Item = BlindedElement<G, H>> + ExactSizeIterator,
) -> Result<Proof<G, H>>
where
    H::OutputSize: IsLess<U256> + IsLessOrEqual<H::BlockSize>,
{
    // https://www.ietf.org/archive/id/draft-irtf-cfrg-voprf-08.html#section-3.3.2.2-1

    let (m, z) = compute_composites(Some(k), b, cs, ds)?;

    let r = G::random_scalar(rng);
    let t2 = a * &r;
    let t3 = m * &r;

    // Bm = GG.SerializeElement(B)
    let bm = G::serialize_elem(b);
    // a0 = GG.SerializeElement(M)
    let a0 = G::serialize_elem(m);
    // a1 = GG.SerializeElement(Z)
    let a1 = G::serialize_elem(z);
    // a2 = GG.SerializeElement(t2)
    let a2 = G::serialize_elem(t2);
    // a3 = GG.SerializeElement(t3)
    let a3 = G::serialize_elem(t3);

    let elem_len = G::ElemLen::U16.to_be_bytes();

    // challengeDST = "Challenge-" || contextString
    let challenge_dst =
        GenericArray::from(STR_CHALLENGE).concat(get_context_string::<G>(Mode::Verifiable));
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

    let c_scalar = G::hash_to_scalar::<H>(&h2_input, Mode::Verifiable)?;
    let s_scalar = r - &(c_scalar * &k);

    Ok(Proof {
        c_scalar,
        s_scalar,
        hash: PhantomData,
    })
}

#[allow(clippy::many_single_char_names)]
fn verify_proof<G: Group, H: BlockSizeUser + Digest>(
    a: G::Elem,
    b: G::Elem,
    cs: impl Iterator<Item = EvaluationElement<G, H>> + ExactSizeIterator,
    ds: impl Iterator<Item = BlindedElement<G, H>> + ExactSizeIterator,
    proof: &Proof<G, H>,
) -> Result<()>
where
    H::OutputSize: IsLess<U256> + IsLessOrEqual<H::BlockSize>,
{
    // https://www.ietf.org/archive/id/draft-irtf-cfrg-voprf-08.html#section-3.3.4.1-2
    let (m, z) = compute_composites(None, b, cs, ds)?;
    let t2 = (a * &proof.s_scalar) + &(b * &proof.c_scalar);
    let t3 = (m * &proof.s_scalar) + &(z * &proof.c_scalar);

    // Bm = GG.SerializeElement(B)
    let bm = G::serialize_elem(b);
    // a0 = GG.SerializeElement(M)
    let a0 = G::serialize_elem(m);
    // a1 = GG.SerializeElement(Z)
    let a1 = G::serialize_elem(z);
    // a2 = GG.SerializeElement(t2)
    let a2 = G::serialize_elem(t2);
    // a3 = GG.SerializeElement(t3)
    let a3 = G::serialize_elem(t3);

    let elem_len = G::ElemLen::U16.to_be_bytes();

    // challengeDST = "Challenge-" || contextString
    let challenge_dst =
        GenericArray::from(STR_CHALLENGE).concat(get_context_string::<G>(Mode::Verifiable));
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

    let c = G::hash_to_scalar::<H>(&h2_input, Mode::Verifiable)?;

    match c.ct_eq(&proof.c_scalar).into() {
        true => Ok(()),
        false => Err(Error::ProofVerificationError),
    }
}

type FinalizeAfterUnblindResult<'a, G, H, I, IE> = Map<
    Zip<IE, Repeat<(&'a [u8], GenericArray<u8, U20>)>>,
    fn(((I, <G as Group>::Elem), (&'a [u8], GenericArray<u8, U20>))) -> Result<Output<H>>,
>;

fn finalize_after_unblind<
    'a,
    G: Group,
    H: BlockSizeUser + Digest,
    I: AsRef<[u8]>,
    IE: 'a + Iterator<Item = (I, G::Elem)>,
>(
    inputs_and_unblinded_elements: IE,
    info: &'a [u8],
    mode: Mode,
) -> Result<FinalizeAfterUnblindResult<G, H, I, IE>> {
    // https://www.ietf.org/archive/id/draft-irtf-cfrg-voprf-08.html#section-3.3.3.2-2
    // https://www.ietf.org/archive/id/draft-irtf-cfrg-voprf-08.html#section-3.3.4.3-1

    // finalizeDST = "Finalize-" || contextString
    let finalize_dst = GenericArray::from(STR_FINALIZE).concat(get_context_string::<G>(mode));

    Ok(inputs_and_unblinded_elements
        // To make a return type possible, we have to convert to a `fn` pointer,
        // which isn't possible if we `move` from context.
        .zip(iter::repeat((info, finalize_dst)))
        .map(|((input, unblinded_element), (info, finalize_dst))| {
            let finalize_dst_len = i2osp_2_array(finalize_dst);
            let elem_len = G::ElemLen::U16.to_be_bytes();

            // hashInput = I2OSP(len(input), 2) || input ||
            //             I2OSP(len(info), 2) || info ||
            //             I2OSP(len(unblindedElement), 2) || unblindedElement ||
            //             I2OSP(len(finalizeDST), 2) || finalizeDST
            // return Hash(hashInput)
            Ok(H::new()
                .chain_update(i2osp_2(input.as_ref().len())?)
                .chain_update(input.as_ref())
                .chain_update(i2osp_2(info.len())?)
                .chain_update(info)
                .chain_update(elem_len)
                .chain_update(G::serialize_elem(unblinded_element))
                .chain_update(finalize_dst_len)
                .chain_update(finalize_dst)
                .finalize())
        }))
}

fn compute_composites<G: Group, H: BlockSizeUser + Digest>(
    k_option: Option<G::Scalar>,
    b: G::Elem,
    c_slice: impl Iterator<Item = EvaluationElement<G, H>> + ExactSizeIterator,
    d_slice: impl Iterator<Item = BlindedElement<G, H>> + ExactSizeIterator,
) -> Result<(G::Elem, G::Elem)>
where
    H::OutputSize: IsLess<U256> + IsLessOrEqual<H::BlockSize>,
{
    // https://www.ietf.org/archive/id/draft-irtf-cfrg-voprf-08.html#section-3.3.2.3-2

    let elem_len = G::ElemLen::U16.to_be_bytes();

    if c_slice.len() != d_slice.len() {
        return Err(Error::MismatchedLengthsForCompositeInputs);
    }

    let len = u16::try_from(c_slice.len()).map_err(|_| Error::SerializationError)?;

    let seed_dst = GenericArray::from(STR_SEED).concat(get_context_string::<G>(Mode::Verifiable));
    let composite_dst =
        GenericArray::from(STR_COMPOSITE).concat(get_context_string::<G>(Mode::Verifiable));
    let composite_dst_len = i2osp_2_array(composite_dst);

    let seed = H::new()
        .chain_update(&elem_len)
        .chain_update(G::serialize_elem(b))
        .chain_update(i2osp_2_array(seed_dst))
        .chain_update(seed_dst)
        .finalize();
    let seed_len = i2osp_2(seed.len())?;

    let mut m = G::identity_elem();
    let mut z = G::identity_elem();

    for (i, (c, d)) in (0..len).zip(c_slice.zip(d_slice)) {
        // Ci = GG.SerializeElement(Cs[i])
        let ci = G::serialize_elem(c.value);
        // Di = GG.SerializeElement(Ds[i])
        let di = G::serialize_elem(d.value);
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
        let di = G::hash_to_scalar::<H>(&h2_input, Mode::Verifiable)?;
        m = c.value * &di + &m;
        z = match k_option {
            Some(_) => z,
            None => d.value * &di + &z,
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

    fn prf<G: Group, H: BlockSizeUser + Digest>(
        input: &[u8],
        key: G::Scalar,
        info: &[u8],
        mode: Mode,
    ) -> Output<H>
    where
        H::OutputSize: IsLess<U256> + IsLessOrEqual<H::BlockSize>,
    {
        let point = G::hash_to_curve::<H>(&[input], mode).unwrap();

        let context_string = get_context_string::<G>(mode);
        let info_len = i2osp_2(info.len()).unwrap();
        let context = [&STR_CONTEXT, context_string.as_slice(), &info_len, info];

        let m = G::hash_to_scalar::<H>(&context, mode).unwrap();

        let res = point * &G::invert_scalar(key + &m);

        finalize_after_unblind::<G, H, _, _>(Some((input, res)).into_iter(), info, mode)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
    }

    fn base_retrieval<G: Group, H: BlockSizeUser + Digest>()
    where
        H::OutputSize: IsLess<U256> + IsLessOrEqual<H::BlockSize>,
    {
        let input = b"input";
        let info = b"info";
        let mut rng = OsRng;
        let client_blind_result = NonVerifiableClient::<G, H>::blind(input, &mut rng).unwrap();
        let server = NonVerifiableServer::<G, H>::new(&mut rng).unwrap();
        let server_result = server
            .evaluate(&client_blind_result.message, Some(info))
            .unwrap();
        let client_finalize_result = client_blind_result
            .state
            .finalize(input, &server_result.message, Some(info))
            .unwrap();
        let res2 = prf::<G, H>(input, server.get_private_key(), info, Mode::Base);
        assert_eq!(client_finalize_result, res2);
    }

    fn verifiable_retrieval<G: Group, H: BlockSizeUser + Digest>()
    where
        H::OutputSize: IsLess<U256> + IsLessOrEqual<H::BlockSize>,
    {
        let input = b"input";
        let info = b"info";
        let mut rng = OsRng;
        let client_blind_result = VerifiableClient::<G, H>::blind(input, &mut rng).unwrap();
        let server = VerifiableServer::<G, H>::new(&mut rng).unwrap();
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
        let res2 = prf::<G, H>(input, server.get_private_key(), info, Mode::Verifiable);
        assert_eq!(client_finalize_result, res2);
    }

    fn verifiable_bad_public_key<G: Group, H: BlockSizeUser + Digest>()
    where
        H::OutputSize: IsLess<U256> + IsLessOrEqual<H::BlockSize>,
    {
        let input = b"input";
        let info = b"info";
        let mut rng = OsRng;
        let client_blind_result = VerifiableClient::<G, H>::blind(input, &mut rng).unwrap();
        let server = VerifiableServer::<G, H>::new(&mut rng).unwrap();
        let server_result = server
            .evaluate(&mut rng, &client_blind_result.message, Some(info))
            .unwrap();
        let wrong_pk = {
            // Choose a group element that is unlikely to be the right public key
            G::hash_to_curve::<H>(&[b"msg"], Mode::Base).unwrap()
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

    fn verifiable_batch_retrieval<G: Group, H: BlockSizeUser + Digest>()
    where
        H::OutputSize: IsLess<U256> + IsLessOrEqual<H::BlockSize>,
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
            let client_blind_result = VerifiableClient::<G, H>::blind(&input, &mut rng).unwrap();
            inputs.push(input);
            client_states.push(client_blind_result.state);
            client_messages.push(client_blind_result.message);
        }
        let server = VerifiableServer::<G, H>::new(&mut rng).unwrap();
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
            let output = prf::<G, H>(input, server.get_private_key(), info, Mode::Verifiable);
            res2.push(output);
        }
        assert_eq!(client_finalize_result, res2);
    }

    fn verifiable_batch_bad_public_key<G: Group, H: BlockSizeUser + Digest>()
    where
        H::OutputSize: IsLess<U256> + IsLessOrEqual<H::BlockSize>,
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
            let client_blind_result = VerifiableClient::<G, H>::blind(&input, &mut rng).unwrap();
            inputs.push(input);
            client_states.push(client_blind_result.state);
            client_messages.push(client_blind_result.message);
        }
        let server = VerifiableServer::<G, H>::new(&mut rng).unwrap();
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
            G::hash_to_curve::<H>(&[b"msg"], Mode::Base).unwrap()
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

    fn base_inversion_unsalted<G: Group, H: BlockSizeUser + Digest>()
    where
        H::OutputSize: IsLess<U256> + IsLessOrEqual<H::BlockSize>,
    {
        let mut rng = OsRng;
        let mut input = [0u8; 64];
        rng.fill_bytes(&mut input);
        let info = b"info";
        let client_blind_result = NonVerifiableClient::<G, H>::blind(&input, &mut rng).unwrap();
        let client_finalize_result = client_blind_result
            .state
            .finalize(
                &input,
                &EvaluationElement {
                    value: client_blind_result.message.value,
                    hash: PhantomData,
                },
                Some(info),
            )
            .unwrap();

        let point = G::hash_to_curve::<H>(&[&input], Mode::Base).unwrap();
        let res2 = finalize_after_unblind::<G, H, _, _>(
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

    fn zeroize_base_client<G: Group, H: BlockSizeUser + Digest>()
    where
        H::OutputSize: IsLess<U256> + IsLessOrEqual<H::BlockSize>,
    {
        let input = b"input";
        let mut rng = OsRng;
        let client_blind_result = NonVerifiableClient::<G, H>::blind(input, &mut rng).unwrap();

        let mut state = client_blind_result.state;
        Zeroize::zeroize(&mut state);
        assert!(state.serialize().iter().all(|&x| x == 0));

        let mut message = client_blind_result.message;
        Zeroize::zeroize(&mut message);
        assert!(message.serialize().iter().all(|&x| x == 0));
    }

    fn zeroize_verifiable_client<G: Group, H: BlockSizeUser + Digest>()
    where
        H::OutputSize: IsLess<U256> + IsLessOrEqual<H::BlockSize>,
        G::ScalarLen: Add<G::ElemLen>,
        Sum<G::ScalarLen, G::ElemLen>: ArrayLength<u8>,
    {
        let input = b"input";
        let mut rng = OsRng;
        let client_blind_result = VerifiableClient::<G, H>::blind(input, &mut rng).unwrap();

        let mut state = client_blind_result.state;
        Zeroize::zeroize(&mut state);
        assert!(state.serialize().iter().all(|&x| x == 0));

        let mut message = client_blind_result.message;
        Zeroize::zeroize(&mut message);
        assert!(message.serialize().iter().all(|&x| x == 0));
    }

    fn zeroize_base_server<G: Group, H: BlockSizeUser + Digest>()
    where
        H::OutputSize: IsLess<U256> + IsLessOrEqual<H::BlockSize>,
    {
        let input = b"input";
        let info = b"info";
        let mut rng = OsRng;
        let client_blind_result = NonVerifiableClient::<G, H>::blind(input, &mut rng).unwrap();
        let server = NonVerifiableServer::<G, H>::new(&mut rng).unwrap();
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

    fn zeroize_verifiable_server<G: Group, H: BlockSizeUser + Digest>()
    where
        H::OutputSize: IsLess<U256> + IsLessOrEqual<H::BlockSize>,
        G::ScalarLen: Add<G::ElemLen>,
        Sum<G::ScalarLen, G::ElemLen>: ArrayLength<u8>,
        G::ScalarLen: Add<G::ScalarLen>,
        Sum<G::ScalarLen, G::ScalarLen>: ArrayLength<u8>,
    {
        let input = b"input";
        let info = b"info";
        let mut rng = OsRng;
        let client_blind_result = VerifiableClient::<G, H>::blind(input, &mut rng).unwrap();
        let server = VerifiableServer::<G, H>::new(&mut rng).unwrap();
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
            use sha2::Sha512;

            use crate::Ristretto255;

            base_retrieval::<Ristretto255, Sha512>();
            base_inversion_unsalted::<Ristretto255, Sha512>();
            verifiable_retrieval::<Ristretto255, Sha512>();
            verifiable_batch_retrieval::<Ristretto255, Sha512>();
            verifiable_bad_public_key::<Ristretto255, Sha512>();
            verifiable_batch_bad_public_key::<Ristretto255, Sha512>();

            zeroize_base_client::<Ristretto255, Sha512>();
            zeroize_base_server::<Ristretto255, Sha512>();
            zeroize_verifiable_client::<Ristretto255, Sha512>();
            zeroize_verifiable_server::<Ristretto255, Sha512>();
        }

        #[cfg(feature = "p256")]
        {
            use p256::NistP256;
            use sha2::Sha256;

            base_retrieval::<NistP256, Sha256>();
            base_inversion_unsalted::<NistP256, Sha256>();
            verifiable_retrieval::<NistP256, Sha256>();
            verifiable_batch_retrieval::<NistP256, Sha256>();
            verifiable_bad_public_key::<NistP256, Sha256>();
            verifiable_batch_bad_public_key::<NistP256, Sha256>();

            zeroize_base_client::<NistP256, Sha256>();
            zeroize_base_server::<NistP256, Sha256>();
            zeroize_verifiable_client::<NistP256, Sha256>();
            zeroize_verifiable_server::<NistP256, Sha256>();
        }

        Ok(())
    }
}

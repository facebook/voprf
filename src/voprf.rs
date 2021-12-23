// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Contains the main VOPRF API

#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use core::convert::TryInto;
use core::iter::{self, Map, Repeat, Zip};
use core::marker::PhantomData;

use derive_where::DeriveWhere;
use digest::core_api::BlockSizeUser;
use digest::{Digest, FixedOutputReset};
use generic_array::sequence::Concat;
use generic_array::typenum::{U1, U11, U2, U20};
use generic_array::GenericArray;
use rand_core::{CryptoRng, RngCore};
use subtle::ConstantTimeEq;

use crate::errors::InternalError;
use crate::group::Group;
use crate::util::{i2osp, serialize, serialize_owned};

///////////////
// Constants //
// ========= //
///////////////

static STR_HASH_TO_SCALAR: [u8; 13] = *b"HashToScalar-";
static STR_HASH_TO_GROUP: [u8; 12] = *b"HashToGroup-";
static STR_FINALIZE: [u8; 9] = *b"Finalize-";
static STR_SEED: [u8; 5] = *b"Seed-";
static STR_CONTEXT: [u8; 8] = *b"Context-";
static STR_COMPOSITE: [u8; 10] = *b"Composite-";
static STR_CHALLENGE: [u8; 10] = *b"Challenge-";
static STR_VOPRF: [u8; 8] = *b"VOPRF08-";

/// Determines the mode of operation (either base mode or verifiable mode)
#[derive(Clone, Copy)]
enum Mode {
    Base = 0,
    Verifiable = 1,
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
pub struct NonVerifiableClient<G: Group, H: BlockSizeUser + Digest + FixedOutputReset> {
    pub(crate) blind: G::Scalar,
    #[derive_where(skip(Zeroize))]
    pub(crate) hash: PhantomData<H>,
}

/// A client which engages with a [VerifiableServer] in verifiable mode, meaning
/// that the OPRF outputs can be checked against a server public key.
#[derive(DeriveWhere)]
#[derive_where(Clone, Zeroize(drop))]
#[derive_where(Debug, Eq, Hash, Ord, PartialEq, PartialOrd; G, G::Scalar)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(bound(
        deserialize = "G::Scalar: serde::Deserialize<'de>, G: serde::Deserialize<'de>",
        serialize = "G::Scalar: serde::Serialize, G: serde::Serialize"
    ))
)]
pub struct VerifiableClient<G: Group, H: BlockSizeUser + Digest + FixedOutputReset> {
    pub(crate) blind: G::Scalar,
    pub(crate) blinded_element: G,
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
pub struct NonVerifiableServer<G: Group, H: BlockSizeUser + Digest + FixedOutputReset> {
    pub(crate) sk: G::Scalar,
    #[derive_where(skip(Zeroize))]
    pub(crate) hash: PhantomData<H>,
}

/// A server which engages with a [VerifiableClient] in verifiable mode, meaning
/// that the OPRF outputs can be checked against a server public key.
#[derive(DeriveWhere)]
#[derive_where(Clone, Zeroize(drop))]
#[derive_where(Debug, Eq, Hash, Ord, PartialEq, PartialOrd; G, G::Scalar)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(bound(
        deserialize = "G::Scalar: serde::Deserialize<'de>, G: serde::Deserialize<'de>",
        serialize = "G::Scalar: serde::Serialize, G: serde::Serialize"
    ))
)]
pub struct VerifiableServer<G: Group, H: BlockSizeUser + Digest + FixedOutputReset> {
    pub(crate) sk: G::Scalar,
    pub(crate) pk: G,
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
pub struct Proof<G: Group, H: BlockSizeUser + Digest + FixedOutputReset> {
    pub(crate) c_scalar: G::Scalar,
    pub(crate) s_scalar: G::Scalar,
    #[derive_where(skip(Zeroize))]
    pub(crate) hash: PhantomData<H>,
}

/// The first client message sent from a client (either verifiable or not) to a
/// server (either verifiable or not).
#[derive(DeriveWhere)]
#[derive_where(Clone, Zeroize(drop))]
#[derive_where(Debug, Eq, Hash, Ord, PartialEq, PartialOrd; G)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(bound(
        deserialize = "G: serde::Deserialize<'de>",
        serialize = "G: serde::Serialize"
    ))
)]
pub struct BlindedElement<G: Group, H: BlockSizeUser + Digest + FixedOutputReset> {
    pub(crate) value: G,
    #[derive_where(skip(Zeroize))]
    pub(crate) hash: PhantomData<H>,
}

/// The server's response to the [BlindedElement] message from a client (either
/// verifiable or not) to a server (either verifiable or not).
#[derive(DeriveWhere)]
#[derive_where(Clone, Zeroize(drop))]
#[derive_where(Debug, Eq, Hash, Ord, PartialEq, PartialOrd; G)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(bound(
        deserialize = "G: serde::Deserialize<'de>",
        serialize = "G: serde::Serialize"
    ))
)]
pub struct EvaluationElement<G: Group, H: BlockSizeUser + Digest + FixedOutputReset> {
    pub(crate) value: G,
    #[derive_where(skip(Zeroize))]
    pub(crate) hash: PhantomData<H>,
}

/////////////////////////
// API Implementations //
// =================== //
/////////////////////////

impl<G: Group, H: BlockSizeUser + Digest + FixedOutputReset> NonVerifiableClient<G, H> {
    /// Computes the first step for the multiplicative blinding version of
    /// DH-OPRF.
    pub fn blind<R: RngCore + CryptoRng>(
        input: &[u8],
        blinding_factor_rng: &mut R,
    ) -> Result<NonVerifiableClientBlindResult<G, H>, InternalError> {
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
    ) -> Result<NonVerifiableClientBlindResult<G, H>, InternalError> {
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
    ) -> Result<GenericArray<u8, H::OutputSize>, InternalError> {
        let unblinded_element = evaluation_element.value * &G::scalar_invert(&self.blind);
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

impl<G: Group, H: BlockSizeUser + Digest + FixedOutputReset> VerifiableClient<G, H> {
    /// Computes the first step for the multiplicative blinding version of
    /// DH-OPRF.
    pub fn blind<R: RngCore + CryptoRng>(
        input: &[u8],
        blinding_factor_rng: &mut R,
    ) -> Result<VerifiableClientBlindResult<G, H>, InternalError> {
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
    ) -> Result<VerifiableClientBlindResult<G, H>, InternalError> {
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
        pk: G,
        metadata: Option<&[u8]>,
    ) -> Result<GenericArray<u8, H::OutputSize>, InternalError> {
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
        pk: G,
        metadata: Option<&'a [u8]>,
    ) -> Result<VerifiableClientBatchFinalizeResult<'a, G, H, I, II, IC, IM>, InternalError>
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
    pub fn from_blind_and_element(blind: G::Scalar, blinded_element: G) -> Self {
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

impl<G: Group, H: BlockSizeUser + Digest + FixedOutputReset> NonVerifiableServer<G, H> {
    /// Produces a new instance of a [NonVerifiableServer] using a supplied RNG
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Result<Self, InternalError> {
        let mut seed = GenericArray::<_, H::OutputSize>::default();
        rng.fill_bytes(&mut seed);
        Self::new_from_seed(&seed)
    }

    /// Produces a new instance of a [NonVerifiableServer] using a supplied set
    /// of bytes to represent the server's private key
    pub fn new_with_key(private_key_bytes: &[u8]) -> Result<Self, InternalError> {
        let sk = G::from_scalar_slice(private_key_bytes)?;
        Ok(Self {
            sk,
            hash: PhantomData,
        })
    }

    /// Produces a new instance of a [NonVerifiableServer] using a supplied set
    /// of bytes which are used as a seed to derive the server's private key.
    ///
    /// Corresponds to DeriveKeyPair() function from the VOPRF specification.
    pub fn new_from_seed(seed: &[u8]) -> Result<Self, InternalError> {
        let dst =
            GenericArray::from(STR_HASH_TO_SCALAR).concat(get_context_string::<G>(Mode::Base)?);
        let sk = G::hash_to_scalar::<H, _, _>(Some(seed), dst)?;
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
    ) -> Result<NonVerifiableServerEvaluateResult<G, H>, InternalError> {
        chain!(
            context,
            STR_CONTEXT => |x| Some(x.as_ref()),
            get_context_string::<G>(Mode::Base)? => |x| Some(x.as_slice()),
            serialize::<U2>(metadata.unwrap_or_default())?,
        );
        let dst =
            GenericArray::from(STR_HASH_TO_SCALAR).concat(get_context_string::<G>(Mode::Base)?);
        let m = G::hash_to_scalar::<H, _, _>(context, dst)?;
        let t = self.sk + &m;
        let evaluation_element = blinded_element.value * &G::scalar_invert(&t);
        Ok(NonVerifiableServerEvaluateResult {
            message: EvaluationElement {
                value: evaluation_element,
                hash: PhantomData,
            },
        })
    }
}

impl<G: Group, H: BlockSizeUser + Digest + FixedOutputReset> VerifiableServer<G, H> {
    /// Produces a new instance of a [VerifiableServer] using a supplied RNG
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Result<Self, InternalError> {
        let mut seed = GenericArray::<_, H::OutputSize>::default();
        rng.fill_bytes(&mut seed);
        Self::new_from_seed(&seed)
    }

    /// Produces a new instance of a [VerifiableServer] using a supplied set of
    /// bytes to represent the server's private key
    pub fn new_with_key(key: &[u8]) -> Result<Self, InternalError> {
        let sk = G::from_scalar_slice(key)?;
        let pk = G::base_point() * &sk;
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
    pub fn new_from_seed(seed: &[u8]) -> Result<Self, InternalError> {
        let dst = GenericArray::from(STR_HASH_TO_SCALAR)
            .concat(get_context_string::<G>(Mode::Verifiable)?);
        let sk = G::hash_to_scalar::<H, _, _>(Some(seed), dst)?;
        let pk = G::base_point() * &sk;
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
    ) -> Result<VerifiableServerEvaluateResult<G, H>, InternalError> {
        let (mut evaluation_elements, t) =
            self.batch_evaluate_1(Some(blinded_element.copy()).into_iter(), metadata)?;

        let evaluation_element = evaluation_elements.next().unwrap();

        let proof = Self::batch_evaluate_2(
            rng,
            Some(blinded_element.copy()).into_iter(),
            Some(evaluation_element.copy()).into_iter(),
            t,
        )?;

        //let batch_result = self.batch_evaluate(rng, blinded_elements, metadata)?;
        Ok(VerifiableServerEvaluateResult {
            message: evaluation_element,
            proof,
        })
    }

    /// Allows for batching of the evaluation of multiple [BlindedElement]
    /// messages from a [VerifiableClient]
    #[cfg(feature = "alloc")]
    pub fn batch_evaluate<'a, R: RngCore + CryptoRng, I>(
        &self,
        rng: &mut R,
        blinded_elements: &'a I,
        metadata: Option<&[u8]>,
    ) -> Result<VerifiableServerBatchEvaluateResult<G, H>, InternalError>
    where
        G: 'a,
        H: 'a,
        &'a I: IntoIterator<Item = &'a BlindedElement<G, H>>,
        <&'a I as IntoIterator>::IntoIter: ExactSizeIterator,
    {
        let (evaluation_elements, t) = self.batch_evaluate_1(
            blinded_elements.into_iter().map(BlindedElement::copy),
            metadata,
        )?;

        let evaluation_elements: Vec<_> = evaluation_elements.collect();

        let proof = Self::batch_evaluate_2(
            rng,
            blinded_elements.into_iter().map(BlindedElement::copy),
            evaluation_elements.iter().map(EvaluationElement::copy),
            t,
        )?;

        Ok(VerifiableServerBatchEvaluateResult {
            messages: evaluation_elements,
            proof,
        })
    }

    fn batch_evaluate_1<I>(
        &self,
        blinded_elements: I,
        metadata: Option<&[u8]>,
    ) -> Result<
        (
            impl Iterator<Item = EvaluationElement<G, H>> + ExactSizeIterator,
            G::Scalar,
        ),
        InternalError,
    >
    where
        I: Iterator<Item = BlindedElement<G, H>> + ExactSizeIterator,
    {
        chain!(context,
            STR_CONTEXT => |x| Some(x.as_ref()),
            get_context_string::<G>(Mode::Verifiable)? => |x| Some(x.as_slice()),
            serialize::<U2>(metadata.unwrap_or_default())?,
        );
        let dst = GenericArray::from(STR_HASH_TO_SCALAR)
            .concat(get_context_string::<G>(Mode::Verifiable)?);
        let m = G::hash_to_scalar::<H, _, _>(context, dst)?;
        let t = self.sk + &m;
        let evaluation_elements = blinded_elements.map(move |x| EvaluationElement {
            value: x.value * &G::scalar_invert(&t),
            hash: PhantomData,
        });

        Ok((evaluation_elements, t))
    }

    /// Allows for batching of the evaluation of multiple [BlindedElement]
    /// messages from a [VerifiableClient]
    fn batch_evaluate_2<R: RngCore + CryptoRng, IE, IB>(
        rng: &mut R,
        blinded_elements: IB,
        evaluation_elements: IE,
        t: G::Scalar,
    ) -> Result<Proof<G, H>, InternalError>
    where
        IB: Iterator<Item = BlindedElement<G, H>> + ExactSizeIterator,
        IE: Iterator<Item = EvaluationElement<G, H>> + ExactSizeIterator,
    {
        let g = G::base_point();
        let u = g * &t;

        generate_proof(rng, t, g, u, evaluation_elements, blinded_elements)
    }

    /// Retrieves the server's public key
    pub fn get_public_key(&self) -> G {
        self.pk
    }
}

/////////////////////////
// Convenience Structs //
//==================== //
/////////////////////////

/// Contains the fields that are returned by a non-verifiable client blind
pub struct NonVerifiableClientBlindResult<G: Group, H: BlockSizeUser + Digest + FixedOutputReset> {
    /// The state to be persisted on the client
    pub state: NonVerifiableClient<G, H>,
    /// The message to send to the server
    pub message: BlindedElement<G, H>,
}

/// Contains the fields that are returned by a non-verifiable server evaluate
pub struct NonVerifiableServerEvaluateResult<G: Group, H: BlockSizeUser + Digest + FixedOutputReset>
{
    /// The message to send to the client
    pub message: EvaluationElement<G, H>,
}

/// Contains the fields that are returned by a verifiable client blind
pub struct VerifiableClientBlindResult<G: Group, H: BlockSizeUser + Digest + FixedOutputReset> {
    /// The state to be persisted on the client
    pub state: VerifiableClient<G, H>,
    /// The message to send to the server
    pub message: BlindedElement<G, H>,
}

pub type VerifiableClientBatchFinalizeResult<'a, G, H, I, II, IC, IM> = FinalizeAfterUnblindResult<
    'a,
    G,
    H,
    I,
    Zip<<&'a II as IntoIterator>::IntoIter, VerifiableUnblindResult<'a, G, H, IC, IM>>,
>;

/// Contains the fields that are returned by a verifiable server evaluate
pub struct VerifiableServerEvaluateResult<G: Group, H: BlockSizeUser + Digest + FixedOutputReset> {
    /// The message to send to the client
    pub message: EvaluationElement<G, H>,
    /// The proof for the client to verify
    pub proof: Proof<G, H>,
}

/// Contains the fields that are returned by a verifiable server batch evaluate
#[cfg(feature = "alloc")]
pub struct VerifiableServerBatchEvaluateResult<
    G: Group,
    H: BlockSizeUser + Digest + FixedOutputReset,
> {
    /// The messages to send to the client
    pub messages: alloc::vec::Vec<EvaluationElement<G, H>>,
    /// The proof for the client to verify
    pub proof: Proof<G, H>,
}

///////////////////////////////////////////////
// Inner functions and Trait Implementations //
// ========================================= //
///////////////////////////////////////////////

impl<G: Group, H: BlockSizeUser + Digest + FixedOutputReset> BlindedElement<G, H> {
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
    pub fn from_value_unchecked(value: G) -> Self {
        Self {
            value,
            hash: PhantomData,
        }
    }

    #[cfg(feature = "danger")]
    /// Exposes the internal value
    pub fn value(&self) -> G {
        self.value
    }
}

impl<G: Group, H: BlockSizeUser + Digest + FixedOutputReset> EvaluationElement<G, H> {
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
    pub fn from_value_unchecked(value: G) -> Self {
        Self {
            value,
            hash: PhantomData,
        }
    }

    #[cfg(feature = "danger")]
    /// Exposes the internal value
    pub fn value(&self) -> G {
        self.value
    }
}

// Inner function for blind. Returns the blind scalar and the blinded element
fn blind<G: Group, H: BlockSizeUser + Digest + FixedOutputReset, R: RngCore + CryptoRng>(
    input: &[u8],
    blinding_factor_rng: &mut R,
    mode: Mode,
) -> Result<(G::Scalar, G), InternalError> {
    // Choose a random scalar that must be non-zero
    let blind = G::random_nonzero_scalar(blinding_factor_rng);
    let blinded_element = deterministic_blind_unchecked::<G, H>(input, &blind, mode)?;
    Ok((blind, blinded_element))
}

// Inner function for blind that assumes that the blinding factor has already
// been chosen, and therefore takes it as input. Does not check if the blinding
// factor is non-zero.
fn deterministic_blind_unchecked<G: Group, H: BlockSizeUser + Digest + FixedOutputReset>(
    input: &[u8],
    blind: &G::Scalar,
    mode: Mode,
) -> Result<G, InternalError> {
    let dst = GenericArray::from(STR_HASH_TO_GROUP).concat(get_context_string::<G>(mode)?);
    let hashed_point = G::hash_to_curve::<H, _>(input, dst)?;
    Ok(hashed_point * blind)
}

#[allow(type_alias_bounds)]
type VerifiableUnblindResult<'a, G: Group, H, IC, IM> = Map<
    Zip<
        Map<<&'a IC as IntoIterator>::IntoIter, fn(&VerifiableClient<G, H>) -> G::Scalar>,
        <&'a IM as IntoIterator>::IntoIter,
    >,
    fn((G::Scalar, &EvaluationElement<G, H>)) -> G,
>;

fn verifiable_unblind<
    'a,
    G: 'a + Group,
    H: 'a + BlockSizeUser + Digest + FixedOutputReset,
    IC,
    IM,
>(
    clients: &'a IC,
    messages: &'a IM,
    pk: G,
    proof: &Proof<G, H>,
    info: &[u8],
) -> Result<VerifiableUnblindResult<'a, G, H, IC, IM>, InternalError>
where
    &'a IC: 'a + IntoIterator<Item = &'a VerifiableClient<G, H>>,
    <&'a IC as IntoIterator>::IntoIter: ExactSizeIterator,
    &'a IM: 'a + IntoIterator<Item = &'a EvaluationElement<G, H>>,
    <&'a IM as IntoIterator>::IntoIter: ExactSizeIterator,
{
    chain!(context,
        STR_CONTEXT => |x| Some(x.as_ref()),
        get_context_string::<G>(Mode::Verifiable)? => |x| Some(x.as_slice()),
        serialize::<U2>(info)?,
    );

    let dst =
        GenericArray::from(STR_HASH_TO_SCALAR).concat(get_context_string::<G>(Mode::Verifiable)?);
    let m = G::hash_to_scalar::<H, _, _>(context, dst)?;

    let g = G::base_point();
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
        .map(|(blind, x)| x.value * &G::scalar_invert(&blind)))
}

#[allow(clippy::many_single_char_names)]
fn generate_proof<
    G: Group,
    H: BlockSizeUser + Digest + FixedOutputReset,
    R: RngCore + CryptoRng,
>(
    rng: &mut R,
    k: G::Scalar,
    a: G,
    b: G,
    cs: impl Iterator<Item = EvaluationElement<G, H>> + ExactSizeIterator,
    ds: impl Iterator<Item = BlindedElement<G, H>> + ExactSizeIterator,
) -> Result<Proof<G, H>, InternalError> {
    let (m, z) = compute_composites(Some(k), b, cs, ds)?;

    let r = G::random_nonzero_scalar(rng);
    let t2 = a * &r;
    let t3 = m * &r;

    let challenge_dst =
        GenericArray::from(STR_CHALLENGE).concat(get_context_string::<G>(Mode::Verifiable)?);
    chain!(
        h2_input,
        serialize_owned::<U2, _>(b.to_arr())?,
        serialize_owned::<U2, _>(m.to_arr())?,
        serialize_owned::<U2, _>(z.to_arr())?,
        serialize_owned::<U2, _>(t2.to_arr())?,
        serialize_owned::<U2, _>(t3.to_arr())?,
        serialize_owned::<U2, _>(challenge_dst)?,
    );

    let hash_to_scalar_dst =
        GenericArray::from(STR_HASH_TO_SCALAR).concat(get_context_string::<G>(Mode::Verifiable)?);

    let c_scalar = G::hash_to_scalar::<H, _, _>(h2_input, hash_to_scalar_dst)?;
    let s_scalar = r - &(c_scalar * &k);

    Ok(Proof {
        c_scalar,
        s_scalar,
        hash: PhantomData,
    })
}

#[allow(clippy::many_single_char_names)]
fn verify_proof<G: Group, H: BlockSizeUser + Digest + FixedOutputReset>(
    a: G,
    b: G,
    cs: impl Iterator<Item = EvaluationElement<G, H>> + ExactSizeIterator,
    ds: impl Iterator<Item = BlindedElement<G, H>> + ExactSizeIterator,
    proof: &Proof<G, H>,
) -> Result<(), InternalError> {
    let (m, z) = compute_composites(None, b, cs, ds)?;
    let t2 = (a * &proof.s_scalar) + &(b * &proof.c_scalar);
    let t3 = (m * &proof.s_scalar) + &(z * &proof.c_scalar);

    let challenge_dst =
        GenericArray::from(STR_CHALLENGE).concat(get_context_string::<G>(Mode::Verifiable)?);
    chain!(
        h2_input,
        serialize_owned::<U2, _>(b.to_arr())?,
        serialize_owned::<U2, _>(m.to_arr())?,
        serialize_owned::<U2, _>(z.to_arr())?,
        serialize_owned::<U2, _>(t2.to_arr())?,
        serialize_owned::<U2, _>(t3.to_arr())?,
        serialize_owned::<U2, _>(challenge_dst)?,
    );

    let hash_to_scalar_dst =
        GenericArray::from(STR_HASH_TO_SCALAR).concat(get_context_string::<G>(Mode::Verifiable)?);
    let c = G::hash_to_scalar::<H, _, _>(h2_input, hash_to_scalar_dst)?;

    match c.ct_eq(&proof.c_scalar).into() {
        true => Ok(()),
        false => Err(InternalError::ProofVerificationError),
    }
}

#[allow(type_alias_bounds)]
type FinalizeAfterUnblindResult<'a, G, H: Digest, I, IE> = Map<
    Zip<IE, Repeat<(&'a [u8], GenericArray<u8, U20>)>>,
    fn(
        ((I, G), (&'a [u8], GenericArray<u8, U20>)),
    ) -> Result<GenericArray<u8, H::OutputSize>, InternalError>,
>;

fn finalize_after_unblind<
    'a,
    G: Group,
    H: BlockSizeUser + Digest + FixedOutputReset,
    I: AsRef<[u8]>,
    IE: 'a + Iterator<Item = (I, G)>,
>(
    inputs_and_unblinded_elements: IE,
    info: &'a [u8],
    mode: Mode,
) -> Result<FinalizeAfterUnblindResult<G, H, I, IE>, InternalError> {
    let finalize_dst = GenericArray::from(STR_FINALIZE).concat(get_context_string::<G>(mode)?);

    Ok(inputs_and_unblinded_elements
        // To make a return type possible, we have to convert to a `fn` pointer,
        // which isn't possible if we `move` from context.
        .zip(iter::repeat((info, finalize_dst)))
        .map(|((input, unblinded_element), (info, finalize_dst))| {
            chain!(
                hash_input,
                serialize::<U2>(input.as_ref())?,
                serialize::<U2>(info)?,
                serialize_owned::<U2, _>(unblinded_element.to_arr())?,
                serialize_owned::<U2, _>(finalize_dst)?,
            );

            Ok(hash_input
                .fold(H::new(), |h, bytes| h.chain_update(bytes))
                .finalize())
        }))
}

fn compute_composites<G: Group, H: BlockSizeUser + Digest + FixedOutputReset>(
    k_option: Option<G::Scalar>,
    b: G,
    c_slice: impl Iterator<Item = EvaluationElement<G, H>> + ExactSizeIterator,
    d_slice: impl Iterator<Item = BlindedElement<G, H>> + ExactSizeIterator,
) -> Result<(G, G), InternalError> {
    if c_slice.len() != d_slice.len() {
        return Err(InternalError::MismatchedLengthsForCompositeInputs);
    }

    let seed_dst = GenericArray::from(STR_SEED).concat(get_context_string::<G>(Mode::Verifiable)?);
    let composite_dst =
        GenericArray::from(STR_COMPOSITE).concat(get_context_string::<G>(Mode::Verifiable)?);

    chain!(
        h1_input,
        serialize_owned::<U2, _>(b.to_arr())?,
        serialize_owned::<U2, _>(seed_dst)?,
    );
    let seed = h1_input
        .fold(H::new(), |h, bytes| h.chain_update(bytes))
        .finalize();

    let mut m = G::identity();
    let mut z = G::identity();

    for (i, (c, d)) in c_slice.zip(d_slice).enumerate() {
        chain!(h2_input,
            serialize_owned::<U2, _>(seed.clone())?,
            i2osp::<U2>(i)? => |x| Some(x.as_slice()),
            serialize_owned::<U2, _>(c.value.to_arr())?,
            serialize_owned::<U2, _>(d.value.to_arr())?,
            serialize_owned::<U2, _>(composite_dst)?,
        );
        let dst = GenericArray::from(STR_HASH_TO_SCALAR)
            .concat(get_context_string::<G>(Mode::Verifiable)?);
        let di = G::hash_to_scalar::<H, _, _>(h2_input, dst)?;
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
fn get_context_string<G: Group>(mode: Mode) -> Result<GenericArray<u8, U11>, InternalError> {
    Ok(GenericArray::from(STR_VOPRF)
        .concat(i2osp::<U1>(mode as usize)?)
        .concat(i2osp::<U2>(G::SUITE_ID)?))
}

///////////
// Tests //
// ===== //
///////////

#[cfg(test)]
mod tests {
    use core::ops::Add;

    use generic_array::typenum::Sum;
    use generic_array::{ArrayLength, GenericArray};
    use rand::rngs::OsRng;
    use zeroize::Zeroize;
    #[cfg(feature = "alloc")]
    use ::{alloc::vec, alloc::vec::Vec};

    use super::*;
    use crate::group::Group;

    fn prf<G: Group, H: BlockSizeUser + Digest + FixedOutputReset>(
        input: &[u8],
        key: G::Scalar,
        info: &[u8],
        mode: Mode,
    ) -> GenericArray<u8, H::OutputSize> {
        let dst =
            GenericArray::from(STR_HASH_TO_GROUP).concat(get_context_string::<G>(mode).unwrap());
        let point = G::hash_to_curve::<H, _>(input, dst).unwrap();

        chain!(context,
            STR_CONTEXT => |x| Some(x.as_ref()),
            get_context_string::<G>(mode).unwrap() => |x| Some(x.as_slice()),
            serialize::<U2>(info).unwrap(),
        );

        let dst =
            GenericArray::from(STR_HASH_TO_SCALAR).concat(get_context_string::<G>(mode).unwrap());
        let m = G::hash_to_scalar::<H, _, _>(context, dst).unwrap();

        let res = point * &G::scalar_invert(&(key + &m));

        finalize_after_unblind::<G, H, _, _>(Some((input, res)).into_iter(), info, mode)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
    }

    fn base_retrieval<G: Group, H: BlockSizeUser + Digest + FixedOutputReset>() {
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

    fn verifiable_retrieval<G: Group, H: BlockSizeUser + Digest + FixedOutputReset>() {
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

    #[cfg(feature = "alloc")]
    fn verifiable_bad_public_key<G: Group, H: BlockSizeUser + Digest + FixedOutputReset>() {
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
            G::hash_to_curve::<H, _>(b"msg", (*b"dst").into()).unwrap()
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

    #[cfg(feature = "alloc")]
    fn verifiable_batch_retrieval<G: Group, H: BlockSizeUser + Digest + FixedOutputReset>() {
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
        let server_result = server
            .batch_evaluate(&mut rng, &client_messages, Some(info))
            .unwrap();
        let client_finalize_result = VerifiableClient::batch_finalize(
            &inputs,
            &client_states,
            &server_result.messages,
            &server_result.proof,
            server.get_public_key(),
            Some(info),
        )
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
        let mut res2 = vec![];
        for input in inputs.iter().take(num_iterations) {
            let output = prf::<G, H>(input, server.get_private_key(), info, Mode::Verifiable);
            res2.push(output);
        }
        assert_eq!(client_finalize_result, res2);
    }

    #[cfg(feature = "alloc")]
    fn verifiable_batch_bad_public_key<G: Group, H: BlockSizeUser + Digest + FixedOutputReset>() {
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
        let server_result = server
            .batch_evaluate(&mut rng, &client_messages, Some(info))
            .unwrap();
        let wrong_pk = {
            // Choose a group element that is unlikely to be the right public key
            G::hash_to_curve::<H, _>(b"msg", (*b"dst").into()).unwrap()
        };
        let client_finalize_result = VerifiableClient::batch_finalize(
            &inputs,
            &client_states,
            &server_result.messages,
            &server_result.proof,
            wrong_pk,
            Some(info),
        );
        assert!(client_finalize_result.is_err());
    }

    fn base_inversion_unsalted<G: Group, H: BlockSizeUser + Digest + FixedOutputReset>() {
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

        let dst = GenericArray::from(STR_HASH_TO_GROUP)
            .concat(get_context_string::<G>(Mode::Base).unwrap());
        let point = G::hash_to_curve::<H, _>(&input, dst).unwrap();
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

    fn zeroize_base_client<G: Group, H: BlockSizeUser + Digest + FixedOutputReset>() {
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

    fn zeroize_verifiable_client<G: Group, H: BlockSizeUser + Digest + FixedOutputReset>()
    where
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

    fn zeroize_base_server<G: Group, H: BlockSizeUser + Digest + FixedOutputReset>() {
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

    fn zeroize_verifiable_server<G: Group, H: BlockSizeUser + Digest + FixedOutputReset>()
    where
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
    fn test_functionality() -> Result<(), InternalError> {
        #[cfg(feature = "ristretto255")]
        {
            use curve25519_dalek::ristretto::RistrettoPoint;
            use sha2::Sha512;

            base_retrieval::<RistrettoPoint, Sha512>();
            base_inversion_unsalted::<RistrettoPoint, Sha512>();
            verifiable_retrieval::<RistrettoPoint, Sha512>();
            #[cfg(feature = "alloc")]
            verifiable_batch_retrieval::<RistrettoPoint, Sha512>();
            #[cfg(feature = "alloc")]
            verifiable_bad_public_key::<RistrettoPoint, Sha512>();
            #[cfg(feature = "alloc")]
            verifiable_batch_bad_public_key::<RistrettoPoint, Sha512>();

            zeroize_base_client::<RistrettoPoint, Sha512>();
            zeroize_base_server::<RistrettoPoint, Sha512>();
            zeroize_verifiable_client::<RistrettoPoint, Sha512>();
            zeroize_verifiable_server::<RistrettoPoint, Sha512>();
        }

        #[cfg(feature = "p256")]
        {
            use p256_::ProjectivePoint;
            use sha2::Sha256;

            base_retrieval::<ProjectivePoint, Sha256>();
            base_inversion_unsalted::<ProjectivePoint, Sha256>();
            verifiable_retrieval::<ProjectivePoint, Sha256>();
            verifiable_batch_retrieval::<ProjectivePoint, Sha256>();
            verifiable_bad_public_key::<ProjectivePoint, Sha256>();
            verifiable_batch_bad_public_key::<ProjectivePoint, Sha256>();

            zeroize_base_client::<ProjectivePoint, Sha256>();
            zeroize_base_server::<ProjectivePoint, Sha256>();
            zeroize_verifiable_client::<ProjectivePoint, Sha256>();
            zeroize_verifiable_server::<ProjectivePoint, Sha256>();
        }

        Ok(())
    }
}

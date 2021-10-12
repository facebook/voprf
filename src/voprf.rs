// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Contains the main VOPRF API

use crate::{
    errors::InternalError,
    group::Group,
    serialization::{i2osp, serialize},
};
use alloc::vec::Vec;
use core::marker::PhantomData;
use digest::{BlockInput, Digest};
use generic_array::sequence::Concat;
use generic_array::{
    typenum::{U1, U11, U2},
    GenericArray,
};
use rand::{CryptoRng, RngCore};

///////////////
// Constants //
// ========= //
///////////////

static STR_HASH_TO_SCALAR: &[u8; 13] = b"HashToScalar-";
static STR_HASH_TO_GROUP: &[u8; 12] = b"HashToGroup-";
static STR_FINALIZE: &[u8; 9] = b"Finalize-";
static STR_SEED: &[u8; 5] = b"Seed-";
static STR_CONTEXT: &[u8] = b"Context-";
static STR_COMPOSITE: &[u8; 10] = b"Composite-";
static STR_CHALLENGE: &[u8; 10] = b"Challenge-";
static STR_VOPRF: &[u8; 8] = b"VOPRF07-";

/// Determines the mode of operation (either base mode or
/// verifiable mode)
#[derive(Clone, Copy)]
enum Mode {
    Base = 0,
    Verifiable = 1,
}

////////////////////////////
// High-level API Structs //
// ====================== //
////////////////////////////

impl_traits_for! {
    /// A client which engages with a [NonVerifiableServer]
    /// in base mode, meaning that the OPRF outputs are not
    /// verifiable.
    pub struct NonVerifiableClient<G: Group, H: BlockInput + Digest> {
        #[bind]
        pub(crate) blind: <G as Group>::Scalar,
        pub(crate) data: Vec<u8>,
        #[pd]
        pub(crate) hash: PhantomData<H>,
    }
}

impl_traits_for! {
    /// A client which engages with a [VerifiableServer]
    /// in verifiable mode, meaning that the OPRF outputs
    /// can be checked against a server public key.
    pub struct VerifiableClient<G: Group, H: BlockInput + Digest> {
        #[bind]
        pub(crate) blind: <G as Group>::Scalar,
        #[bind]
        pub(crate) blinded_element: G,
        pub(crate) data: Vec<u8>,
        #[pd]
        pub(crate) hash: PhantomData<H>,
    }
}

impl_traits_for! {
    /// A server which engages with a [NonVerifiableClient]
    /// in base mode, meaning that the OPRF outputs are not
    /// verifiable.
    pub struct NonVerifiableServer<G: Group, H: BlockInput + Digest> {
        #[bind]
        pub(crate) sk: <G as Group>::Scalar,
        #[pd]
        pub(crate) hash: PhantomData<H>,
    }
}

impl_traits_for! {
    /// A server which engages with a [VerifiableClient]
    /// in verifiable mode, meaning that the OPRF outputs
    /// can be checked against a server public key.
    pub struct VerifiableServer<G: Group, H: BlockInput + Digest> {
        #[bind]
        pub(crate) sk: <G as Group>::Scalar,
        #[bind]
        pub(crate) pk: G,
        #[pd]
        pub(crate) hash: PhantomData<H>,
    }
}

impl_traits_for! {
    /// A proof produced by a [VerifiableServer] that
    /// the OPRF output matches against a server public key.
    pub struct Proof<G: Group, H: BlockInput + Digest> {
        #[bind]
        pub(crate) c_scalar: <G as Group>::Scalar,
        pub(crate) s_scalar: <G as Group>::Scalar,
        #[pd]
        pub(crate) hash: PhantomData<H>,
    }
}

impl_traits_for! {
    /// The first client message sent from a client (either verifiable or not)
    /// to a server (either verifiable or not).
    pub struct BlindedElement<G: Group, H: BlockInput + Digest> {
        #[bind]
        pub(crate) value: G,
        #[pd]
        pub(crate) hash: PhantomData<H>,
    }
}

impl_traits_for! {
    /// The server's response to the [BlindedElement] message from
    /// a client (either verifiable or not)
    /// to a server (either verifiable or not).
    pub struct EvaluationElement<G: Group, H: BlockInput + Digest> {
        #[bind]
        pub(crate) value: G,
        #[pd]
        pub(crate) hash: PhantomData<H>,
    }
}

/////////////////////////
// API Implementations //
// =================== //
/////////////////////////

impl<G: Group, H: BlockInput + Digest> NonVerifiableClient<G, H> {
    /// Computes the first step for the multiplicative blinding version of DH-OPRF.
    pub fn blind<R: RngCore + CryptoRng>(
        input: &[u8],
        blinding_factor_rng: &mut R,
    ) -> Result<NonVerifiableClientBlindResult<G, H>, InternalError> {
        let (blind, blinded_element) = blind::<G, H, _>(input, blinding_factor_rng, Mode::Base)?;
        Ok(NonVerifiableClientBlindResult {
            state: Self {
                data: input.to_vec(),
                blind,
                hash: PhantomData,
            },
            message: BlindedElement {
                value: blinded_element,
                hash: PhantomData,
            },
        })
    }

    /// Computes the third step for the multiplicative blinding version of DH-OPRF, in which
    /// the client unblinds the server's message.
    pub fn finalize(
        &self,
        evaluation_element: EvaluationElement<G, H>,
        metadata: &Metadata,
    ) -> Result<GenericArray<u8, <H as Digest>::OutputSize>, InternalError> {
        let unblinded_element =
            evaluation_element.value * &<G as Group>::scalar_invert(&self.blind);
        let outputs = finalize_after_unblind::<G, H>(
            &[(self.data.clone(), unblinded_element)],
            &metadata.0,
            Mode::Base,
        )?;
        Ok(outputs[0].clone())
    }

    #[cfg(test)]
    /// Only used for test functions
    pub fn from_data_and_blind(data: &[u8], blind: <G as Group>::Scalar) -> Self {
        Self {
            data: data.to_vec(),
            blind,
            hash: PhantomData,
        }
    }

    #[cfg(test)]
    /// Only used for test functions
    pub fn get_blind(&self) -> <G as Group>::Scalar {
        self.blind
    }

    #[cfg(test)]
    /// Only used for testing zeroize
    pub fn as_ptrs(&self) -> Vec<Vec<u8>> {
        vec![
            self.data.clone(),
            <G as Group>::scalar_as_bytes(self.blind).to_vec(),
        ]
    }
}

impl<G: Group, H: BlockInput + Digest> VerifiableClient<G, H> {
    /// Computes the first step for the multiplicative blinding version of DH-OPRF.
    pub fn blind<R: RngCore + CryptoRng>(
        input: &[u8],
        blinding_factor_rng: &mut R,
    ) -> Result<VerifiableClientBlindResult<G, H>, InternalError> {
        let (blind, blinded_element) =
            blind::<G, H, _>(input, blinding_factor_rng, Mode::Verifiable)?;
        Ok(VerifiableClientBlindResult {
            state: Self {
                data: input.to_vec(),
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

    /// Computes the third step for the multiplicative blinding version of DH-OPRF, in which
    /// the client unblinds the server's message.
    pub fn finalize(
        &self,
        evaluation_element: EvaluationElement<G, H>,
        proof: Proof<G, H>,
        pk: G,
        metadata: &Metadata,
    ) -> Result<GenericArray<u8, <H as Digest>::OutputSize>, InternalError> {
        let batch_result = Self::batch_finalize(
            &vec![self.clone()],
            &vec![evaluation_element],
            proof,
            pk,
            metadata,
        )?;
        Ok(batch_result[0].clone())
    }

    /// Allows for batching of the finalization of multiple [VerifiableClient] and [EvaluationElement] pairs
    pub fn batch_finalize<'a, IC, IM>(
        clients: &'a IC,
        messages: &'a IM,
        proof: Proof<G, H>,
        pk: G,
        metadata: &Metadata,
    ) -> Result<Vec<GenericArray<u8, <H as Digest>::OutputSize>>, InternalError>
    where
        G: 'a,
        H: 'a,
        &'a IC: 'a + IntoIterator<Item = &'a VerifiableClient<G, H>>,
        <&'a IC as IntoIterator>::IntoIter: ExactSizeIterator,
        &'a IM: 'a + IntoIterator<Item = &'a EvaluationElement<G, H>>,
        <&'a IM as IntoIterator>::IntoIter: ExactSizeIterator,
    {
        struct Items<IC, IM> {
            clients: IC,
            messages: IM,
        }

        impl<'a, G: 'a + Group, H: 'a + BlockInput + Digest, IC: Copy, IM: Copy> IntoIterator
            for &Items<IC, IM>
        where
            IC: IntoIterator<Item = &'a VerifiableClient<G, H>>,
            <IC as IntoIterator>::IntoIter: ExactSizeIterator,
            IM: IntoIterator<Item = &'a EvaluationElement<G, H>>,
            <IM as IntoIterator>::IntoIter: ExactSizeIterator,
        {
            type Item = BatchItems<G, H>;

            #[allow(clippy::type_complexity)]
            type IntoIter = core::iter::Map<
                core::iter::Zip<<IC as IntoIterator>::IntoIter, <IM as IntoIterator>::IntoIter>,
                fn((&VerifiableClient<G, H>, &EvaluationElement<G, H>)) -> BatchItems<G, H>,
            >;

            fn into_iter(self) -> Self::IntoIter {
                self.clients.into_iter().zip(self.messages.into_iter()).map(
                    |(client, evaluation_element)| BatchItems {
                        blind: client.blind,
                        evaluation_element: evaluation_element.copy(),
                        blinded_element: BlindedElement {
                            value: client.blinded_element,
                            hash: PhantomData,
                        },
                    },
                )
            }
        }

        let batch_items = Items { clients, messages };

        let unblinded_elements = verifiable_unblind(&batch_items, pk, proof, &metadata.0)?;

        let inputs_and_unblinded_elements: Vec<(Vec<u8>, G)> = clients
            .into_iter()
            .zip(unblinded_elements.iter())
            .map(|(client, &unblinded_element)| (client.data.clone(), unblinded_element))
            .collect();

        finalize_after_unblind::<G, H>(
            &inputs_and_unblinded_elements,
            &metadata.0,
            Mode::Verifiable,
        )
    }

    #[cfg(test)]
    /// Only used for test functions
    pub fn from_data_and_blind(
        data: &[u8],
        blind: <G as Group>::Scalar,
        blinded_element: G,
    ) -> Self {
        Self {
            data: data.to_vec(),
            blind,
            blinded_element,
            hash: PhantomData,
        }
    }

    #[cfg(test)]
    /// Only used for test functions
    pub fn get_blind(&self) -> <G as Group>::Scalar {
        self.blind
    }

    #[cfg(test)]
    /// Only used for testing zeroize
    pub fn as_ptrs(&self) -> Vec<Vec<u8>> {
        vec![
            self.data.clone(),
            <G as Group>::scalar_as_bytes(self.blind).to_vec(),
            self.blinded_element.to_arr().to_vec(),
        ]
    }
}

impl<G: Group, H: BlockInput + Digest> NonVerifiableServer<G, H> {
    /// Produces a new instance of a [NonVerifiableServer] using a supplied RNG
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Result<Self, InternalError> {
        let mut seed = GenericArray::<_, <H as Digest>::OutputSize>::default();
        rng.fill_bytes(&mut seed);
        Self::new_from_seed(&seed)
    }

    /// Produces a new instance of a [NonVerifiableServer] using a supplied set of bytes to
    /// represent the server's private key
    pub fn new_with_key(private_key_bytes: &[u8]) -> Result<Self, InternalError> {
        let sk = G::from_scalar_slice(private_key_bytes)?;
        Ok(Self {
            sk,
            hash: PhantomData,
        })
    }

    /// Produces a new instance of a [NonVerifiableServer] using a supplied set of bytes which
    /// are used as a seed to derive the server's private key.
    ///
    /// Corresponds to DeriveKeyPair() function from the VOPRF specification.
    pub fn new_from_seed(seed: &[u8]) -> Result<Self, InternalError> {
        let dst =
            GenericArray::from(*STR_HASH_TO_SCALAR).concat(get_context_string::<G>(Mode::Base)?);
        let sk = G::hash_to_scalar::<H>(seed, &dst)?;
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

    /// Computes the second step for the multiplicative blinding version of DH-OPRF. This
    /// message is sent from the server (who holds the OPRF key) to the client.
    pub fn evaluate(
        &self,
        blinded_element: BlindedElement<G, H>,
        metadata: &Metadata,
    ) -> Result<NonVerifiableServerEvaluateResult<G, H>, InternalError> {
        let context = [
            STR_CONTEXT,
            &get_context_string::<G>(Mode::Base)?,
            &serialize::<U2>(&metadata.0)?,
        ]
        .concat();
        let dst =
            GenericArray::from(*STR_HASH_TO_SCALAR).concat(get_context_string::<G>(Mode::Base)?);
        let m = G::hash_to_scalar::<H>(&context, &dst)?;
        let t = self.sk + &m;
        let evaluation_element = blinded_element.value * &G::scalar_invert(&t);
        Ok(NonVerifiableServerEvaluateResult {
            message: EvaluationElement {
                value: evaluation_element,
                hash: PhantomData,
            },
        })
    }

    #[cfg(test)]
    /// Only used for testing zeroize
    pub fn as_ptrs(&self) -> Vec<Vec<u8>> {
        vec![<G as Group>::scalar_as_bytes(self.sk).to_vec()]
    }
}

impl<G: Group, H: BlockInput + Digest> VerifiableServer<G, H> {
    /// Produces a new instance of a [VerifiableServer] using a supplied RNG
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Result<Self, InternalError> {
        let mut seed = GenericArray::<_, <H as Digest>::OutputSize>::default();
        rng.fill_bytes(&mut seed);
        Self::new_from_seed(&seed)
    }

    /// Produces a new instance of a [VerifiableServer] using a supplied set of bytes to
    /// represent the server's private key
    pub fn new_with_key(key: &[u8]) -> Result<Self, InternalError> {
        let sk = G::from_scalar_slice(key)?;
        let pk = G::base_point() * &sk;
        Ok(Self {
            sk,
            pk,
            hash: PhantomData,
        })
    }

    /// Produces a new instance of a [VerifiableServer] using a supplied set of bytes which
    /// are used as a seed to derive the server's private key.
    ///
    /// Corresponds to DeriveKeyPair() function from the VOPRF specification.
    pub fn new_from_seed(seed: &[u8]) -> Result<Self, InternalError> {
        let dst = GenericArray::from(*STR_HASH_TO_SCALAR)
            .concat(get_context_string::<G>(Mode::Verifiable)?);
        let sk = G::hash_to_scalar::<H>(seed, &dst)?;
        let pk = G::base_point() * &sk;
        Ok(Self {
            sk,
            pk,
            hash: PhantomData,
        })
    }

    // Only used for tests
    #[cfg(test)]
    pub fn get_private_key(&self) -> <G as Group>::Scalar {
        self.sk
    }

    /// Computes the second step for the multiplicative blinding version of DH-OPRF. This
    /// message is sent from the server (who holds the OPRF key) to the client.
    pub fn evaluate<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        blinded_element: BlindedElement<G, H>,
        metadata: &Metadata,
    ) -> Result<VerifiableServerEvaluateResult<G, H>, InternalError> {
        let batch_result = self.batch_evaluate(rng, &[blinded_element], metadata)?;
        Ok(VerifiableServerEvaluateResult {
            message: batch_result.messages[0].clone(),
            proof: batch_result.proof,
        })
    }

    /// Allows for batching of the evaluation of multiple [BlindedElement] messages from a [VerifiableClient]
    pub fn batch_evaluate<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        blinded_elements: &[BlindedElement<G, H>],
        metadata: &Metadata,
    ) -> Result<VerifiableServerBatchEvaluateResult<G, H>, InternalError> {
        let context = [
            STR_CONTEXT,
            &get_context_string::<G>(Mode::Verifiable)?,
            &serialize::<U2>(&metadata.0)?,
        ]
        .concat();
        let dst = GenericArray::from(*STR_HASH_TO_SCALAR)
            .concat(get_context_string::<G>(Mode::Verifiable)?);
        let m = G::hash_to_scalar::<H>(&context, &dst)?;
        let t = self.sk + &m;
        let evaluation_elements: Vec<EvaluationElement<G, H>> = blinded_elements
            .iter()
            .map(|x| EvaluationElement {
                value: x.value * &G::scalar_invert(&t),
                hash: PhantomData,
            })
            .collect();

        let g = G::base_point();
        let u = g * &t;

        let proof = generate_proof(
            rng,
            t,
            g,
            u,
            evaluation_elements.iter().map(EvaluationElement::copy),
            blinded_elements.iter().map(BlindedElement::copy),
        )?;

        Ok(VerifiableServerBatchEvaluateResult {
            messages: evaluation_elements,
            proof,
        })
    }

    /// Retrieves the server's public key
    pub fn get_public_key(&self) -> G {
        self.pk
    }

    #[cfg(test)]
    /// Only used for testing zeroize
    pub fn as_ptrs(&self) -> Vec<Vec<u8>> {
        vec![
            <G as Group>::scalar_as_bytes(self.sk).to_vec(),
            self.pk.to_arr().to_vec(),
        ]
    }
}

/////////////////////////
// Optional Parameters //
//==================== //
/////////////////////////

/// Allows for implementations to specify an optional sequence of
/// public bytes that must be agreed-upon by the client and server
#[derive(Default)]
pub struct Metadata(pub Vec<u8>);

impl Metadata {
    /// Specifies no metadata (the default option)
    pub fn none() -> Self {
        Self::default()
    }
}

/////////////////////////
// Convenience Structs //
//==================== //
/////////////////////////

/// Contains the fields that are returned by a non-verifiable client blind
pub struct NonVerifiableClientBlindResult<G: Group, H: BlockInput + Digest> {
    /// The state to be persisted on the client
    pub state: NonVerifiableClient<G, H>,
    /// The message to send to the server
    pub message: BlindedElement<G, H>,
}

/// Contains the fields that are returned by a non-verifiable server evaluate
pub struct NonVerifiableServerEvaluateResult<G: Group, H: BlockInput + Digest> {
    /// The message to send to the client
    pub message: EvaluationElement<G, H>,
}

/// Contains the fields that are returned by a verifiable client blind
pub struct VerifiableClientBlindResult<G: Group, H: BlockInput + Digest> {
    /// The state to be persisted on the client
    pub state: VerifiableClient<G, H>,
    /// The message to send to the server
    pub message: BlindedElement<G, H>,
}

/// Contains the fields that are returned by a verifiable server evaluate
pub struct VerifiableServerEvaluateResult<G: Group, H: BlockInput + Digest> {
    /// The message to send to the client
    pub message: EvaluationElement<G, H>,
    /// The proof for the client to verify
    pub proof: Proof<G, H>,
}

/// Contains the fields that are returned by a verifiable server batch evaluate
pub struct VerifiableServerBatchEvaluateResult<G: Group, H: BlockInput + Digest> {
    /// The messages to send to the client
    pub messages: Vec<EvaluationElement<G, H>>,
    /// The proof for the client to verify
    pub proof: Proof<G, H>,
}

///////////////////////////////////////////////
// Inner functions and Trait Implementations //
// ========================================= //
///////////////////////////////////////////////

/// Convenience struct only used in batching APIs
struct BatchItems<G: Group, H: BlockInput + Digest> {
    blind: <G as Group>::Scalar,
    evaluation_element: EvaluationElement<G, H>,
    blinded_element: BlindedElement<G, H>,
}

/// Convenience test functions for [BlindedElement], [EvaluationElement], and [Proof]

impl<G: Group, H: BlockInput + Digest> BlindedElement<G, H> {
    /// Only used to easier validate allocation
    fn copy(&self) -> Self {
        Self {
            value: self.value,
            hash: PhantomData,
        }
    }

    #[cfg(test)]
    /// Only used for testing zeroize
    pub fn as_ptrs(&self) -> Vec<Vec<u8>> {
        vec![self.value.to_arr().to_vec()]
    }
}

impl<G: Group, H: BlockInput + Digest> EvaluationElement<G, H> {
    /// Only used to easier validate allocation
    fn copy(&self) -> Self {
        Self {
            value: self.value,
            hash: PhantomData,
        }
    }

    #[cfg(test)]
    /// Only used for testing zeroize
    pub fn as_ptrs(&self) -> Vec<Vec<u8>> {
        vec![self.value.to_arr().to_vec()]
    }
}

impl<G: Group, H: BlockInput + Digest> Proof<G, H> {
    #[cfg(test)]
    /// Only used for testing zeroize
    pub fn as_ptrs(&self) -> Vec<Vec<u8>> {
        vec![
            <G as Group>::scalar_as_bytes(self.c_scalar).to_vec(),
            <G as Group>::scalar_as_bytes(self.s_scalar).to_vec(),
        ]
    }
}

// Inner function for blind. Returns the blind scalar and the blinded element
fn blind<G: Group, H: BlockInput + Digest, R: RngCore + CryptoRng>(
    input: &[u8],
    blinding_factor_rng: &mut R,
    mode: Mode,
) -> Result<(<G as Group>::Scalar, G), InternalError> {
    // Choose a random scalar that must be non-zero
    let blind = <G as Group>::random_nonzero_scalar(blinding_factor_rng);
    let dst = GenericArray::from(*STR_HASH_TO_GROUP).concat(get_context_string::<G>(mode)?);
    let hashed_point = <G as Group>::hash_to_curve::<H>(input, &dst)?;
    let blinded_element = hashed_point * &blind;
    Ok((blind, blinded_element))
}

fn verifiable_unblind<'a, G: 'a + Group, H: 'a + BlockInput + Digest, I>(
    batch_items: &'a I,
    pk: G,
    proof: Proof<G, H>,
    info: &[u8],
) -> Result<Vec<G>, InternalError>
where
    &'a I: IntoIterator<Item = BatchItems<G, H>>,
    <&'a I as IntoIterator>::IntoIter: ExactSizeIterator,
{
    let context = [
        STR_CONTEXT,
        &get_context_string::<G>(Mode::Verifiable)?,
        &serialize::<U2>(info)?,
    ]
    .concat();

    let dst =
        GenericArray::from(*STR_HASH_TO_SCALAR).concat(get_context_string::<G>(Mode::Verifiable)?);
    let m = G::hash_to_scalar::<H>(&context, &dst)?;

    let g = G::base_point();
    let t = g * &m;
    let u = t + &pk;

    let blinds = batch_items.into_iter().map(|x| x.blind);
    let evaluation_elements = batch_items.into_iter().map(|x| x.evaluation_element);
    let blinded_elements = batch_items.into_iter().map(|x| x.blinded_element);

    verify_proof(g, u, evaluation_elements, blinded_elements, proof)?;

    let unblinded_elements = blinds
        .zip(batch_items.into_iter().map(|x| x.evaluation_element))
        .map(|(blind, x)| x.value * &G::scalar_invert(&blind))
        .collect();
    Ok(unblinded_elements)
}

#[allow(clippy::many_single_char_names)]
fn generate_proof<G: Group, H: BlockInput + Digest, R: RngCore + CryptoRng>(
    rng: &mut R,
    k: <G as Group>::Scalar,
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
        GenericArray::from(*STR_CHALLENGE).concat(get_context_string::<G>(Mode::Verifiable)?);
    let h2_input = [
        serialize::<U2>(&b.to_arr())?,
        serialize::<U2>(&m.to_arr())?,
        serialize::<U2>(&z.to_arr())?,
        serialize::<U2>(&t2.to_arr())?,
        serialize::<U2>(&t3.to_arr())?,
        serialize::<U2>(&challenge_dst)?,
    ]
    .concat();

    let hash_to_scalar_dst =
        GenericArray::from(*STR_HASH_TO_SCALAR).concat(get_context_string::<G>(Mode::Verifiable)?);

    let c_scalar = G::hash_to_scalar::<H>(&h2_input, &hash_to_scalar_dst)?;
    let s_scalar = r - &(c_scalar * &k);

    Ok(Proof {
        c_scalar,
        s_scalar,
        hash: PhantomData,
    })
}

#[allow(clippy::many_single_char_names)]
fn verify_proof<G: Group, H: BlockInput + Digest>(
    a: G,
    b: G,
    cs: impl Iterator<Item = EvaluationElement<G, H>> + ExactSizeIterator,
    ds: impl Iterator<Item = BlindedElement<G, H>> + ExactSizeIterator,
    proof: Proof<G, H>,
) -> Result<(), InternalError> {
    let (m, z) = compute_composites(None, b, cs, ds)?;
    let t2 = (a * &proof.s_scalar) + &(b * &proof.c_scalar);
    let t3 = (m * &proof.s_scalar) + &(z * &proof.c_scalar);

    let challenge_dst =
        GenericArray::from(*STR_CHALLENGE).concat(get_context_string::<G>(Mode::Verifiable)?);
    let h2_input = [
        serialize::<U2>(&b.to_arr())?,
        serialize::<U2>(&m.to_arr())?,
        serialize::<U2>(&z.to_arr())?,
        serialize::<U2>(&t2.to_arr())?,
        serialize::<U2>(&t3.to_arr())?,
        serialize::<U2>(&challenge_dst)?,
    ]
    .concat();

    let hash_to_scalar_dst =
        GenericArray::from(*STR_HASH_TO_SCALAR).concat(get_context_string::<G>(Mode::Verifiable)?);
    let c = G::hash_to_scalar::<H>(&h2_input, &hash_to_scalar_dst)?;

    match G::ct_equal_scalar(&c, &proof.c_scalar) {
        true => Ok(()),
        false => Err(InternalError::ProofVerificationError),
    }
}

#[allow(clippy::type_complexity)]
fn finalize_after_unblind<G: Group, H: BlockInput + Digest>(
    inputs_and_unblinded_elements: &[(Vec<u8>, G)],
    info: &[u8],
    mode: Mode,
) -> Result<Vec<GenericArray<u8, <H as Digest>::OutputSize>>, InternalError> {
    let finalize_dst = GenericArray::from(*STR_FINALIZE).concat(get_context_string::<G>(mode)?);

    inputs_and_unblinded_elements
        .iter()
        .map(|(input, unblinded_element)| {
            Ok(<H as Digest>::digest(
                &[
                    serialize::<U2>(input)?,
                    serialize::<U2>(info)?,
                    serialize::<U2>(&unblinded_element.to_arr())?,
                    serialize::<U2>(&finalize_dst)?,
                ]
                .concat(),
            ))
        })
        .collect()
}

fn compute_composites<G: Group, H: BlockInput + Digest>(
    k_option: Option<<G as Group>::Scalar>,
    b: G,
    c_slice: impl Iterator<Item = EvaluationElement<G, H>> + ExactSizeIterator,
    d_slice: impl Iterator<Item = BlindedElement<G, H>> + ExactSizeIterator,
) -> Result<(G, G), InternalError> {
    if c_slice.len() != d_slice.len() {
        return Err(InternalError::MismatchedLengthsForCompositeInputs);
    }

    let seed_dst = GenericArray::from(*STR_SEED).concat(get_context_string::<G>(Mode::Verifiable)?);
    let composite_dst =
        GenericArray::from(*STR_COMPOSITE).concat(get_context_string::<G>(Mode::Verifiable)?);

    let h1_input = [serialize::<U2>(&b.to_arr())?, serialize::<U2>(&seed_dst)?].concat();
    let seed = <H as Digest>::digest(&h1_input);

    let mut m = G::identity();
    let mut z = G::identity();

    for (i, (c, d)) in c_slice.zip(d_slice).enumerate() {
        let h2_input = [
            serialize::<U2>(&seed)?.as_slice(),
            &i2osp::<U2>(i)?,
            &serialize::<U2>(&c.value.to_arr())?,
            &serialize::<U2>(&d.value.to_arr())?,
            &serialize::<U2>(&composite_dst)?,
        ]
        .concat();
        let dst = GenericArray::from(*STR_HASH_TO_SCALAR)
            .concat(get_context_string::<G>(Mode::Verifiable)?);
        let di = G::hash_to_scalar::<H>(&h2_input, &dst)?;
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
/// <https://www.ietf.org/archive/id/draft-irtf-cfrg-voprf-07.html>
fn get_context_string<G: Group>(mode: Mode) -> Result<GenericArray<u8, U11>, InternalError> {
    Ok(GenericArray::from(*STR_VOPRF)
        .concat(i2osp::<U1>(mode as usize)?)
        .concat(i2osp::<U2>(G::SUITE_ID)?))
}

///////////
// Tests //
// ===== //
///////////

#[cfg(test)]
mod tests {
    use super::*;
    use crate::group::Group;
    use generic_array::GenericArray;
    use rand::rngs::OsRng;
    use zeroize::Zeroize;

    fn prf<G: Group, H: BlockInput + Digest>(
        input: &[u8],
        key: <G as Group>::Scalar,
        info: &[u8],
        mode: Mode,
    ) -> GenericArray<u8, <H as Digest>::OutputSize> {
        let dst =
            GenericArray::from(*STR_HASH_TO_GROUP).concat(get_context_string::<G>(mode).unwrap());
        let point = G::hash_to_curve::<H>(input, &dst).unwrap();

        let context = [
            STR_CONTEXT,
            &get_context_string::<G>(mode).unwrap(),
            &serialize::<U2>(info).unwrap(),
        ]
        .concat();
        let dst =
            GenericArray::from(*STR_HASH_TO_SCALAR).concat(get_context_string::<G>(mode).unwrap());
        let m = <G as Group>::hash_to_scalar::<H>(&context, &dst).unwrap();

        let res = point * &<G as Group>::scalar_invert(&(key + &m));

        finalize_after_unblind::<G, H>(&[(input.to_vec(), res)], info, mode).unwrap()[0].clone()
    }

    fn base_retrieval<G: Group, H: BlockInput + Digest>() {
        let input = b"input";
        let info = b"info";
        let mut rng = OsRng;
        let client_blind_result = NonVerifiableClient::<G, H>::blind(&input[..], &mut rng).unwrap();
        let server = NonVerifiableServer::<G, H>::new(&mut rng).unwrap();
        let server_result = server
            .evaluate(client_blind_result.message, &Metadata(info.to_vec()))
            .unwrap();
        let client_finalize_result = client_blind_result
            .state
            .finalize(server_result.message, &Metadata(info.to_vec()))
            .unwrap();
        let res2 = prf::<G, H>(&input[..], server.get_private_key(), info, Mode::Base);
        assert_eq!(client_finalize_result, res2);
    }

    fn verifiable_retrieval<G: Group, H: BlockInput + Digest>() {
        let input = b"input";
        let info = b"info";
        let mut rng = OsRng;
        let client_blind_result = VerifiableClient::<G, H>::blind(&input[..], &mut rng).unwrap();
        let server = VerifiableServer::<G, H>::new(&mut rng).unwrap();
        let server_result = server
            .evaluate(
                &mut rng,
                client_blind_result.message,
                &Metadata(info.to_vec()),
            )
            .unwrap();
        let client_finalize_result = client_blind_result
            .state
            .finalize(
                server_result.message,
                server_result.proof,
                server.get_public_key(),
                &Metadata(info.to_vec()),
            )
            .unwrap();
        let res2 = prf::<G, H>(&input[..], server.get_private_key(), info, Mode::Verifiable);
        assert_eq!(client_finalize_result, res2);
    }

    fn verifiable_bad_public_key<G: Group, H: BlockInput + Digest>() {
        let input = b"input";
        let info = b"info";
        let mut rng = OsRng;
        let client_blind_result = VerifiableClient::<G, H>::blind(&input[..], &mut rng).unwrap();
        let server = VerifiableServer::<G, H>::new(&mut rng).unwrap();
        let server_result = server
            .evaluate(
                &mut rng,
                client_blind_result.message,
                &Metadata(info.to_vec()),
            )
            .unwrap();
        let wrong_pk = {
            // Choose a group element that is unlikely to be the right public key
            G::hash_to_curve::<H>(b"msg", b"dst").unwrap()
        };
        let client_finalize_result = client_blind_result.state.finalize(
            server_result.message,
            server_result.proof,
            wrong_pk,
            &Metadata(info.to_vec()),
        );
        assert!(client_finalize_result.is_err());
    }

    fn verifiable_batch_retrieval<G: Group, H: BlockInput + Digest>() {
        let info = b"info";
        let mut rng = OsRng;
        let mut inputs = vec![];
        let mut client_states = vec![];
        let mut client_messages = vec![];
        let num_iterations = 10;
        for _ in 0..num_iterations {
            let mut input = vec![0u8; 32];
            rng.fill_bytes(&mut input);
            let client_blind_result =
                VerifiableClient::<G, H>::blind(&input[..], &mut rng).unwrap();
            inputs.push(input);
            client_states.push(client_blind_result.state);
            client_messages.push(client_blind_result.message);
        }
        let server = VerifiableServer::<G, H>::new(&mut rng).unwrap();
        let server_result = server
            .batch_evaluate(&mut rng, &client_messages, &Metadata(info.to_vec()))
            .unwrap();
        let client_finalize_result = VerifiableClient::batch_finalize(
            &client_states,
            &server_result.messages,
            server_result.proof,
            server.get_public_key(),
            &Metadata(info.to_vec()),
        )
        .unwrap();
        let mut res2 = vec![];
        for input in inputs.iter().take(num_iterations) {
            let output = prf::<G, H>(&input[..], server.get_private_key(), info, Mode::Verifiable);
            res2.push(output);
        }
        assert_eq!(client_finalize_result, res2);
    }

    fn verifiable_batch_bad_public_key<G: Group, H: BlockInput + Digest>() {
        let info = b"info";
        let mut rng = OsRng;
        let mut inputs = vec![];
        let mut client_states = vec![];
        let mut client_messages = vec![];
        let num_iterations = 10;
        for _ in 0..num_iterations {
            let mut input = vec![0u8; 32];
            rng.fill_bytes(&mut input);
            let client_blind_result =
                VerifiableClient::<G, H>::blind(&input[..], &mut rng).unwrap();
            inputs.push(input);
            client_states.push(client_blind_result.state);
            client_messages.push(client_blind_result.message);
        }
        let server = VerifiableServer::<G, H>::new(&mut rng).unwrap();
        let server_result = server
            .batch_evaluate(&mut rng, &client_messages, &Metadata(info.to_vec()))
            .unwrap();
        let wrong_pk = {
            // Choose a group element that is unlikely to be the right public key
            G::hash_to_curve::<H>(b"msg", b"dst").unwrap()
        };
        let client_finalize_result = VerifiableClient::batch_finalize(
            &client_states,
            &server_result.messages,
            server_result.proof,
            wrong_pk,
            &Metadata(info.to_vec()),
        );
        assert!(client_finalize_result.is_err());
    }

    fn base_inversion_unsalted<G: Group, H: BlockInput + Digest>() {
        let mut rng = OsRng;
        let mut input = alloc::vec![0u8; 64];
        rng.fill_bytes(&mut input);
        let info = b"info";
        let client_blind_result = NonVerifiableClient::<G, H>::blind(&input, &mut rng).unwrap();
        let client_finalize_result = client_blind_result
            .state
            .finalize(
                EvaluationElement {
                    value: client_blind_result.message.value,
                    hash: PhantomData,
                },
                &Metadata(info.to_vec()),
            )
            .unwrap();

        let dst = GenericArray::from(*STR_HASH_TO_GROUP)
            .concat(get_context_string::<G>(Mode::Base).unwrap());
        let point = G::hash_to_curve::<H>(&input, &dst).unwrap();
        let res2 = finalize_after_unblind::<G, H>(&[(input.to_vec(), point)], info, Mode::Base)
            .unwrap()[0]
            .clone();

        assert_eq!(client_finalize_result, res2);
    }

    fn zeroize_base_client<G: Group, H: BlockInput + Digest>() {
        let input = b"input";
        let mut rng = OsRng;
        let client_blind_result = NonVerifiableClient::<G, H>::blind(&input[..], &mut rng).unwrap();

        let mut state = client_blind_result.state;
        Zeroize::zeroize(&mut state);
        for bytes in state.as_ptrs() {
            assert!(bytes.iter().all(|&x| x == 0));
        }

        let mut message = client_blind_result.message;
        Zeroize::zeroize(&mut message);
        for bytes in message.as_ptrs() {
            assert!(bytes.iter().all(|&x| x == 0));
        }
    }

    fn zeroize_verifiable_client<G: Group, H: BlockInput + Digest>() {
        let input = b"input";
        let mut rng = OsRng;
        let client_blind_result = VerifiableClient::<G, H>::blind(&input[..], &mut rng).unwrap();

        let mut state = client_blind_result.state;
        Zeroize::zeroize(&mut state);
        for bytes in state.as_ptrs() {
            assert!(bytes.iter().all(|&x| x == 0));
        }

        let mut message = client_blind_result.message;
        Zeroize::zeroize(&mut message);
        for bytes in message.as_ptrs() {
            assert!(bytes.iter().all(|&x| x == 0));
        }
    }

    fn zeroize_base_server<G: Group, H: BlockInput + Digest>() {
        let input = b"input";
        let info = b"info";
        let mut rng = OsRng;
        let client_blind_result = NonVerifiableClient::<G, H>::blind(&input[..], &mut rng).unwrap();
        let server = NonVerifiableServer::<G, H>::new(&mut rng).unwrap();
        let server_result = server
            .evaluate(client_blind_result.message, &Metadata(info.to_vec()))
            .unwrap();

        let mut state = server;
        Zeroize::zeroize(&mut state);
        for bytes in state.as_ptrs() {
            assert!(bytes.iter().all(|&x| x == 0));
        }

        let mut message = server_result.message;
        Zeroize::zeroize(&mut message);
        for bytes in message.as_ptrs() {
            assert!(bytes.iter().all(|&x| x == 0));
        }
    }

    fn zeroize_verifiable_server<G: Group, H: BlockInput + Digest>() {
        let input = b"input";
        let info = b"info";
        let mut rng = OsRng;
        let client_blind_result = VerifiableClient::<G, H>::blind(&input[..], &mut rng).unwrap();
        let server = VerifiableServer::<G, H>::new(&mut rng).unwrap();
        let server_result = server
            .evaluate(
                &mut rng,
                client_blind_result.message,
                &Metadata(info.to_vec()),
            )
            .unwrap();

        let mut state = server;
        Zeroize::zeroize(&mut state);
        for bytes in state.as_ptrs() {
            assert!(bytes.iter().all(|&x| x == 0));
        }

        let mut message = server_result.message;
        Zeroize::zeroize(&mut message);
        for bytes in message.as_ptrs() {
            assert!(bytes.iter().all(|&x| x == 0));
        }

        let mut proof = server_result.proof;
        Zeroize::zeroize(&mut proof);
        for bytes in proof.as_ptrs() {
            assert!(bytes.iter().all(|&x| x == 0));
        }
    }

    #[test]
    fn test_functionality() -> Result<(), InternalError> {
        use curve25519_dalek::ristretto::RistrettoPoint;
        use sha2::Sha512;

        base_retrieval::<RistrettoPoint, Sha512>();
        base_inversion_unsalted::<RistrettoPoint, Sha512>();
        verifiable_retrieval::<RistrettoPoint, Sha512>();
        verifiable_batch_retrieval::<RistrettoPoint, Sha512>();
        verifiable_bad_public_key::<RistrettoPoint, Sha512>();
        verifiable_batch_bad_public_key::<RistrettoPoint, Sha512>();

        zeroize_base_client::<RistrettoPoint, Sha512>();
        zeroize_base_server::<RistrettoPoint, Sha512>();
        zeroize_verifiable_client::<RistrettoPoint, Sha512>();
        zeroize_verifiable_server::<RistrettoPoint, Sha512>();

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

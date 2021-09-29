// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Contains the main VOPRF API

use crate::{
    ciphersuite::CipherSuite,
    errors::InternalError,
    group::Group,
    serialization::{i2osp, serialize},
};
use alloc::vec;
use alloc::vec::Vec;
use digest::Digest;
use generic_array::{typenum::Unsigned, GenericArray};
use rand::{CryptoRng, RngCore};

///////////////
// Constants //
// ========= //
///////////////

static STR_HASH_TO_SCALAR: &[u8] = b"HashToScalar-";
static STR_HASH_TO_GROUP: &[u8] = b"HashToGroup-";
static STR_FINALIZE: &[u8] = b"Finalize-";
static STR_SEED: &[u8] = b"Seed-";
static STR_CONTEXT: &[u8] = b"Context-";
static STR_COMPOSITE: &[u8] = b"Composite-";
static STR_CHALLENGE: &[u8] = b"Challenge-";
static STR_VOPRF: &[u8] = b"VOPRF07-";

/// Determines the mode of operation (either base mode or
/// verifiable mode)
enum Mode {
    Base = 0,
    Verifiable = 1,
}

////////////////////////////
// High-level API Structs //
// ====================== //
////////////////////////////

/// A client which engages with a [NonVerifiableServer]
/// in base mode, meaning that the OPRF outputs are not
/// verifiable.
pub struct NonVerifiableClient<CS: CipherSuite> {
    pub(crate) blind: <CS::Group as Group>::Scalar,
    pub(crate) data: Vec<u8>,
}
impl_traits_for!(
    struct NonVerifiableClient<CS: CipherSuite>,
    [blind, data],
    [<CS::Group as Group>::Scalar],
);

/// A client which engages with a [VerifiableServer]
/// in verifiable mode, meaning that the OPRF outputs
/// can be checked against a server public key.
pub struct VerifiableClient<CS: CipherSuite> {
    pub(crate) blind: <CS::Group as Group>::Scalar,
    pub(crate) blinded_element: CS::Group,
    pub(crate) data: alloc::vec::Vec<u8>,
}
impl_traits_for!(
    struct VerifiableClient<CS: CipherSuite>,
    [blind, blinded_element, data],
    [<CS::Group as Group>::Scalar, CS::Group],
);

/// A server which engages with a [NonVerifiableClient]
/// in base mode, meaning that the OPRF outputs are not
/// verifiable.
pub struct NonVerifiableServer<CS: CipherSuite> {
    pub(crate) sk: <CS::Group as Group>::Scalar,
}
impl_traits_for!(
    struct NonVerifiableServer<CS: CipherSuite>,
    [sk],
    [<CS::Group as Group>::Scalar],
);

/// A server which engages with a [VerifiableClient]
/// in verifiable mode, meaning that the OPRF outputs
/// can be checked against a server public key.
pub struct VerifiableServer<CS: CipherSuite> {
    pub(crate) sk: <CS::Group as Group>::Scalar,
    pub(crate) pk: CS::Group,
}
impl_traits_for!(
    struct VerifiableServer<CS: CipherSuite>,
    [sk, pk],
    [<CS::Group as Group>::Scalar, CS::Group],
);

/// A proof produced by a [VerifiableServer] that
/// the OPRF output matches against a server public key.
pub struct Proof<CS: CipherSuite> {
    pub(crate) c_scalar: <CS::Group as Group>::Scalar,
    pub(crate) s_scalar: <CS::Group as Group>::Scalar,
}
impl_traits_for!(
    struct Proof<CS: CipherSuite>,
    [c_scalar, s_scalar],
    [<CS::Group as Group>::Scalar],
);

/// The first client message sent from a client (either verifiable or not)
/// to a server (either verifiable or not).
pub struct BlindedElement<CS: CipherSuite> {
    pub(crate) value: CS::Group,
}
impl_traits_for!(
    struct BlindedElement<CS: CipherSuite>,
    [value],
    [CS::Group],
);

/// The server's response to the [BlindedElement] message from
/// a client (either verifiable or not)
/// to a server (either verifiable or not).
pub struct EvaluationElement<CS: CipherSuite> {
    pub(crate) value: CS::Group,
}
impl_traits_for!(
    struct EvaluationElement<CS: CipherSuite>,
    [value],
    [CS::Group],
);

/////////////////////////
// API Implementations //
// =================== //
/////////////////////////

impl<CS: CipherSuite> NonVerifiableClient<CS> {
    /// Computes the first step for the multiplicative blinding version of DH-OPRF.
    pub fn blind<R: RngCore + CryptoRng>(
        input: &[u8],
        blinding_factor_rng: &mut R,
    ) -> Result<NonVerifiableClientBlindResult<CS>, InternalError> {
        let (blind, blinded_element) = blind::<CS, _>(input, blinding_factor_rng, Mode::Base)?;
        Ok(NonVerifiableClientBlindResult {
            state: Self {
                data: input.to_vec(),
                blind,
            },
            message: BlindedElement {
                value: blinded_element,
            },
        })
    }

    /// Computes the third step for the multiplicative blinding version of DH-OPRF, in which
    /// the client unblinds the server's message.
    pub fn finalize(
        &self,
        evaluation_element: EvaluationElement<CS>,
        metadata: &Metadata,
    ) -> Result<NonVerifiableClientFinalizeResult<CS>, InternalError> {
        let unblinded_element =
            evaluation_element.value * &<CS::Group as Group>::scalar_invert(&self.blind);
        let outputs = finalize_after_unblind::<CS>(
            &[(self.data.clone(), unblinded_element)],
            &metadata.0,
            Mode::Base,
        )?;
        Ok(NonVerifiableClientFinalizeResult {
            output: outputs[0].clone(),
        })
    }

    #[cfg(test)]
    /// Only used for test functions
    pub fn from_data_and_blind(data: &[u8], blind: &<CS::Group as Group>::Scalar) -> Self {
        Self {
            data: data.to_vec(),
            blind: blind.clone(),
        }
    }

    #[cfg(test)]
    /// Only used for test functions
    pub fn get_blind(&self) -> <CS::Group as Group>::Scalar {
        self.blind
    }
}

impl<CS: CipherSuite> VerifiableClient<CS> {
    /// Computes the first step for the multiplicative blinding version of DH-OPRF.
    pub fn blind<R: RngCore + CryptoRng>(
        input: &[u8],
        blinding_factor_rng: &mut R,
    ) -> Result<VerifiableClientBlindResult<CS>, InternalError> {
        let (blind, blinded_element) =
            blind::<CS, _>(input, blinding_factor_rng, Mode::Verifiable)?;
        Ok(VerifiableClientBlindResult {
            state: Self {
                data: input.to_vec(),
                blind,
                blinded_element,
            },
            message: BlindedElement {
                value: blinded_element,
            },
        })
    }

    /// Computes the third step for the multiplicative blinding version of DH-OPRF, in which
    /// the client unblinds the server's message.
    pub fn finalize(
        &self,
        evaluation_element: EvaluationElement<CS>,
        proof: Proof<CS>,
        pk: CS::Group,
        metadata: &Metadata,
    ) -> Result<VerifiableClientFinalizeResult<CS>, InternalError> {
        let batch_finalize_input =
            BatchFinalizeInput::new(vec![self.clone()], vec![evaluation_element]);
        let batch_result = Self::batch_finalize(batch_finalize_input, proof, pk, metadata)?;
        Ok(VerifiableClientFinalizeResult {
            output: batch_result.outputs[0].clone(),
        })
    }

    /// Allows for batching of the finalization of multiple [VerifiableClient] and [EvaluationElement] pairs
    #[allow(clippy::type_complexity)]
    pub fn batch_finalize(
        batch_finalize_input: BatchFinalizeInput<CS>,
        proof: Proof<CS>,
        pk: CS::Group,
        metadata: &Metadata,
    ) -> Result<VerifiableClientBatchFinalizeResult<CS>, InternalError> {
        let batch_items: Vec<BatchItems<CS>> = batch_finalize_input
            .clients
            .iter()
            .zip(batch_finalize_input.messages.iter())
            .map(|(client, evaluation_element)| BatchItems {
                blind: client.blind,
                evaluation_element: evaluation_element.clone(),
                blinded_element: BlindedElement {
                    value: client.blinded_element,
                },
            })
            .collect();

        let unblinded_elements = verifiable_unblind(&batch_items, pk, proof, &metadata.0)?;

        let inputs_and_unblinded_elements: Vec<(Vec<u8>, CS::Group)> = batch_finalize_input
            .clients
            .iter()
            .zip(unblinded_elements.iter())
            .map(|(client, &unblinded_element)| (client.data.clone(), unblinded_element))
            .collect();

        Ok(VerifiableClientBatchFinalizeResult {
            outputs: finalize_after_unblind::<CS>(
                &inputs_and_unblinded_elements,
                &metadata.0,
                Mode::Verifiable,
            )?,
        })
    }

    #[cfg(test)]
    /// Only used for test functions
    pub fn from_data_and_blind(
        data: &[u8],
        blind: &<CS::Group as Group>::Scalar,
        blinded_element: &CS::Group,
    ) -> Self {
        Self {
            data: data.to_vec(),
            blind: blind.clone(),
            blinded_element: blinded_element.clone(),
        }
    }

    #[cfg(test)]
    /// Only used for test functions
    pub fn get_blind(&self) -> <CS::Group as Group>::Scalar {
        self.blind
    }
}

impl<CS: CipherSuite> NonVerifiableServer<CS> {
    /// Produces a new instance of a [NonVerifiableServer] using a supplied RNG
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Result<Self, InternalError> {
        let mut seed = vec![0u8; <CS::Hash as Digest>::OutputSize::USIZE];
        rng.fill_bytes(&mut seed);
        Self::new_from_seed(&seed)
    }

    /// Produces a new instance of a [NonVerifiableServer] using a supplied set of bytes to
    /// represent the server's private key
    pub fn new_with_key(private_key_bytes: &[u8]) -> Result<Self, InternalError> {
        let sk = CS::Group::from_scalar_slice(&GenericArray::clone_from_slice(private_key_bytes))?;
        Ok(Self { sk })
    }

    /// Produces a new instance of a [NonVerifiableServer] using a supplied set of bytes which
    /// are used as a seed to derive the server's private key.
    ///
    /// Corresponds to DeriveKeyPair() function from the VOPRF specification.
    pub fn new_from_seed(seed: &[u8]) -> Result<Self, InternalError> {
        let dst = [STR_HASH_TO_SCALAR, &get_context_string::<CS>(Mode::Base)?].concat();
        let sk = CS::Group::hash_to_scalar::<CS::Hash>(seed, &dst)?;
        Ok(Self { sk })
    }

    // Only used for tests
    #[cfg(test)]
    pub fn get_private_key(&self) -> <CS::Group as Group>::Scalar {
        self.sk
    }

    /// Computes the second step for the multiplicative blinding version of DH-OPRF. This
    /// message is sent from the server (who holds the OPRF key) to the client.
    pub fn evaluate(
        &self,
        blinded_element: BlindedElement<CS>,
        metadata: &Metadata,
    ) -> Result<NonVerifiableServerEvaluateResult<CS>, InternalError> {
        let context = [
            STR_CONTEXT,
            &get_context_string::<CS>(Mode::Base)?,
            &serialize(&metadata.0, 2)?,
        ]
        .concat();
        let dst = [STR_HASH_TO_SCALAR, &get_context_string::<CS>(Mode::Base)?].concat();
        let m = CS::Group::hash_to_scalar::<CS::Hash>(&context, &dst)?;
        let t = self.sk + &m;
        let evaluation_element = blinded_element.value * &CS::Group::scalar_invert(&t);
        Ok(NonVerifiableServerEvaluateResult {
            message: EvaluationElement {
                value: evaluation_element,
            },
        })
    }
}

impl<CS: CipherSuite> VerifiableServer<CS> {
    /// Produces a new instance of a [VerifiableServer] using a supplied RNG
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Result<Self, InternalError> {
        let mut seed = vec![0u8; <CS::Hash as Digest>::OutputSize::USIZE];
        rng.fill_bytes(&mut seed);
        Self::new_from_seed(&seed)
    }

    /// Produces a new instance of a [VerifiableServer] using a supplied set of bytes to
    /// represent the server's private key
    pub fn new_with_key(key: &[u8]) -> Result<Self, InternalError> {
        let sk = CS::Group::from_scalar_slice(&GenericArray::clone_from_slice(key))?;
        let pk = CS::Group::base_point() * &sk;
        Ok(Self { sk, pk })
    }

    /// Produces a new instance of a [VerifiableServer] using a supplied set of bytes which
    /// are used as a seed to derive the server's private key.
    ///
    /// Corresponds to DeriveKeyPair() function from the VOPRF specification.
    pub fn new_from_seed(seed: &[u8]) -> Result<Self, InternalError> {
        let dst = [
            STR_HASH_TO_SCALAR,
            &get_context_string::<CS>(Mode::Verifiable)?,
        ]
        .concat();
        let sk = CS::Group::hash_to_scalar::<CS::Hash>(seed, &dst)?;
        let pk = CS::Group::base_point() * &sk;
        Ok(Self { sk, pk })
    }

    // Only used for tests
    #[cfg(test)]
    pub fn get_private_key(&self) -> <CS::Group as Group>::Scalar {
        self.sk
    }

    /// Computes the second step for the multiplicative blinding version of DH-OPRF. This
    /// message is sent from the server (who holds the OPRF key) to the client.
    pub fn evaluate<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        blinded_element: BlindedElement<CS>,
        metadata: &Metadata,
    ) -> Result<VerifiableServerEvaluateResult<CS>, InternalError> {
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
        blinded_elements: &[BlindedElement<CS>],
        metadata: &Metadata,
    ) -> Result<VerifiableServerBatchEvaluateResult<CS>, InternalError> {
        let context = [
            STR_CONTEXT,
            &get_context_string::<CS>(Mode::Verifiable)?,
            &serialize(&metadata.0, 2)?,
        ]
        .concat();
        let dst = [
            STR_HASH_TO_SCALAR,
            &get_context_string::<CS>(Mode::Verifiable)?,
        ]
        .concat();
        let m = CS::Group::hash_to_scalar::<CS::Hash>(&context, &dst)?;
        let t = self.sk + &m;
        let evaluation_elements: Vec<EvaluationElement<CS>> = blinded_elements
            .iter()
            .map(|x| EvaluationElement {
                value: x.value * &CS::Group::scalar_invert(&t),
            })
            .collect();

        let g = CS::Group::base_point();
        let u = g * &t;

        let proof = generate_proof(rng, t, g, u, &evaluation_elements, blinded_elements)?;

        Ok(VerifiableServerBatchEvaluateResult {
            messages: evaluation_elements,
            proof,
        })
    }

    /// Retrieves the server's public key
    pub fn get_public_key(&self) -> CS::Group {
        self.pk
    }
}

/////////////////////////
// Optional Parameters //
//==================== //
/////////////////////////

/// Allows for implementations to specify an optional sequence of
/// public bytes that must be agreed-upon by the client and server
pub struct Metadata(pub Vec<u8>);

impl Default for Metadata {
    fn default() -> Self {
        Self(vec![])
    }
}

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
pub struct NonVerifiableClientBlindResult<CS: CipherSuite> {
    /// The state to be persisted on the client
    pub state: NonVerifiableClient<CS>,
    /// The message to send to the server
    pub message: BlindedElement<CS>,
}

/// Contains the fields that are returned by a non-verifiable server evaluate
pub struct NonVerifiableServerEvaluateResult<CS: CipherSuite> {
    /// The message to send to the client
    pub message: EvaluationElement<CS>,
}

/// Contains the fields that are returned by a non-verifiable client finalize
pub struct NonVerifiableClientFinalizeResult<CS: CipherSuite> {
    /// The output of the protocol
    pub output: GenericArray<u8, <CS::Hash as Digest>::OutputSize>,
}

/// Contains the fields that are returned by a verifiable client blind
pub struct VerifiableClientBlindResult<CS: CipherSuite> {
    /// The state to be persisted on the client
    pub state: VerifiableClient<CS>,
    /// The message to send to the server
    pub message: BlindedElement<CS>,
}

/// Contains the fields that are returned by a verifiable server evaluate
pub struct VerifiableServerEvaluateResult<CS: CipherSuite> {
    /// The message to send to the client
    pub message: EvaluationElement<CS>,
    /// The proof for the client to verify
    pub proof: Proof<CS>,
}

/// Contains the fields that are returned by a verifiable server batch evaluate
pub struct VerifiableServerBatchEvaluateResult<CS: CipherSuite> {
    /// The messages to send to the client
    pub messages: Vec<EvaluationElement<CS>>,
    /// The proof for the client to verify
    pub proof: Proof<CS>,
}

/// Contains the fields that are returned by a verifiable client finalize
pub struct VerifiableClientFinalizeResult<CS: CipherSuite> {
    /// The output of the protocol
    pub output: GenericArray<u8, <CS::Hash as Digest>::OutputSize>,
}

/// Contains the fields that are returned by a verifiable client batch finalize
pub struct VerifiableClientBatchFinalizeResult<CS: CipherSuite> {
    /// The output of the protocol
    pub outputs: Vec<GenericArray<u8, <CS::Hash as Digest>::OutputSize>>,
}

/// An input to the verifiable client batch finalize function, constructed
/// by aggregating clients and server messages
pub struct BatchFinalizeInput<CS: CipherSuite> {
    clients: Vec<VerifiableClient<CS>>,
    messages: Vec<EvaluationElement<CS>>,
}

impl<CS: CipherSuite> BatchFinalizeInput<CS> {
    /// Create a new instance from a vector of clients and a vector of messages
    pub fn new(clients: Vec<VerifiableClient<CS>>, messages: Vec<EvaluationElement<CS>>) -> Self {
        Self { clients, messages }
    }
}

///////////////////////////////////////////////
// Inner functions and Trait Implementations //
// ========================================= //
///////////////////////////////////////////////

/// Convenience struct only used in batching APIs
struct BatchItems<CS: CipherSuite> {
    blind: <CS::Group as Group>::Scalar,
    evaluation_element: EvaluationElement<CS>,
    blinded_element: BlindedElement<CS>,
}

// Inner function for blind. Returns the blind scalar and the blinded element
fn blind<CS: CipherSuite, R: RngCore + CryptoRng>(
    input: &[u8],
    blinding_factor_rng: &mut R,
    mode: Mode,
) -> Result<(<CS::Group as Group>::Scalar, CS::Group), InternalError> {
    // Choose a random scalar that must be non-zero
    let blind = <CS::Group as Group>::random_nonzero_scalar(blinding_factor_rng);
    let dst = [STR_HASH_TO_GROUP, &get_context_string::<CS>(mode)?].concat();
    let hashed_point = <CS::Group as Group>::hash_to_curve::<CS::Hash>(input, &dst)?;
    let blinded_element = hashed_point * &blind;
    Ok((blind, blinded_element))
}

fn verifiable_unblind<CS: CipherSuite>(
    batch_items: &[BatchItems<CS>],
    pk: CS::Group,
    proof: Proof<CS>,
    info: &[u8],
) -> Result<Vec<CS::Group>, InternalError> {
    let context = [
        STR_CONTEXT,
        &get_context_string::<CS>(Mode::Verifiable)?,
        &serialize(info, 2)?,
    ]
    .concat();

    let dst = [
        STR_HASH_TO_SCALAR,
        &get_context_string::<CS>(Mode::Verifiable)?,
    ]
    .concat();
    let m = CS::Group::hash_to_scalar::<CS::Hash>(&context, &dst)?;

    let g = CS::Group::base_point();
    let t = g * &m;
    let u = t + &pk;

    let blinds: Vec<<CS::Group as Group>::Scalar> = batch_items.iter().map(|x| x.blind).collect();
    let evaluation_elements: Vec<EvaluationElement<CS>> = batch_items
        .iter()
        .map(|x| x.evaluation_element.clone())
        .collect();
    let blinded_elements: Vec<BlindedElement<CS>> = batch_items
        .iter()
        .map(|x| x.blinded_element.clone())
        .collect();

    verify_proof(g, u, &evaluation_elements, &blinded_elements, proof)?;

    let unblinded_elements = blinds
        .iter()
        .zip(evaluation_elements.iter())
        .map(|(&blind, x)| x.value * &CS::Group::scalar_invert(&blind))
        .collect();
    Ok(unblinded_elements)
}

#[allow(clippy::many_single_char_names)]
fn generate_proof<CS: CipherSuite, R: RngCore + CryptoRng>(
    rng: &mut R,
    k: <CS::Group as Group>::Scalar,
    a: CS::Group,
    b: CS::Group,
    cs: &[EvaluationElement<CS>],
    ds: &[BlindedElement<CS>],
) -> Result<Proof<CS>, InternalError> {
    let (m, z) = compute_composites::<CS>(Some(k), b, cs, ds)?;

    let r = CS::Group::random_nonzero_scalar(rng);
    let t2 = a * &r;
    let t3 = m * &r;

    let challenge_dst = [STR_CHALLENGE, &get_context_string::<CS>(Mode::Verifiable)?].concat();
    let h2_input = [
        serialize(&b.to_arr().to_vec(), 2)?,
        serialize(&m.to_arr().to_vec(), 2)?,
        serialize(&z.to_arr().to_vec(), 2)?,
        serialize(&t2.to_arr().to_vec(), 2)?,
        serialize(&t3.to_arr().to_vec(), 2)?,
        serialize(&challenge_dst, 2)?,
    ]
    .concat();

    let hash_to_scalar_dst = [
        STR_HASH_TO_SCALAR,
        &get_context_string::<CS>(Mode::Verifiable)?,
    ]
    .concat();

    let c_scalar = CS::Group::hash_to_scalar::<CS::Hash>(&h2_input, &hash_to_scalar_dst)?;
    let s_scalar = r - &(c_scalar * &k);

    Ok(Proof { c_scalar, s_scalar })
}

#[allow(clippy::many_single_char_names)]
fn verify_proof<CS: CipherSuite>(
    a: CS::Group,
    b: CS::Group,
    cs: &[EvaluationElement<CS>],
    ds: &[BlindedElement<CS>],
    proof: Proof<CS>,
) -> Result<(), InternalError> {
    let (m, z) = compute_composites::<CS>(None, b, cs, ds)?;
    let t2 = (a * &proof.s_scalar) + &(b * &proof.c_scalar);
    let t3 = (m * &proof.s_scalar) + &(z * &proof.c_scalar);

    let challenge_dst = [STR_CHALLENGE, &get_context_string::<CS>(Mode::Verifiable)?].concat();
    let h2_input = [
        serialize(&b.to_arr().to_vec(), 2)?,
        serialize(&m.to_arr().to_vec(), 2)?,
        serialize(&z.to_arr().to_vec(), 2)?,
        serialize(&t2.to_arr().to_vec(), 2)?,
        serialize(&t3.to_arr().to_vec(), 2)?,
        serialize(&challenge_dst, 2)?,
    ]
    .concat();

    let hash_to_scalar_dst = [
        STR_HASH_TO_SCALAR,
        &get_context_string::<CS>(Mode::Verifiable)?,
    ]
    .concat();
    let c = CS::Group::hash_to_scalar::<CS::Hash>(&h2_input, &hash_to_scalar_dst)?;

    match CS::Group::ct_equal_scalar(&c, &proof.c_scalar) {
        true => Ok(()),
        false => Err(InternalError::ProofVerificationError),
    }
}

#[allow(clippy::type_complexity)]
fn finalize_after_unblind<CS: CipherSuite>(
    inputs_and_unblinded_elements: &[(Vec<u8>, CS::Group)],
    info: &[u8],
    mode: Mode,
) -> Result<Vec<GenericArray<u8, <CS::Hash as Digest>::OutputSize>>, InternalError> {
    let finalize_dst = [STR_FINALIZE, &get_context_string::<CS>(mode)?].concat();

    let mut outputs = vec![];

    for (input, unblinded_element) in inputs_and_unblinded_elements {
        outputs.push(<CS::Hash as Digest>::digest(
            &[
                serialize(input, 2)?,
                serialize(info, 2)?,
                serialize(&unblinded_element.to_arr().to_vec(), 2)?,
                serialize(&finalize_dst, 2)?,
            ]
            .concat(),
        ));
    }

    Ok(outputs)
}

fn compute_composites<CS: CipherSuite>(
    k_option: Option<<CS::Group as Group>::Scalar>,
    b: CS::Group,
    c_slice: &[EvaluationElement<CS>],
    d_slice: &[BlindedElement<CS>],
) -> Result<(CS::Group, CS::Group), InternalError> {
    if c_slice.len() != d_slice.len() {
        return Err(InternalError::MismatchedLengthsForCompositeInputs);
    }

    let seed_dst = [STR_SEED, &get_context_string::<CS>(Mode::Verifiable)?].concat();
    let composite_dst = [STR_COMPOSITE, &get_context_string::<CS>(Mode::Verifiable)?].concat();

    let h1_input = [
        serialize(&b.to_arr().to_vec(), 2)?,
        serialize(&seed_dst, 2)?,
    ]
    .concat();
    let seed = <CS::Hash as Digest>::digest(&h1_input);

    let mut m = CS::Group::identity();
    let mut z = CS::Group::identity();

    for i in 0..c_slice.len() {
        let h2_input = [
            serialize(&seed, 2)?,
            i2osp(i, 2)?,
            serialize(&c_slice[i].value.to_arr().to_vec(), 2)?,
            serialize(&d_slice[i].value.to_arr().to_vec(), 2)?,
            serialize(&composite_dst, 2)?,
        ]
        .concat();
        let dst = [
            STR_HASH_TO_SCALAR,
            &get_context_string::<CS>(Mode::Verifiable)?,
        ]
        .concat();
        let di = CS::Group::hash_to_scalar::<CS::Hash>(&h2_input, &dst)?;
        m = c_slice[i].value * &di + &m;
        z = match k_option {
            Some(_) => z,
            None => d_slice[i].value * &di + &z,
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
fn get_context_string<CS: CipherSuite>(mode: Mode) -> Result<alloc::vec::Vec<u8>, InternalError> {
    Ok([
        STR_VOPRF,
        &i2osp(mode as usize, 1)?,
        &i2osp(CS::Group::SUITE_ID, 2)?,
    ]
    .concat())
}

///////////
// Tests //
// ===== //
///////////

#[cfg(test)]
mod tests {
    use super::*;
    use crate::group::Group;
    use generic_array::{arr, GenericArray};
    use rand::rngs::OsRng;

    fn prf<CS: CipherSuite>(
        input: &[u8],
        oprf_key: &[u8],
        info: &[u8],
    ) -> GenericArray<u8, <CS::Hash as Digest>::OutputSize> {
        let dst = [
            STR_HASH_TO_GROUP,
            &get_context_string::<CS>(Mode::Base).unwrap(),
        ]
        .concat();
        let point = CS::Group::hash_to_curve::<CS::Hash>(input, &dst).unwrap();
        let scalar = CS::Group::from_scalar_slice(GenericArray::from_slice(&oprf_key[..])).unwrap();

        let context = [
            STR_CONTEXT,
            &get_context_string::<CS>(Mode::Base).unwrap(),
            &serialize(info, 2).unwrap(),
        ]
        .concat();
        let dst = [
            STR_HASH_TO_SCALAR,
            &get_context_string::<CS>(Mode::Base).unwrap(),
        ]
        .concat();
        let m = <CS::Group as Group>::hash_to_scalar::<CS::Hash>(&context, &dst).unwrap();

        let res = point * &<CS::Group as Group>::scalar_invert(&(scalar + &m));

        finalize_after_unblind::<CS>(&[(input.to_vec(), res)], info, Mode::Base).unwrap()[0].clone()
    }

    fn oprf_retrieval<CS: CipherSuite>() {
        let input = b"hunter2";
        let info = b"info";
        let mut rng = OsRng;
        let client_blind_result = NonVerifiableClient::<CS>::blind(&input[..], &mut rng).unwrap();
        let oprf_key_bytes = arr![
            u8; 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31, 32,
        ];
        let server = NonVerifiableServer::<CS>::new_with_key(&oprf_key_bytes).unwrap();
        let server_result = server
            .evaluate(client_blind_result.message, &Metadata(info.to_vec()))
            .unwrap();
        let client_finalize_result = client_blind_result
            .state
            .finalize(server_result.message, &Metadata(info.to_vec()))
            .unwrap();
        let res2 = prf::<CS>(&input[..], &oprf_key_bytes, info);
        assert_eq!(client_finalize_result.output, res2);
    }

    fn oprf_inversion_unsalted<CS: CipherSuite>() {
        let mut rng = OsRng;
        let mut input = alloc::vec![0u8; 64];
        rng.fill_bytes(&mut input);
        let info = b"info";
        let client_blind_result = NonVerifiableClient::<CS>::blind(&input, &mut rng).unwrap();
        let client_finalize_result = client_blind_result
            .state
            .finalize(
                EvaluationElement {
                    value: client_blind_result.message.value,
                },
                &Metadata(info.to_vec()),
            )
            .unwrap();

        let dst = [
            STR_HASH_TO_GROUP,
            &get_context_string::<CS>(Mode::Base).unwrap(),
        ]
        .concat();
        let point = CS::Group::hash_to_curve::<CS::Hash>(&input, &dst).unwrap();
        let res2 = finalize_after_unblind::<CS>(&[(input.to_vec(), point)], info, Mode::Base)
            .unwrap()[0]
            .clone();

        assert_eq!(client_finalize_result.output, res2);
    }

    #[test]
    fn test_functionality() -> Result<(), InternalError> {
        use crate::tests::Ristretto255Sha512;

        oprf_retrieval::<Ristretto255Sha512>();
        oprf_inversion_unsalted::<Ristretto255Sha512>();

        #[cfg(feature = "p256")]
        {
            use crate::tests::P256Sha256;

            oprf_retrieval::<P256Sha256>();
            oprf_inversion_unsalted::<P256Sha256>();
        }

        Ok(())
    }
}

// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::{
    ciphersuite::{CipherSuite, Mode},
    errors::InternalError,
    group::Group,
    serialization::{i2osp, serialize},
};
use digest::Digest;
use generic_array::GenericArray;
use rand::{CryptoRng, RngCore};

use alloc::vec;
use generic_array::typenum::Unsigned;

static STR_HASH_TO_SCALAR: &[u8] = b"HashToScalar-";
static STR_HASH_TO_GROUP: &[u8] = b"HashToGroup-";
static STR_FINALIZE: &[u8] = b"Finalize-";
static STR_SEED: &[u8] = b"Seed-";
static STR_CONTEXT: &[u8] = b"Context-";
static STR_COMPOSITE: &[u8] = b"Composite-";
static STR_CHALLENGE: &[u8] = b"Challenge-";

pub struct NonVerifiableClient<CS: CipherSuite> {
    data: alloc::vec::Vec<u8>,
    blind: <CS::Group as Group>::Scalar,
}

impl<CS: CipherSuite> NonVerifiableClient<CS> {
    /// Computes the first step for the multiplicative blinding version of DH-OPRF.
    pub fn blind<R: RngCore + CryptoRng>(
        input: &[u8],
        blinding_factor_rng: &mut R,
    ) -> Result<(Self, CS::Group), InternalError> {
        let (blind, blinded_element) = blind::<CS, _>(input, blinding_factor_rng)?;
        Ok((
            Self {
                data: input.to_vec(),
                blind,
            },
            blinded_element,
        ))
    }

    /// Computes the third step for the multiplicative blinding version of DH-OPRF, in which
    /// the client unblinds the server's message.
    pub fn finalize(
        &self,
        evaluated_element: CS::Group,
        info: &[u8],
    ) -> Result<GenericArray<u8, <CS::Hash as Digest>::OutputSize>, InternalError> {
        let unblinded_element =
            evaluated_element * &<CS::Group as Group>::scalar_invert(&self.blind);
        finalize_after_unblind::<CS>(&self.data, unblinded_element, info, Mode::Base)
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

pub struct VerifiableClient<CS: CipherSuite> {
    data: alloc::vec::Vec<u8>,
    blind: <CS::Group as Group>::Scalar,
    blinded_element: CS::Group,
}

impl<CS: CipherSuite> VerifiableClient<CS> {
    /// Computes the first step for the multiplicative blinding version of DH-OPRF.
    pub fn blind<R: RngCore + CryptoRng>(
        input: &[u8],
        blinding_factor_rng: &mut R,
    ) -> Result<(Self, CS::Group), InternalError> {
        let (blind, blinded_element) = blind::<CS, _>(input, blinding_factor_rng)?;
        Ok((
            Self {
                data: input.to_vec(),
                blind,
                blinded_element,
            },
            blinded_element,
        ))
    }

    /// Computes the third step for the multiplicative blinding version of DH-OPRF, in which
    /// the client unblinds the server's message.
    pub fn finalize(
        &self,
        evaluated_element: CS::Group,
        proof: Proof<CS>,
        pk: CS::Group,
        info: &[u8],
    ) -> Result<GenericArray<u8, <CS::Hash as Digest>::OutputSize>, InternalError> {
        let unblinded_element = verifiable_unblind(
            self.blind,
            evaluated_element,
            self.blinded_element,
            pk,
            proof,
            info,
        )?;
        finalize_after_unblind::<CS>(&self.data, unblinded_element, info, Mode::Verifiable)
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

fn verifiable_unblind<CS: CipherSuite>(
    blind: <CS::Group as Group>::Scalar,
    evaluated_element: CS::Group,
    blinded_element: CS::Group,
    pk: CS::Group,
    proof: Proof<CS>,
    info: &[u8],
) -> Result<CS::Group, InternalError> {
    let context = [
        STR_CONTEXT,
        &CS::get_context_string(Mode::Verifiable)?,
        &serialize(info, 2)?,
    ]
    .concat();

    let dst = [
        STR_HASH_TO_SCALAR,
        &CS::get_context_string(Mode::Verifiable)?,
    ]
    .concat();
    let m = CS::Group::hash_to_scalar::<CS::Hash>(&context, &dst)?;

    let g = CS::Group::base_point();
    let t = g * &m;
    let u = t + &pk;

    verify_proof(g, u, evaluated_element, blinded_element, proof)?;

    let unblinded_element = evaluated_element * &CS::Group::scalar_invert(&blind);
    Ok(unblinded_element)
}

pub struct NonVerifiableServer<CS: CipherSuite> {
    sk: <CS::Group as Group>::Scalar,
}

impl<CS: CipherSuite> NonVerifiableServer<CS> {
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Result<Self, InternalError> {
        let mut seed = vec![0u8; <CS::Hash as Digest>::OutputSize::USIZE];
        rng.fill_bytes(&mut seed);
        Self::new_from_seed(&seed)
    }

    pub fn new_with_key(key: &[u8]) -> Result<Self, InternalError> {
        let sk = CS::Group::from_scalar_slice(&GenericArray::clone_from_slice(key))?;
        Ok(Self { sk })
    }

    // Corresponds to DeriveKeyPair from the VOPRF spec
    pub fn new_from_seed(seed: &[u8]) -> Result<Self, InternalError> {
        let dst = [STR_HASH_TO_SCALAR, &CS::get_context_string(Mode::Base)?].concat();
        let sk = CS::Group::hash_to_scalar::<CS::Hash>(seed, &dst)?;
        Ok(Self { sk })
    }

    /// Computes the second step for the multiplicative blinding version of DH-OPRF. This
    /// message is sent from the server (who holds the OPRF key) to the client.
    pub fn evaluate(
        &self,
        blinded_element: CS::Group,
        info: &[u8],
    ) -> Result<CS::Group, InternalError> {
        let context = [
            STR_CONTEXT,
            &CS::get_context_string(Mode::Base)?,
            &serialize(info, 2)?,
        ]
        .concat();
        let dst = [STR_HASH_TO_SCALAR, &CS::get_context_string(Mode::Base)?].concat();
        let m = CS::Group::hash_to_scalar::<CS::Hash>(&context, &dst)?;
        let t = self.sk + &m;
        let evaluated_element = blinded_element * &CS::Group::scalar_invert(&t);
        Ok(evaluated_element)
    }
}

pub struct VerifiableServer<CS: CipherSuite> {
    sk: <CS::Group as Group>::Scalar,
    pk: CS::Group,
}

impl<CS: CipherSuite> VerifiableServer<CS> {
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Result<Self, InternalError> {
        let mut seed = vec![0u8; <CS::Hash as Digest>::OutputSize::USIZE];
        rng.fill_bytes(&mut seed);
        Self::new_from_seed(&seed)
    }

    pub fn new_with_key(key: &[u8]) -> Result<Self, InternalError> {
        let sk = CS::Group::from_scalar_slice(&GenericArray::clone_from_slice(key))?;
        let pk = CS::Group::base_point() * &sk;
        Ok(Self { sk, pk })
    }

    // Corresponds to DeriveKeyPair from the VOPRF spec
    pub fn new_from_seed(seed: &[u8]) -> Result<Self, InternalError> {
        let dst = [
            STR_HASH_TO_SCALAR,
            &CS::get_context_string(Mode::Verifiable)?,
        ]
        .concat();
        let sk = CS::Group::hash_to_scalar::<CS::Hash>(seed, &dst)?;
        let pk = CS::Group::base_point() * &sk;
        Ok(Self { sk, pk })
    }

    /// Computes the second step for the multiplicative blinding version of DH-OPRF. This
    /// message is sent from the server (who holds the OPRF key) to the client.
    pub fn evaluate<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        blinded_element: CS::Group,
        info: &[u8],
    ) -> Result<(CS::Group, Proof<CS>), InternalError> {
        let context = [
            STR_CONTEXT,
            &CS::get_context_string(Mode::Base)?,
            &serialize(info, 2)?,
        ]
        .concat();
        let dst = [STR_HASH_TO_SCALAR, &CS::get_context_string(Mode::Base)?].concat();
        let m = CS::Group::hash_to_scalar::<CS::Hash>(&context, &dst)?;
        let t = self.sk + &m;
        let evaluated_element = blinded_element * &CS::Group::scalar_invert(&t);

        let g = CS::Group::base_point();
        let u = g * &t;

        let proof = generate_proof(rng, t, g, u, evaluated_element, blinded_element)?;

        Ok((evaluated_element, proof))
    }

    pub fn get_public_key(&self) -> CS::Group {
        self.pk
    }
}

// Inner function for blind. Returns the blind scalar and the blinded element
fn blind<CS: CipherSuite, R: RngCore + CryptoRng>(
    input: &[u8],
    blinding_factor_rng: &mut R,
) -> Result<(<CS::Group as Group>::Scalar, CS::Group), InternalError> {
    // Choose a random scalar that must be non-zero
    let blind = <CS::Group as Group>::random_nonzero_scalar(blinding_factor_rng);
    let dst = [STR_HASH_TO_GROUP, &CS::get_context_string(Mode::Base)?].concat();
    let mapped_point = <CS::Group as Group>::map_to_curve::<CS::Hash>(input, &dst)?;
    let blinded_element = mapped_point * &blind;
    Ok((blind, blinded_element))
}

#[allow(clippy::many_single_char_names)]
fn generate_proof<CS: CipherSuite, R: RngCore + CryptoRng>(
    rng: &mut R,
    k: <CS::Group as Group>::Scalar,
    a: CS::Group,
    b: CS::Group,
    c: CS::Group,
    d: CS::Group,
) -> Result<Proof<CS>, InternalError> {
    let (m, z) = compute_composites::<CS>(Some(k), b, &[c], &[d])?;

    let r = CS::Group::random_nonzero_scalar(rng);
    let t2 = a * &r;
    let t3 = m * &r;

    let challenge_dst = [STR_CHALLENGE, &CS::get_context_string(Mode::Verifiable)?].concat();
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
        &CS::get_context_string(Mode::Verifiable)?,
    ]
    .concat();
    let c = CS::Group::hash_to_scalar::<CS::Hash>(&h2_input, &hash_to_scalar_dst)?;

    let s = r - &(c * &k);

    Ok(Proof {
        c_scalar: c,
        s_scalar: s,
    })
}

pub struct Proof<CS: CipherSuite> {
    c_scalar: <CS::Group as Group>::Scalar,
    s_scalar: <CS::Group as Group>::Scalar,
}

#[allow(clippy::many_single_char_names)]
fn verify_proof<CS: CipherSuite>(
    a: CS::Group,
    b: CS::Group,
    c: CS::Group,
    d: CS::Group,
    proof: Proof<CS>,
) -> Result<(), InternalError> {
    let (m, z) = compute_composites::<CS>(None, b, &[c], &[d])?;
    let t2 = (a * &proof.s_scalar) + &(b * &proof.c_scalar);
    let t3 = (m * &proof.s_scalar) + &(z * &proof.c_scalar);

    let challenge_dst = [STR_CHALLENGE, &CS::get_context_string(Mode::Verifiable)?].concat();
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
        &CS::get_context_string(Mode::Verifiable)?,
    ]
    .concat();
    let c = CS::Group::hash_to_scalar::<CS::Hash>(&h2_input, &hash_to_scalar_dst)?;

    match CS::Group::ct_equal_scalar(&c, &proof.c_scalar) {
        true => Ok(()),
        false => Err(InternalError::ProofVerificationError),
    }
}

fn finalize_after_unblind<CS: CipherSuite>(
    input: &[u8],
    unblinded_element: CS::Group,
    info: &[u8],
    mode: Mode,
) -> Result<GenericArray<u8, <CS::Hash as Digest>::OutputSize>, InternalError> {
    let finalize_dst = [STR_FINALIZE, &CS::get_context_string(mode)?].concat();
    let hash_input = [
        serialize(input, 2)?,
        serialize(info, 2)?,
        serialize(&unblinded_element.to_arr().to_vec(), 2)?,
        serialize(&finalize_dst, 2)?,
    ]
    .concat();
    Ok(<CS::Hash as Digest>::digest(&hash_input))
}

fn compute_composites<CS: CipherSuite>(
    k_option: Option<<CS::Group as Group>::Scalar>,
    b: CS::Group,
    c_slice: &[CS::Group],
    d_slice: &[CS::Group],
) -> Result<(CS::Group, CS::Group), InternalError> {
    if c_slice.len() != d_slice.len() {
        return Err(InternalError::MismatchedLengthsForCompositeInputs);
    }

    let seed_dst = [STR_SEED, &CS::get_context_string(Mode::Verifiable)?].concat();
    let composite_dst = [STR_COMPOSITE, &CS::get_context_string(Mode::Verifiable)?].concat();

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
            serialize(&c_slice[i].to_arr().to_vec(), 2)?,
            serialize(&d_slice[i].to_arr().to_vec(), 2)?,
            serialize(&composite_dst, 2)?,
        ]
        .concat();
        let dst = [
            STR_HASH_TO_SCALAR,
            &CS::get_context_string(Mode::Verifiable)?,
        ]
        .concat();
        let di = CS::Group::hash_to_scalar::<CS::Hash>(&h2_input, &dst)?;
        m = c_slice[i] * &di + &m;
        z = match k_option {
            Some(_) => z,
            None => d_slice[i] * &di + &z,
        };
    }

    z = match k_option {
        Some(k) => m * &k,
        None => z,
    };

    Ok((m, z))
}

///////////
// Tests //
// ===== //
///////////

#[cfg(test)]
mod tests {
    use super::*;
    use crate::group::Group;
    use curve25519_dalek::ristretto::RistrettoPoint;
    use generic_array::{arr, GenericArray};
    use rand::rngs::OsRng;
    use sha2::Sha512;

    struct Ristretto255Sha512;
    impl CipherSuite for Ristretto255Sha512 {
        type Group = RistrettoPoint;
        type Hash = Sha512;
    }

    fn prf(
        input: &[u8],
        oprf_key: &[u8],
        info: &[u8],
    ) -> GenericArray<u8, <Sha512 as Digest>::OutputSize> {
        let dst = [
            STR_HASH_TO_GROUP,
            &Ristretto255Sha512::get_context_string(Mode::Base).unwrap(),
        ]
        .concat();
        let point = RistrettoPoint::map_to_curve::<Sha512>(input, &dst).unwrap();
        let scalar =
            RistrettoPoint::from_scalar_slice(GenericArray::from_slice(&oprf_key[..])).unwrap();

        let context = [
            STR_CONTEXT,
            &Ristretto255Sha512::get_context_string(Mode::Base).unwrap(),
            &serialize(info, 2).unwrap(),
        ]
        .concat();
        let dst = [
            STR_HASH_TO_SCALAR,
            &Ristretto255Sha512::get_context_string(Mode::Base).unwrap(),
        ]
        .concat();
        let m = <<Ristretto255Sha512 as CipherSuite>::Group as Group>::hash_to_scalar::<
            <Ristretto255Sha512 as CipherSuite>::Hash,
        >(&context, &dst)
        .unwrap();

        let res = point
            * &<<Ristretto255Sha512 as CipherSuite>::Group as Group>::scalar_invert(&(scalar + m));

        finalize_after_unblind::<Ristretto255Sha512>(&input, res, info, Mode::Base).unwrap()
    }

    #[test]
    fn oprf_retrieval() {
        let input = b"hunter2";
        let info = b"info";
        let mut rng = OsRng;
        let (client, alpha) =
            NonVerifiableClient::<Ristretto255Sha512>::blind(&input[..], &mut rng).unwrap();
        let oprf_key_bytes = arr![
            u8; 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31, 32,
        ];
        let server =
            NonVerifiableServer::<Ristretto255Sha512>::new_with_key(&oprf_key_bytes).unwrap();
        let beta = server.evaluate(alpha, info).unwrap();
        let res = client.finalize(beta, info).unwrap();
        let res2 = prf(&input[..], &oprf_key_bytes, info);
        assert_eq!(res, res2);
    }

    #[test]
    fn oprf_inversion_unsalted() {
        let mut rng = OsRng;
        let mut input = alloc::vec![0u8; 64];
        rng.fill_bytes(&mut input);
        let info = b"info";
        let (client, alpha) =
            NonVerifiableClient::<Ristretto255Sha512>::blind(&input, &mut rng).unwrap();
        let res = client.finalize(alpha, info).unwrap();

        let dst = [
            STR_HASH_TO_GROUP,
            &Ristretto255Sha512::get_context_string(Mode::Base).unwrap(),
        ]
        .concat();
        let point = RistrettoPoint::map_to_curve::<Sha512>(&input, &dst).unwrap();
        let res2 =
            finalize_after_unblind::<Ristretto255Sha512>(&input, point, info, Mode::Base).unwrap();

        assert_eq!(res, res2);
    }
}

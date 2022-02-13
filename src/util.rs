// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Helper functions

use core::convert::TryFrom;

use derive_where::derive_where;
use digest::core_api::BlockSizeUser;
use digest::{Digest, OutputSizeUser};
use generic_array::sequence::Concat;
use generic_array::typenum::{IsLess, IsLessOrEqual, Unsigned, U11, U2, U256};
use generic_array::{ArrayLength, GenericArray};
use rand_core::{CryptoRng, RngCore};
use subtle::ConstantTimeEq;

use crate::group::{STR_HASH_TO_GROUP, STR_HASH_TO_SCALAR};
#[cfg(feature = "serde")]
use crate::serialization::serde::{Element, Scalar};
use crate::{CipherSuite, Error, Group, InternalError, Result};

///////////////
// Constants //
// ========= //
///////////////

pub(crate) const STR_FINALIZE: [u8; 8] = *b"Finalize";
pub(crate) const STR_SEED: [u8; 5] = *b"Seed-";
pub(crate) const STR_DERIVE_KEYPAIR: [u8; 13] = *b"DeriveKeyPair";
pub(crate) const STR_COMPOSITE: [u8; 9] = *b"Composite";
pub(crate) const STR_CHALLENGE: [u8; 9] = *b"Challenge";
pub(crate) const STR_INFO: [u8; 4] = *b"Info";
pub(crate) const STR_VOPRF: [u8; 8] = *b"VOPRF09-";

/// Determines the mode of operation (either base mode or verifiable mode). This
/// is only used for custom implementations for [`Group`].
#[derive(Clone, Copy, Debug)]
pub enum Mode {
    /// Non-verifiable mode.
    Oprf,
    /// Verifiable mode.
    Voprf,
    /// Partially-oblivious mode.
    Poprf,
}

impl Mode {
    /// Mode as it is represented in a context string.
    pub fn to_u8(self) -> u8 {
        match self {
            Mode::Oprf => 0,
            Mode::Voprf => 1,
            Mode::Poprf => 2,
        }
    }
}

////////////////////////////
// High-level API Structs //
// ====================== //
////////////////////////////

/// The first client message sent from a client (either verifiable or not) to a
/// server (either verifiable or not).
#[derive_where(Clone, ZeroizeOnDrop)]
#[derive_where(Debug, Eq, Hash, Ord, PartialEq, PartialOrd; <CS::Group as Group>::Elem)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(crate = "serde", bound = "")
)]
pub struct BlindedElement<CS: CipherSuite>(
    #[cfg_attr(feature = "serde", serde(with = "Element::<CS::Group>"))]
    pub(crate)  <CS::Group as Group>::Elem,
)
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>;

/// The server's response to the [BlindedElement] message from a client (either
/// verifiable or not) to a server (either verifiable or not).
#[derive_where(Clone, ZeroizeOnDrop)]
#[derive_where(Debug, Eq, Hash, Ord, PartialEq, PartialOrd; <CS::Group as Group>::Elem)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(crate = "serde", bound = "")
)]
pub struct EvaluationElement<CS: CipherSuite>(
    #[cfg_attr(feature = "serde", serde(with = "Element::<CS::Group>"))]
    pub(crate)  <CS::Group as Group>::Elem,
)
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>;

/// Contains prepared [`EvaluationElement`]s by a server batch evaluate
/// preparation.
#[derive_where(Clone, ZeroizeOnDrop)]
#[derive_where(Debug, Eq, Hash, Ord, PartialEq, PartialOrd; <CS::Group as Group>::Elem)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(crate = "serde", bound = "")
)]
pub struct PreparedEvaluationElement<CS: CipherSuite>(pub(crate) EvaluationElement<CS>)
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>;

/// A proof produced by a server that the OPRF output matches against a server
/// public key.
#[derive_where(Clone, ZeroizeOnDrop)]
#[derive_where(Debug, Eq, Hash, Ord, PartialEq, PartialOrd; <CS::Group as Group>::Scalar)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(crate = "serde", bound = "")
)]
pub struct Proof<CS: CipherSuite>
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
{
    #[cfg_attr(feature = "serde", serde(with = "Scalar::<CS::Group>"))]
    pub(crate) c_scalar: <CS::Group as Group>::Scalar,
    #[cfg_attr(feature = "serde", serde(with = "Scalar::<CS::Group>"))]
    pub(crate) s_scalar: <CS::Group as Group>::Scalar,
}

/////////////////////
// Proof Functions //
// =============== //
/////////////////////

/// Can only fail with [`Error::Batch`].
#[allow(clippy::many_single_char_names)]
pub(crate) fn generate_proof<CS: CipherSuite, R: RngCore + CryptoRng>(
    rng: &mut R,
    k: <CS::Group as Group>::Scalar,
    a: <CS::Group as Group>::Elem,
    b: <CS::Group as Group>::Elem,
    cs: impl Iterator<Item = <CS::Group as Group>::Elem> + ExactSizeIterator,
    ds: impl Iterator<Item = <CS::Group as Group>::Elem> + ExactSizeIterator,
    mode: Mode,
) -> Result<Proof<CS>>
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
{
    // https://www.ietf.org/archive/id/draft-irtf-cfrg-voprf-08.html#section-3.3.2.2-1

    let (m, z) = compute_composites::<CS, _, _>(Some(k), b, cs, ds, mode)?;

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

    // h2Input = I2OSP(len(Bm), 2) || Bm ||
    //           I2OSP(len(a0), 2) || a0 ||
    //           I2OSP(len(a1), 2) || a1 ||
    //           I2OSP(len(a2), 2) || a2 ||
    //           I2OSP(len(a3), 2) || a3 ||
    //           "Challenge"
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
        &STR_CHALLENGE,
    ];

    let dst = GenericArray::from(STR_HASH_TO_SCALAR).concat(create_context_string::<CS>(mode));
    // This can't fail, the size of the `input` is known.
    let c_scalar = CS::Group::hash_to_scalar::<CS>(&h2_input, &dst).unwrap();
    let s_scalar = r - &(c_scalar * &k);

    Ok(Proof { c_scalar, s_scalar })
}

/// Can only fail with [`Error::ProofVerification`] or [`Error::Batch`].
#[allow(clippy::many_single_char_names)]
pub(crate) fn verify_proof<CS: CipherSuite>(
    a: <CS::Group as Group>::Elem,
    b: <CS::Group as Group>::Elem,
    cs: impl Iterator<Item = <CS::Group as Group>::Elem> + ExactSizeIterator,
    ds: impl Iterator<Item = <CS::Group as Group>::Elem> + ExactSizeIterator,
    proof: &Proof<CS>,
    mode: Mode,
) -> Result<()>
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
{
    // https://www.ietf.org/archive/id/draft-irtf-cfrg-voprf-08.html#section-3.3.4.1-2
    let (m, z) = compute_composites::<CS, _, _>(None, b, cs, ds, mode)?;
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

    // h2Input = I2OSP(len(Bm), 2) || Bm ||
    //           I2OSP(len(a0), 2) || a0 ||
    //           I2OSP(len(a1), 2) || a1 ||
    //           I2OSP(len(a2), 2) || a2 ||
    //           I2OSP(len(a3), 2) || a3 ||
    //           "Challenge"
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
        &STR_CHALLENGE,
    ];

    let dst = GenericArray::from(STR_HASH_TO_SCALAR).concat(create_context_string::<CS>(mode));
    // This can't fail, the size of the `input` is known.
    let c = CS::Group::hash_to_scalar::<CS>(&h2_input, &dst).unwrap();

    match c.ct_eq(&proof.c_scalar).into() {
        true => Ok(()),
        false => Err(Error::ProofVerification),
    }
}

type ComputeCompositesResult<CS> = (
    <<CS as CipherSuite>::Group as Group>::Elem,
    <<CS as CipherSuite>::Group as Group>::Elem,
);

/// Can only fail with [`Error::Batch`].
fn compute_composites<
    CS: CipherSuite,
    IC: Iterator<Item = <CS::Group as Group>::Elem> + ExactSizeIterator,
    ID: Iterator<Item = <CS::Group as Group>::Elem> + ExactSizeIterator,
>(
    k_option: Option<<CS::Group as Group>::Scalar>,
    b: <CS::Group as Group>::Elem,
    c_slice: IC,
    d_slice: ID,
    mode: Mode,
) -> Result<ComputeCompositesResult<CS>>
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
{
    // https://www.ietf.org/archive/id/draft-irtf-cfrg-voprf-08.html#section-3.3.2.3-2

    let elem_len = <CS::Group as Group>::ElemLen::U16.to_be_bytes();

    if c_slice.len() != d_slice.len() {
        return Err(Error::Batch);
    }

    let len = u16::try_from(c_slice.len()).map_err(|_| Error::Batch)?;

    // seedDST = "Seed-" || contextString
    let seed_dst = GenericArray::from(STR_SEED).concat(create_context_string::<CS>(mode));

    // h1Input = I2OSP(len(Bm), 2) || Bm ||
    //           I2OSP(len(seedDST), 2) || seedDST
    // seed = Hash(h1Input)
    let seed = CS::Hash::new()
        .chain_update(&elem_len)
        .chain_update(CS::Group::serialize_elem(b))
        .chain_update(i2osp_2_array(&seed_dst))
        .chain_update(seed_dst)
        .finalize();
    let seed_len = i2osp_2_array(&seed);

    let mut m = CS::Group::identity_elem();
    let mut z = CS::Group::identity_elem();

    for (i, (c, d)) in (0..len).zip(c_slice.zip(d_slice)) {
        // Ci = GG.SerializeElement(Cs[i])
        let ci = CS::Group::serialize_elem(c);
        // Di = GG.SerializeElement(Ds[i])
        let di = CS::Group::serialize_elem(d);
        // h2Input = I2OSP(len(seed), 2) || seed || I2OSP(i, 2) ||
        //           I2OSP(len(Ci), 2) || Ci ||
        //           I2OSP(len(Di), 2) || Di ||
        //           "Composite"
        let h2_input = [
            seed_len.as_slice(),
            &seed,
            &i.to_be_bytes(),
            &elem_len,
            &ci,
            &elem_len,
            &di,
            &STR_COMPOSITE,
        ];

        let dst = GenericArray::from(STR_HASH_TO_SCALAR).concat(create_context_string::<CS>(mode));
        // This can't fail, the size of the `input` is known.
        let di = CS::Group::hash_to_scalar::<CS>(&h2_input, &dst).unwrap();
        m = c * &di + &m;
        z = match k_option {
            Some(_) => z,
            None => d * &di + &z,
        };
    }

    z = match k_option {
        Some(k) => m * &k,
        None => z,
    };

    Ok((m, z))
}

/////////////////////
// Inner Functions //
// =============== //
/////////////////////

type DeriveKeypairResult<CS> = (
    <<CS as CipherSuite>::Group as Group>::Scalar,
    <<CS as CipherSuite>::Group as Group>::Elem,
);

/// Can only fail with [`Error::DeriveKeyPair`] and [`Error::Protocol`].
pub(crate) fn derive_keypair<CS: CipherSuite>(
    seed: &[u8],
    info: &[u8],
    mode: Mode,
) -> Result<DeriveKeypairResult<CS>, Error>
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
{
    let context_string = create_context_string::<CS>(mode);
    let dst = GenericArray::from(STR_DERIVE_KEYPAIR).concat(context_string);

    let info_len = i2osp_2(info.len()).map_err(|_| Error::DeriveKeyPair)?;

    for counter in 0_u8..=u8::MAX {
        // deriveInput = seed || I2OSP(len(info), 2) || info
        // skS = G.HashToScalar(deriveInput || I2OSP(counter, 1), DST = "DeriveKeyPair"
        // || contextString)
        let sk_s = <CS::Group as Group>::hash_to_scalar::<CS>(
            &[seed, &info_len, info, &counter.to_be_bytes()],
            &dst,
        )
        .map_err(|_| Error::DeriveKeyPair)?;

        if !bool::from(CS::Group::is_zero_scalar(sk_s)) {
            let pk_s = CS::Group::base_elem() * &sk_s;
            return Ok((sk_s, pk_s));
        }
    }

    Err(Error::Protocol)
}

/// Inner function for blind that assumes that the blinding factor has already
/// been chosen, and therefore takes it as input. Does not check if the blinding
/// factor is non-zero.
///
/// Can only fail with [`Error::Input`].
pub(crate) fn deterministic_blind_unchecked<CS: CipherSuite>(
    input: &[u8],
    blind: &<CS::Group as Group>::Scalar,
    mode: Mode,
) -> Result<<CS::Group as Group>::Elem>
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
{
    let dst = GenericArray::from(STR_HASH_TO_GROUP).concat(create_context_string::<CS>(mode));
    let hashed_point = CS::Group::hash_to_curve::<CS>(&[input], &dst).map_err(|_| Error::Input)?;
    Ok(hashed_point * blind)
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

///////////////////////
// Utility Functions //
// ================= //
///////////////////////

pub(crate) fn i2osp_2(input: usize) -> Result<[u8; 2], InternalError> {
    u16::try_from(input)
        .map(|input| input.to_be_bytes())
        .map_err(|_| InternalError::I2osp)
}

pub(crate) fn i2osp_2_array<L: ArrayLength<u8> + IsLess<U256>>(
    _: &GenericArray<u8, L>,
) -> GenericArray<u8, U2> {
    L::U16.to_be_bytes().into()
}

#[cfg(test)]
mod unit_tests {
    use proptest::collection::vec;
    use proptest::prelude::*;

    use crate::{
        BlindedElement, EvaluationElement, OprfClient, OprfServer, PoprfClient, PoprfServer, Proof,
        VoprfClient, VoprfServer,
    };

    macro_rules! test_deserialize {
        ($item:ident, $bytes:ident) => {
            #[cfg(feature = "ristretto255")]
            {
                let _ = $item::<crate::Ristretto255>::deserialize(&$bytes[..]);
            }

            let _ = $item::<p256::NistP256>::deserialize(&$bytes[..]);
        };
    }

    proptest! {
        #[test]
        fn test_nocrash_oprf_client(bytes in vec(any::<u8>(), 0..200)) {
            test_deserialize!(OprfClient, bytes);
        }

        #[test]
        fn test_nocrash_voprf_client(bytes in vec(any::<u8>(), 0..200)) {
            test_deserialize!(VoprfClient, bytes);
        }

        #[test]
        fn test_nocrash_poprf_client(bytes in vec(any::<u8>(), 0..200)) {
            test_deserialize!(PoprfClient, bytes);
        }

        #[test]
        fn test_nocrash_oprf_server(bytes in vec(any::<u8>(), 0..200)) {
            test_deserialize!(OprfServer, bytes);
        }

        #[test]
        fn test_nocrash_voprf_server(bytes in vec(any::<u8>(), 0..200)) {
            test_deserialize!(VoprfServer, bytes);
        }

        #[test]
        fn test_nocrash_poprf_server(bytes in vec(any::<u8>(), 0..200)) {
            test_deserialize!(PoprfServer, bytes);
        }


        #[test]
        fn test_nocrash_blinded_element(bytes in vec(any::<u8>(), 0..200)) {
            test_deserialize!(BlindedElement, bytes);
        }

        #[test]
        fn test_nocrash_evaluation_element(bytes in vec(any::<u8>(), 0..200)) {
            test_deserialize!(EvaluationElement, bytes);
        }

        #[test]
        fn test_nocrash_proof(bytes in vec(any::<u8>(), 0..200)) {
            test_deserialize!(Proof, bytes);
        }
    }
}

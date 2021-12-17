// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use crate::{
    errors::InternalError,
    group::Group,
    tests::{mock_rng::CycleRng, parser::*},
    voprf::{
        BlindedElement, EvaluationElement, NonVerifiableClient, NonVerifiableServer, Proof,
        VerifiableClient, VerifiableServer,
    },
};
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use digest::{BlockInput, Digest};
use generic_array::GenericArray;
use json::JsonValue;

#[derive(Debug)]
struct VOPRFTestVectorParameters {
    seed: Vec<u8>,
    sksm: Vec<u8>,
    pksm: Vec<u8>,
    input: Vec<Vec<u8>>,
    info: Vec<u8>,
    blind: Vec<Vec<u8>>,
    blinded_element: Vec<Vec<u8>>,
    evaluation_element: Vec<Vec<u8>>,
    proof: Vec<u8>,
    proof_random_scalar: Vec<u8>,
    output: Vec<Vec<u8>>,
}

fn populate_test_vectors(values: &JsonValue) -> VOPRFTestVectorParameters {
    VOPRFTestVectorParameters {
        seed: decode(values, "seed"),
        sksm: decode(values, "skSm"),
        pksm: decode(values, "pkSm"),
        input: decode_vec(values, "Input"),
        info: decode(values, "Info"),
        blind: decode_vec(values, "Blind"),
        blinded_element: decode_vec(values, "BlindedElement"),
        evaluation_element: decode_vec(values, "EvaluationElement"),
        proof: decode(values, "Proof"),
        proof_random_scalar: decode(values, "ProofRandomScalar"),
        output: decode_vec(values, "Output"),
    }
}

fn decode(values: &JsonValue, key: &str) -> Vec<u8> {
    values[key]
        .as_str()
        .and_then(|s| hex::decode(&s.to_string()).ok())
        .unwrap_or_default()
}

fn decode_vec(values: &JsonValue, key: &str) -> Vec<Vec<u8>> {
    let s = values[key].as_str().unwrap();
    let res = match s.contains(',') {
        true => Some(
            s.split(',')
                .map(|x| hex::decode(&x.to_string()).unwrap())
                .collect(),
        ),
        false => Some(vec![hex::decode(&s.to_string()).unwrap()]),
    };
    res.unwrap()
}

macro_rules! json_to_test_vectors {
    ( $v:ident, $cs:expr, $mode:expr ) => {
        $v[$cs][$mode]
            .members()
            .map(|x| populate_test_vectors(&x))
            .collect::<Vec<VOPRFTestVectorParameters>>()
    };
}

#[test]
fn test_vectors() -> Result<(), InternalError> {
    let rfc = json::parse(rfc_to_json(super::voprf_vectors::VECTORS).as_str())
        .expect("Could not parse json");

    cfg_ristretto! { {
        use curve25519_dalek::ristretto::RistrettoPoint;
        use sha2::Sha512;

        let ristretto_base_tvs = json_to_test_vectors!(
            rfc,
            String::from("ristretto255, SHA-512"),
            String::from("Base")
        );

        let ristretto_verifiable_tvs = json_to_test_vectors!(
            rfc,
            String::from("ristretto255, SHA-512"),
            String::from("Verifiable")
        );

        test_base_seed_to_key::<RistrettoPoint, Sha512>(&ristretto_base_tvs)?;
        test_base_blind::<RistrettoPoint, Sha512>(&ristretto_base_tvs)?;
        test_base_evaluate::<RistrettoPoint, Sha512>(&ristretto_base_tvs)?;
        test_base_finalize::<RistrettoPoint, Sha512>(&ristretto_base_tvs)?;

        test_verifiable_seed_to_key::<RistrettoPoint, Sha512>(&ristretto_verifiable_tvs)?;
        test_verifiable_blind::<RistrettoPoint, Sha512>(&ristretto_verifiable_tvs)?;
        test_verifiable_evaluate::<RistrettoPoint, Sha512>(&ristretto_verifiable_tvs)?;
        test_verifiable_finalize::<RistrettoPoint, Sha512>(&ristretto_verifiable_tvs)?;
    } }

    #[cfg(feature = "p256")]
    {
        use p256_::ProjectivePoint;
        use sha2::Sha256;

        let p256_base_tvs =
            json_to_test_vectors!(rfc, String::from("P-256, SHA-256"), String::from("Base"));

        let p256_verifiable_tvs = json_to_test_vectors!(
            rfc,
            String::from("P-256, SHA-256"),
            String::from("Verifiable")
        );

        test_base_seed_to_key::<ProjectivePoint, Sha256>(&p256_base_tvs)?;
        test_base_blind::<ProjectivePoint, Sha256>(&p256_base_tvs)?;
        test_base_evaluate::<ProjectivePoint, Sha256>(&p256_base_tvs)?;
        test_base_finalize::<ProjectivePoint, Sha256>(&p256_base_tvs)?;

        test_verifiable_seed_to_key::<ProjectivePoint, Sha256>(&p256_verifiable_tvs)?;
        test_verifiable_blind::<ProjectivePoint, Sha256>(&p256_verifiable_tvs)?;
        test_verifiable_evaluate::<ProjectivePoint, Sha256>(&p256_verifiable_tvs)?;
        test_verifiable_finalize::<ProjectivePoint, Sha256>(&p256_verifiable_tvs)?;
    }

    Ok(())
}

fn test_base_seed_to_key<G: Group, H: BlockInput + Digest>(
    tvs: &[VOPRFTestVectorParameters],
) -> Result<(), InternalError> {
    for parameters in tvs {
        let server = NonVerifiableServer::<G, H>::new_from_seed(&parameters.seed)?;

        assert_eq!(
            &parameters.sksm,
            &G::scalar_as_bytes(server.get_private_key()).to_vec()
        );
    }
    Ok(())
}

fn test_verifiable_seed_to_key<G: Group, H: BlockInput + Digest>(
    tvs: &[VOPRFTestVectorParameters],
) -> Result<(), InternalError> {
    for parameters in tvs {
        let server = VerifiableServer::<G, H>::new_from_seed(&parameters.seed)?;

        assert_eq!(
            &parameters.sksm,
            &G::scalar_as_bytes(server.get_private_key()).to_vec()
        );
        assert_eq!(&parameters.pksm, &server.get_public_key().to_arr().to_vec());
    }
    Ok(())
}

// Tests input -> blind, blinded_element
fn test_base_blind<G: Group, H: BlockInput + Digest>(
    tvs: &[VOPRFTestVectorParameters],
) -> Result<(), InternalError> {
    for parameters in tvs {
        for i in 0..parameters.input.len() {
            let blind =
                G::from_scalar_slice(&GenericArray::clone_from_slice(&parameters.blind[i]))?;
            let client_result = NonVerifiableClient::<G, H>::deterministic_blind_unchecked(
                parameters.input[i].clone(),
                blind,
            )?;

            assert_eq!(
                &parameters.blind[i],
                &G::scalar_as_bytes(client_result.state.blind).to_vec()
            );
            assert_eq!(
                &parameters.blinded_element[i],
                &client_result.message.serialize()
            );
        }
    }
    Ok(())
}

// Tests input -> blind, blinded_element
fn test_verifiable_blind<G: Group, H: BlockInput + Digest>(
    tvs: &[VOPRFTestVectorParameters],
) -> Result<(), InternalError> {
    for parameters in tvs {
        for i in 0..parameters.input.len() {
            let blind =
                G::from_scalar_slice(&GenericArray::clone_from_slice(&parameters.blind[i]))?;
            let client_blind_result = VerifiableClient::<G, H>::deterministic_blind_unchecked(
                parameters.input[i].clone(),
                blind,
            )?;

            assert_eq!(
                &parameters.blind[i],
                &G::scalar_as_bytes(client_blind_result.state.get_blind()).to_vec()
            );
            assert_eq!(
                &parameters.blinded_element[i],
                &client_blind_result.message.serialize()
            );
        }
    }
    Ok(())
}

// Tests sksm, blinded_element -> evaluation_element
fn test_base_evaluate<G: Group, H: BlockInput + Digest>(
    tvs: &[VOPRFTestVectorParameters],
) -> Result<(), InternalError> {
    for parameters in tvs {
        for i in 0..parameters.input.len() {
            let server = NonVerifiableServer::<G, H>::new_with_key(&parameters.sksm)?;
            let server_result = server.evaluate(
                &BlindedElement::deserialize(&parameters.blinded_element[i])?,
                Some(&parameters.info),
            )?;

            assert_eq!(
                &parameters.evaluation_element[i],
                &server_result.message.serialize()
            );
        }
    }
    Ok(())
}

fn test_verifiable_evaluate<G: Group, H: BlockInput + Digest>(
    tvs: &[VOPRFTestVectorParameters],
) -> Result<(), InternalError> {
    for parameters in tvs {
        let mut rng = CycleRng::new(parameters.proof_random_scalar.clone());
        let server = VerifiableServer::<G, H>::new_with_key(&parameters.sksm)?;

        let mut blinded_elements = vec![];
        for blinded_element_bytes in &parameters.blinded_element {
            blinded_elements.push(BlindedElement::deserialize(blinded_element_bytes)?);
        }

        let batch_evaluate_result =
            server.batch_evaluate(&mut rng, &blinded_elements, Some(&parameters.info))?;

        for i in 0..parameters.evaluation_element.len() {
            assert_eq!(
                &parameters.evaluation_element[i],
                &batch_evaluate_result.messages[i].serialize(),
            );
        }

        assert_eq!(&parameters.proof, &batch_evaluate_result.proof.serialize());
    }
    Ok(())
}

// Tests input, blind, evaluation_element -> output
fn test_base_finalize<G: Group, H: BlockInput + Digest>(
    tvs: &[VOPRFTestVectorParameters],
) -> Result<(), InternalError> {
    for parameters in tvs {
        for i in 0..parameters.input.len() {
            let client = NonVerifiableClient::<G, H>::from_data_and_blind(
                &parameters.input[i],
                <G as Group>::from_scalar_slice(&GenericArray::clone_from_slice(
                    &parameters.blind[i],
                ))?,
            );

            let client_finalize_result = client.finalize(
                &EvaluationElement::deserialize(&parameters.evaluation_element[i])?,
                Some(&parameters.info),
            )?;

            assert_eq!(&parameters.output[i], &client_finalize_result.to_vec());
        }
    }
    Ok(())
}

fn test_verifiable_finalize<G: Group, H: BlockInput + Digest>(
    tvs: &[VOPRFTestVectorParameters],
) -> Result<(), InternalError> {
    for parameters in tvs {
        let mut clients = vec![];
        for i in 0..parameters.input.len() {
            let client = VerifiableClient::<G, H>::from_data_and_blind_and_element(
                &parameters.input[i],
                <G as Group>::from_scalar_slice(&GenericArray::clone_from_slice(
                    &parameters.blind[i],
                ))?,
                <G as Group>::from_element_slice(&GenericArray::clone_from_slice(
                    &parameters.blinded_element[i],
                ))?,
            );
            clients.push(client.clone());
        }

        let messages: Vec<_> = parameters
            .evaluation_element
            .iter()
            .map(|x| EvaluationElement::deserialize(x).unwrap())
            .collect();

        let batch_result = VerifiableClient::batch_finalize(
            &clients,
            &messages,
            &Proof::deserialize(&parameters.proof)?,
            G::from_element_slice(GenericArray::from_slice(&parameters.pksm))?,
            Some(&parameters.info),
        )?;

        assert_eq!(
            parameters.output,
            batch_result
                .iter()
                .map(|arr| arr.to_vec())
                .collect::<Vec<Vec<u8>>>()
        );
    }
    Ok(())
}

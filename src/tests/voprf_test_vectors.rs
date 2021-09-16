// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::{
    ciphersuite::CipherSuite,
    errors::InternalError,
    group::Group,
    tests::{mock_rng::CycleRng, parser::*},
    voprf::{
        BlindedElement, EvaluationElement, NonVerifiableClient, NonVerifiableServer, Proof,
        VerifiableClient, VerifiableServer,
    },
};
use alloc::string::ToString;
use alloc::vec::Vec;
use curve25519_dalek::ristretto::RistrettoPoint;
use generic_array::GenericArray;
use json::JsonValue;
use sha2::Sha512;

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
        input: decode_vec(&values, "Input"),
        info: decode(values, "Info"),
        blind: decode_vec(&values, "Blind"),
        blinded_element: decode_vec(&values, "BlindedElement"),
        evaluation_element: decode_vec(&values, "EvaluationElement"),
        proof: decode(values, "Proof"),
        proof_random_scalar: decode(values, "ProofRandomScalar"),
        output: decode_vec(&values, "Output"),
    }
}

fn decode(values: &JsonValue, key: &str) -> Vec<u8> {
    values[key]
        .as_str()
        .and_then(|s| hex::decode(&s.to_string()).ok())
        .unwrap_or(vec![])
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
    struct Ristretto255Sha512;
    impl CipherSuite for Ristretto255Sha512 {
        type Group = RistrettoPoint;
        type Hash = Sha512;
    }

    let rfc = json::parse(rfc_to_json(super::voprf_vectors::VECTORS).as_str())
        .expect("Could not parse json");

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

    test_base_seed_to_key::<Ristretto255Sha512>(&ristretto_base_tvs)?;
    test_base_blind::<Ristretto255Sha512>(&ristretto_base_tvs)?;
    test_base_evaluate::<Ristretto255Sha512>(&ristretto_base_tvs)?;
    test_base_finalize::<Ristretto255Sha512>(&ristretto_base_tvs)?;

    test_verifiable_seed_to_key::<Ristretto255Sha512>(&ristretto_verifiable_tvs)?;
    test_verifiable_blind::<Ristretto255Sha512>(&ristretto_verifiable_tvs)?;
    test_verifiable_evaluate::<Ristretto255Sha512>(&ristretto_verifiable_tvs)?;
    test_verifiable_finalize::<Ristretto255Sha512>(&ristretto_verifiable_tvs)?;

    #[cfg(feature = "p256")]
    {
        struct P256Sha256;
        impl CipherSuite for P256Sha256 {
            type Group = p256_::ProjectivePoint;
            type Hash = sha2::Sha256;
        }

        let p256_base_tvs =
            json_to_test_vectors!(rfc, String::from("P-256, SHA-256"), String::from("Base"));

        let p256_verifiable_tvs = json_to_test_vectors!(
            rfc,
            String::from("P-256, SHA-256"),
            String::from("Verifiable")
        );

        test_base_seed_to_key::<P256Sha256>(&p256_base_tvs)?;
        test_base_blind::<P256Sha256>(&p256_base_tvs)?;
        test_base_evaluate::<P256Sha256>(&p256_base_tvs)?;
        test_base_finalize::<P256Sha256>(&p256_base_tvs)?;

        test_verifiable_seed_to_key::<P256Sha256>(&p256_verifiable_tvs)?;
        test_verifiable_blind::<P256Sha256>(&p256_verifiable_tvs)?;
        test_verifiable_evaluate::<P256Sha256>(&p256_verifiable_tvs)?;
        test_verifiable_finalize::<P256Sha256>(&p256_verifiable_tvs)?;
    }

    Ok(())
}

fn test_base_seed_to_key<CS: CipherSuite>(
    tvs: &[VOPRFTestVectorParameters],
) -> Result<(), InternalError> {
    for parameters in tvs {
        let server = NonVerifiableServer::<CS>::new_from_seed(&parameters.seed)?;

        assert_eq!(
            &parameters.sksm,
            &CS::Group::scalar_as_bytes(server.get_private_key()).to_vec()
        );
    }
    Ok(())
}

fn test_verifiable_seed_to_key<CS: CipherSuite>(
    tvs: &[VOPRFTestVectorParameters],
) -> Result<(), InternalError> {
    for parameters in tvs {
        let server = VerifiableServer::<CS>::new_from_seed(&parameters.seed)?;

        assert_eq!(
            &parameters.sksm,
            &CS::Group::scalar_as_bytes(server.get_private_key()).to_vec()
        );
        assert_eq!(&parameters.pksm, &server.get_public_key().to_arr().to_vec());
    }
    Ok(())
}

// Tests input -> blind, blinded_element
fn test_base_blind<CS: CipherSuite>(
    tvs: &[VOPRFTestVectorParameters],
) -> Result<(), InternalError> {
    for parameters in tvs {
        for i in 0..parameters.input.len() {
            let mut rng = CycleRng::new(parameters.blind[i].to_vec());
            let (client, blinded_element) =
                NonVerifiableClient::<CS>::blind(&parameters.input[i], &mut rng)?;

            assert_eq!(
                &parameters.blind[i],
                &CS::Group::scalar_as_bytes(client.get_blind()).to_vec()
            );
            assert_eq!(&parameters.blinded_element[i], &blinded_element.serialize());
        }
    }
    Ok(())
}

// Tests input -> blind, blinded_element
fn test_verifiable_blind<CS: CipherSuite>(
    tvs: &[VOPRFTestVectorParameters],
) -> Result<(), InternalError> {
    for parameters in tvs {
        for i in 0..parameters.input.len() {
            let mut rng = CycleRng::new(parameters.blind[i].to_vec());
            let (client, blinded_element) =
                VerifiableClient::<CS>::blind(&parameters.input[i], &mut rng)?;

            assert_eq!(
                &parameters.blind[i],
                &CS::Group::scalar_as_bytes(client.get_blind()).to_vec()
            );
            assert_eq!(&parameters.blinded_element[i], &blinded_element.serialize());
        }
    }
    Ok(())
}

// Tests sksm, blinded_element -> evaluation_element
fn test_base_evaluate<CS: CipherSuite>(
    tvs: &[VOPRFTestVectorParameters],
) -> Result<(), InternalError> {
    for parameters in tvs {
        for i in 0..parameters.input.len() {
            let server = NonVerifiableServer::<CS>::new_with_key(&parameters.sksm)?;
            let evaluation_element = server.evaluate(
                BlindedElement::deserialize(&parameters.blinded_element[i])?,
                &parameters.info,
            )?;

            assert_eq!(
                &parameters.evaluation_element[i],
                &evaluation_element.serialize()
            );
        }
    }
    Ok(())
}

fn test_verifiable_evaluate<CS: CipherSuite>(
    tvs: &[VOPRFTestVectorParameters],
) -> Result<(), InternalError> {
    for parameters in tvs {
        let mut rng = CycleRng::new(parameters.proof_random_scalar.clone());
        let server = VerifiableServer::<CS>::new_with_key(&parameters.sksm)?;

        let mut blinded_elements = vec![];
        for blinded_element_bytes in &parameters.blinded_element {
            blinded_elements.push(BlindedElement::deserialize(&blinded_element_bytes)?);
        }

        let (evaluation_elements, proof) =
            server.batch_evaluate(&mut rng, &blinded_elements, &parameters.info)?;

        for i in 0..parameters.evaluation_element.len() {
            assert_eq!(
                &parameters.evaluation_element[i],
                &evaluation_elements[i].serialize(),
            );
        }

        assert_eq!(&parameters.proof, &proof.serialize());
    }
    Ok(())
}

// Tests input, blind, evaluation_element -> output
fn test_base_finalize<CS: CipherSuite>(
    tvs: &[VOPRFTestVectorParameters],
) -> Result<(), InternalError> {
    for parameters in tvs {
        for i in 0..parameters.input.len() {
            let client = NonVerifiableClient::<CS>::from_data_and_blind(
                &parameters.input[i],
                &<CS::Group as Group>::from_scalar_slice(&GenericArray::clone_from_slice(
                    &parameters.blind[i],
                ))?,
            );

            let output = client.finalize(
                EvaluationElement::deserialize(&parameters.evaluation_element[i])?,
                &parameters.info,
            )?;

            assert_eq!(&parameters.output[i], &output.to_vec());
        }
    }
    Ok(())
}

fn test_verifiable_finalize<CS: CipherSuite>(
    tvs: &[VOPRFTestVectorParameters],
) -> Result<(), InternalError> {
    for parameters in tvs {
        let mut clients_and_evaluation_elements = vec![];

        let mut clients = vec![];
        for i in 0..parameters.input.len() {
            let client = VerifiableClient::<CS>::from_data_and_blind(
                &parameters.input[i],
                &<CS::Group as Group>::from_scalar_slice(&GenericArray::clone_from_slice(
                    &parameters.blind[i],
                ))?,
                &<CS::Group as Group>::from_element_slice(&GenericArray::clone_from_slice(
                    &parameters.blinded_element[i],
                ))?,
            );
            clients.push(client.clone());
        }

        for i in 0..parameters.input.len() {
            let evaluation_element =
                EvaluationElement::deserialize(&parameters.evaluation_element[i])?;
            clients_and_evaluation_elements.push((&clients[i], evaluation_element));
        }

        let outputs = VerifiableClient::batch_finalize(
            &clients_and_evaluation_elements,
            Proof::deserialize(&parameters.proof)?,
            CS::Group::from_element_slice(GenericArray::from_slice(&parameters.pksm))?,
            &parameters.info,
        )?;

        assert_eq!(
            parameters.output,
            outputs
                .iter()
                .map(|arr| arr.to_vec())
                .collect::<Vec<Vec<u8>>>()
        );
    }
    Ok(())
}

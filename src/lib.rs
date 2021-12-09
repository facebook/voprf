// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! An implementation of a verifiable oblivious pseudorandom function (VOPRF)
//!
//! Note: This implementation is in sync with
//! [draft-irtf-cfrg-voprf-08](https://www.ietf.org/archive/id/draft-irtf-cfrg-voprf-08.html),
//! but this specification is subject to change, until the final version
//! published by the IETF.
//!
//! # Overview
//!
//! A verifiable oblivious pseudorandom function is a protocol that is
//! evaluated between a client and a server. They must first agree on a
//! collection of primitives to be kept consistent throughout protocol
//! execution. These include:
//! - a finite cyclic group along with a point representation, and
//! - a hashing function.
//!
//! We will use the following choices in this example:
//!
//! ```
//! type Group = curve25519_dalek::ristretto::RistrettoPoint;
//! type Hash = sha2::Sha512;
//! ```
//!
//! ## Modes of Operation
//!
//! VOPRF can be used in two modes:
//! - [Base Mode](#base-mode), which corresponds to a normal OPRF evaluation with no
//!   support for the verification of the OPRF outputs
//! - [Verifiable Mode](#verifiable-mode), which corresponds to an OPRF evaluation where
//!   the outputs can be verified against a server public key
//!
//! In either mode, the protocol begins with a client blinding, followed by
//! a server evaluation, and finishes with a client finalization.
//!
//! ## Base Mode
//!
//! In base mode, a [NonVerifiableClient] interacts with a
//! [NonVerifiableServer] to compute the output of the VOPRF.
//!
//! ### Server Setup
//!
//! The protocol begins with a setup phase, in which the server must run
//! [NonVerifiableServer::new()] to produce an instance of itself. This
//! instance must be persisted on the server and used for online
//! client evaluations.
//!
//! ```
//! # type Group = curve25519_dalek::ristretto::RistrettoPoint;
//! # type Hash = sha2::Sha512;
//! use voprf::NonVerifiableServer;
//! use rand::{rngs::OsRng, RngCore};
//!
//! let mut server_rng = OsRng;
//! let server = NonVerifiableServer::<Group, Hash>::new(&mut server_rng)
//!    .expect("Unable to construct server");
//! ```
//!
//! ### Client Blinding
//!
//! In the first step, the client chooses an input, and runs
//! [NonVerifiableClient::blind] to produce a [NonVerifiableClientBlindResult],
//! which consists of a [BlindedElement] to be sent to the server and a
//! [NonVerifiableClient] which must be persisted on the client for the final
//! step of the VOPRF protocol.
//!
//! ```
//! # type Group = curve25519_dalek::ristretto::RistrettoPoint;
//! # type Hash = sha2::Sha512;
//! use voprf::NonVerifiableClient;
//! use rand::{rngs::OsRng, RngCore};
//!
//! let mut client_rng = OsRng;
//! let client_blind_result = NonVerifiableClient::<Group, Hash>::blind(
//!     b"input".to_vec(),
//!     &mut client_rng,
//! ).expect("Unable to construct client");
//! ```
//!
//! ### Server Evaluation
//!
//! In the second step, the server takes as input the message from
//! [NonVerifiableClient::blind] (a [BlindedElement]), and runs
//! [NonVerifiableServer::evaluate] to produce a
//! [NonVerifiableServerEvaluateResult], which consists of an
//! [EvaluationElement] to be sent to the client.
//!
//! ```
//! # type Group = curve25519_dalek::ristretto::RistrettoPoint;
//! # type Hash = sha2::Sha512;
//! # use voprf::NonVerifiableClient;
//! # use rand::{rngs::OsRng, RngCore};
//! #
//! # let mut client_rng = OsRng;
//! # let client_blind_result = NonVerifiableClient::<Group, Hash>::blind(
//! #     b"input".to_vec(),
//! #     &mut client_rng,
//! # ).expect("Unable to construct client");
//! # use voprf::NonVerifiableServer;
//! # let mut server_rng = OsRng;
//! # let server = NonVerifiableServer::<Group, Hash>::new(&mut server_rng)
//! #   .expect("Unable to construct server");
//! let server_evaluate_result = server.evaluate(
//!     client_blind_result.message,
//!     None,
//! ).expect("Unable to perform server evaluate");
//! ```
//!
//! ### Client Finalization
//!
//! In the final step, the client takes as input the message from
//! [NonVerifiableServer::evaluate] (an [EvaluationElement]), and runs
//! [NonVerifiableClient::finalize] to produce an output for the protocol.
//!
//! ```
//! # type Group = curve25519_dalek::ristretto::RistrettoPoint;
//! # type Hash = sha2::Sha512;
//! # use voprf::NonVerifiableClient;
//! # use rand::{rngs::OsRng, RngCore};
//! #
//! # let mut client_rng = OsRng;
//! # let client_blind_result = NonVerifiableClient::<Group, Hash>::blind(
//! #     b"input".to_vec(),
//! #     &mut client_rng,
//! # ).expect("Unable to construct client");
//! # use voprf::NonVerifiableServer;
//! # let mut server_rng = OsRng;
//! # let server = NonVerifiableServer::<Group, Hash>::new(&mut server_rng)
//! #   .expect("Unable to construct server");
//! # let server_evaluate_result = server.evaluate(
//! #     client_blind_result.message,
//! #     None,
//! # ).expect("Unable to perform server evaluate");
//! let client_finalize_result = client_blind_result.state.finalize(
//!     server_evaluate_result.message,
//!     None,
//! ).expect("Unable to perform client finalization");
//!
//! println!("VOPRF output: {:?}", client_finalize_result.to_vec());
//! ```
//!
//! ## Verifiable Mode
//!
//! In verifiable mode, a [VerifiableClient] interacts with a
//! [VerifiableServer] to compute the output of the VOPRF. In order to
//! verify the server's computation, the client checks a server-generated
//! proof against the server's public key. If the proof fails to verify,
//! then the client does not receive an output.
//!
//! In batch mode, a single proof can be used for multiple VOPRF evaluations.
//! See [the batching section](#batching)
//! for more details on how to perform batch evaluations.
//!
//! ### Server Setup
//!
//! The protocol begins with a setup phase, in which the server must run
//! [VerifiableServer::new()] to produce an instance of itself. This
//! instance must be persisted on the server and used for online
//! client evaluations.
//!
//! ```
//! # type Group = curve25519_dalek::ristretto::RistrettoPoint;
//! # type Hash = sha2::Sha512;
//! use voprf::VerifiableServer;
//! use rand::{rngs::OsRng, RngCore};
//!
//! let mut server_rng = OsRng;
//! let server = VerifiableServer::<Group, Hash>::new(&mut server_rng)
//!    .expect("Unable to construct server");
//!
//! // To be sent to the client
//! println!("Server public key: {:?}", server.get_public_key());
//! ```
//!
//! The public key should be sent to the client, since the client will
//! need it in the final step of the protocol in order to complete
//! the evaluation of the VOPRF.
//!
//! ### Client Blinding
//!
//! In the first step, the client chooses an input, and runs
//! [VerifiableClient::blind] to produce a [VerifiableClientBlindResult],
//! which consists of a [BlindedElement] to be sent to the server and a
//! [VerifiableClient] which must be persisted on the client for the final
//! step of the VOPRF protocol.
//!
//! ```
//! # type Group = curve25519_dalek::ristretto::RistrettoPoint;
//! # type Hash = sha2::Sha512;
//! use voprf::VerifiableClient;
//! use rand::{rngs::OsRng, RngCore};
//!
//! let mut client_rng = OsRng;
//! let client_blind_result = VerifiableClient::<Group, Hash>::blind(
//!     b"input".to_vec(),
//!     &mut client_rng,
//! ).expect("Unable to construct client");
//! ```
//!
//! ### Server Evaluation
//!
//! In the second step, the server takes as input the message from
//! [VerifiableClient::blind] (a [BlindedElement]), and runs
//! [VerifiableServer::evaluate] to produce a
//! [VerifiableServerEvaluateResult], which consists of an
//! [EvaluationElement] to be sent to the client along with a proof.
//!
//! ```
//! # type Group = curve25519_dalek::ristretto::RistrettoPoint;
//! # type Hash = sha2::Sha512;
//! # use voprf::VerifiableClient;
//! # use rand::{rngs::OsRng, RngCore};
//! #
//! # let mut client_rng = OsRng;
//! # let client_blind_result = VerifiableClient::<Group, Hash>::blind(
//! #     b"input".to_vec(),
//! #     &mut client_rng,
//! # ).expect("Unable to construct client");
//! # use voprf::VerifiableServer;
//! # let mut server_rng = OsRng;
//! # let server = VerifiableServer::<Group, Hash>::new(&mut server_rng)
//! #   .expect("Unable to construct server");
//! let server_evaluate_result = server.evaluate(
//!     &mut server_rng,
//!     client_blind_result.message,
//!     None,
//! ).expect("Unable to perform server evaluate");
//! ```
//!
//! ### Client Finalization
//!
//! In the final step, the client takes as input the message from
//! [VerifiableServer::evaluate] (an [EvaluationElement]),
//! the proof, and the server's public key, and runs
//! [VerifiableClient::finalize] to produce an output for the protocol.
//!
//! ```
//! # type Group = curve25519_dalek::ristretto::RistrettoPoint;
//! # type Hash = sha2::Sha512;
//! # use voprf::VerifiableClient;
//! # use rand::{rngs::OsRng, RngCore};
//! #
//! # let mut client_rng = OsRng;
//! # let client_blind_result = VerifiableClient::<Group, Hash>::blind(
//! #     b"input".to_vec(),
//! #     &mut client_rng,
//! # ).expect("Unable to construct client");
//! # use voprf::VerifiableServer;
//! # let mut server_rng = OsRng;
//! # let server = VerifiableServer::<Group, Hash>::new(&mut server_rng)
//! #   .expect("Unable to construct server");
//! # let server_evaluate_result = server.evaluate(
//! #     &mut server_rng,
//! #     client_blind_result.message,
//! #     None,
//! # ).expect("Unable to perform server evaluate");
//! let client_finalize_result = client_blind_result.state.finalize(
//!     server_evaluate_result.message,
//!     server_evaluate_result.proof,
//!     server.get_public_key(),
//!     None,
//! ).expect("Unable to perform client finalization");
//!
//! println!("VOPRF output: {:?}", client_finalize_result.to_vec());
//! ```
//!
//! # Advanced Usage
//!
//! There are two additional (and optional) extensions to the core VOPRF
//! protocol: support for batching of evaluations, and support for public
//! metadata.
//!
//! ## Batching
//!
//! It is sometimes desirable to generate only a single, constant-size
//! proof for an unbounded number of VOPRF evaluations (on arbitrary inputs).
//! [VerifiableClient] and [VerifiableServer] support a batch API for
//! handling this case. In the following example, we show how to use
//! the batch API to produce a single proof for 10 parallel
//! VOPRF evaluations.
//!
//! First, the client produces 10 blindings, storing their resulting
//! states and messages:
//!
//! ```
//! # type Group = curve25519_dalek::ristretto::RistrettoPoint;
//! # type Hash = sha2::Sha512;
//! # use voprf::VerifiableClient;
//! # use rand::{rngs::OsRng, RngCore};
//! #
//! let mut client_rng = OsRng;
//! let mut client_states = vec![];
//! let mut client_messages = vec![];
//! for _ in 0..10 {
//!     let client_blind_result = VerifiableClient::<Group, Hash>::blind(
//!         b"input".to_vec(),
//!         &mut client_rng,
//!     ).expect("Unable to construct client");
//!     client_states.push(client_blind_result.state);
//!     client_messages.push(client_blind_result.message);
//! }
//! ```
//!
//! Next, the server calls the [VerifiableServer::batch_evaluate]
//! function on a set of client messages, to produce a corresponding
//! set of messages to be returned to the client (returned in the same order),
//! along with a single proof:
//!
//! ```
//! # type Group = curve25519_dalek::ristretto::RistrettoPoint;
//! # type Hash = sha2::Sha512;
//! # use voprf::VerifiableClient;
//! # use rand::{rngs::OsRng, RngCore};
//! #
//! # let mut client_rng = OsRng;
//! # let mut client_states = vec![];
//! # let mut client_messages = vec![];
//! # for _ in 0..10 {
//! #     let client_blind_result = VerifiableClient::<Group, Hash>::blind(
//! #         b"input".to_vec(),
//! #        &mut client_rng,
//! #     ).expect("Unable to construct client");
//! #     client_states.push(client_blind_result.state);
//! #     client_messages.push(client_blind_result.message);
//! # }
//! # use voprf::VerifiableServer;
//! let mut server_rng = OsRng;
//! # let server = VerifiableServer::<Group, Hash>::new(&mut server_rng)
//! #   .expect("Unable to construct server");
//! let server_batch_evaluate_result = server.batch_evaluate(
//!     &mut server_rng,
//!     &client_messages,
//!     None,
//! ).expect("Unable to perform server batch evaluate");
//! ```
//!
//! Then, the client calls [VerifiableClient::batch_finalize] on
//! the client states saved from the first step, along with the messages
//! returned by the server, along with the server's proof, in order to produce
//! a vector of outputs if the proof verifies correctly.
//!
//! ```
//! # type Group = curve25519_dalek::ristretto::RistrettoPoint;
//! # type Hash = sha2::Sha512;
//! # use voprf::VerifiableClient;
//! # use rand::{rngs::OsRng, RngCore};
//! #
//! # let mut client_rng = OsRng;
//! # let mut client_states = vec![];
//! # let mut client_messages = vec![];
//! # for _ in 0..10 {
//! #     let client_blind_result = VerifiableClient::<Group, Hash>::blind(
//! #         b"input".to_vec(),
//! #        &mut client_rng,
//! #     ).expect("Unable to construct client");
//! #     client_states.push(client_blind_result.state);
//! #     client_messages.push(client_blind_result.message);
//! # }
//! # use voprf::VerifiableServer;
//! let mut server_rng = OsRng;
//! # let server = VerifiableServer::<Group, Hash>::new(&mut server_rng)
//! #   .expect("Unable to construct server");
//! # let server_batch_evaluate_result = server.batch_evaluate(
//! #     &mut server_rng,
//! #     &client_messages,
//! #     None,
//! # ).expect("Unable to perform server batch evaluate");
//! let client_batch_finalize_result = VerifiableClient::batch_finalize(
//!     &client_states,
//!     &server_batch_evaluate_result.messages,
//!     server_batch_evaluate_result.proof,
//!     server.get_public_key(),
//!     None,
//! ).expect("Unable to perform client batch finalization");
//!
//! println!("VOPRF batch outputs: {:?}", client_batch_finalize_result);
//! ```
//!
//! ## Metadata
//!
//! The optional metadata parameter included in the protocol allows clients and
//! servers (of either mode) to cryptographically bind additional data to the
//! VOPRF output. This metadata is known to both parties at the start of the protocol,
//! and is inserted under the server's evaluate step and the client's finalize step.
//! This metadata can be constructed with some type of higher-level domain separation
//! to avoid cross-protocol attacks or related issues.
//!
//! A custom metadata can be specified, for example, by: `Some(b"custom metadata")`.
//!
//! # Features
//!
//! - The `p256` feature enables using p256 as the underlying group for the [Group](group::Group) choice.
//!   Note that this is currently an experimental feature ⚠️, and is not yet ready for production use.
//!
//! - The `serde` feature, enabled by default, provides convenience functions for serializing and deserializing with
//!   [serde](https://serde.rs/).
//!
//! - The `danger` feature, disabled by default, exposes functions for setting and getting
//!   internal values not available in the default API. These functions are intended for use in
//!   by higher-level cryptographic protocols that need access to these raw values and are able to
//!   perform the necessary validations on them (such as being valid group elements).
//!
//! - The backend features are re-exported from
//!   [curve25519-dalek](https://doc.dalek.rs/curve25519_dalek/index.html#backends-and-features) and allow for selecting
//!   the corresponding backend for the curve arithmetic used. The `ristretto255_u64` feature is included as the default.
//!   Other features are mapped as `ristretto255_u32`, `ristretto255_fiat_u64` and `ristretto255_fiat_u32`.
//!
//! - The `ristretto255_simd` feature is re-exported from
//!   [curve25519-dalek](https://doc.dalek.rs/curve25519_dalek/index.html#backends-and-features) and enables parallel formulas,
//!   using either AVX2 or AVX512-IFMA. This will automatically enable the `ristretto255_u64` feature and requires Rust nightly.

#![deny(unsafe_code)]
#![no_std]
#![warn(clippy::cargo, missing_docs)]
#![allow(clippy::multiple_crate_versions)]
#![cfg_attr(docsrs, feature(doc_cfg))]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

#[macro_use]
mod util;
#[macro_use]
mod serialization;
pub mod errors;
pub mod group;
mod voprf;

#[cfg(test)]
mod tests;

// Exports

pub use crate::voprf::{
    BlindedElement, EvaluationElement, NonVerifiableClient, NonVerifiableClientBlindResult,
    NonVerifiableServer, NonVerifiableServerEvaluateResult, VerifiableClient,
    VerifiableClientBlindResult, VerifiableServer, VerifiableServerEvaluateResult,
};

// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

mod mock_rng;
mod parser;
mod voprf_test_vectors;
mod voprf_vectors;

/// Ciphersuite definitions for tests
pub(crate) struct Ristretto255Sha512;
impl crate::CipherSuite for Ristretto255Sha512 {
    type Group = curve25519_dalek::ristretto::RistrettoPoint;
    type Hash = sha2::Sha512;
}

#[cfg(feature = "p256")]
pub(crate) struct P256Sha256;
#[cfg(feature = "p256")]
impl crate::CipherSuite for P256Sha256 {
    type Group = p256_::ProjectivePoint;
    type Hash = sha2::Sha256;
}

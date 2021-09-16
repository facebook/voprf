// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! An implementation of a verifiable oblivious pseudorandom function (VOPRF)
//!
//! Note: This implementation is in sync with
//! [draft-irtf-cfrg-opaque-07](https://www.ietf.org/archive/id/draft-irtf-cfrg-opaque-07.html),
//! but this specification is subject to change, until the final version published by the IETF.
//!
//!

#![cfg_attr(not(feature = "bench"), deny(missing_docs))]
#![deny(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[macro_use]
mod serialization;

pub mod ciphersuite;
pub mod errors;
pub mod group;
pub mod hash;
pub mod voprf;

#[cfg(test)]
mod tests;

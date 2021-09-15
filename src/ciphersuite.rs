// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! Defines the CipherSuite trait to specify the underlying primitives for VOPRF

/// Configures the underlying primitives used in VOPRF
pub trait CipherSuite {
    /// A finite cyclic group along with a point representation that allows some
    /// customization on how to hash an input to a curve point. See `group::Group`.
    type Group: crate::group::Group;
    /// The main hash function to use (for HKDF computations and hashing transcripts).
    type Hash: crate::hash::Hash;
}

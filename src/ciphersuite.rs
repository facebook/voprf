// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Defines the CipherSuite trait to specify the underlying primitives for VOPRF

use digest::core_api::BlockSizeUser;
use digest::{FixedOutput, HashMarker, OutputSizeUser};
use elliptic_curve::VoprfParameters;
use generic_array::typenum::{IsLess, IsLessOrEqual, U256};

use crate::Group;

/// Configures the underlying primitives used in VOPRF
pub trait CipherSuite
where
    <Self::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<Self::Hash as BlockSizeUser>::BlockSize>,
{
    /// The ciphersuite identifier as dictated by
    /// <https://datatracker.ietf.org/doc/draft-irtf-cfrg-voprf/>
    const ID: &'static str;

    /// A finite cyclic group along with a point representation that allows some
    /// customization on how to hash an input to a curve point. See [`Group`].
    type Group: Group;

    /// The main hash function to use (for HKDF computations and hashing
    /// transcripts).
    type Hash: BlockSizeUser + Default + FixedOutput + HashMarker;
}

impl<T: VoprfParameters> CipherSuite for T
where
    T: Group,
    T::Hash: BlockSizeUser + Default + FixedOutput + HashMarker,
    <T::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<T::Hash as BlockSizeUser>::BlockSize>,
{
    const ID: &'static str = T::ID;

    type Group = T;

    type Hash = T::Hash;
}

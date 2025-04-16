// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

//! Defines the CipherSuite trait to specify the underlying primitives for VOPRF

use digest::core_api::BlockSizeUser;
use digest::{FixedOutput, HashMarker, OutputSizeUser};
use elliptic_curve::VoprfParameters;
use elliptic_curve::hash2curve::{ExpandMsg, ExpandMsgXmd};
use hybrid_array::typenum::{IsLess, IsLessOrEqual, U256, U65536};

use crate::Group;

/// Configures the underlying primitives used in VOPRF
pub trait CipherSuite
where
    <Self::Hash as OutputSizeUser>::OutputSize: IsLess<U65536>,
{
    /// The ciphersuite identifier as dictated by
    /// <https://www.rfc-editor.org/rfc/rfc9497>
    const ID: &'static str;

    /// A finite cyclic group along with a point representation that allows some
    /// customization on how to hash an input to a curve point. See [`Group`].
    type Group: Group;

    /// The main hash function to use (for HKDF computations and hashing
    /// transcripts).
    type Hash: Default + FixedOutput + HashMarker;

    /// Which function to use for `expand_message` in `HashToGroup()` and
    /// `HashToScalar()`.
    type ExpandMsg: for<'a> ExpandMsg<'a>;
}

impl<T: VoprfParameters> CipherSuite for T
where
    T: Group,
    T::Hash: BlockSizeUser + Default + FixedOutput + HashMarker,
    <T::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLess<U65536> + IsLessOrEqual<<T::Hash as BlockSizeUser>::BlockSize>,
{
    const ID: &'static str = T::ID;

    type Group = T;

    type Hash = T::Hash;

    type ExpandMsg = ExpandMsgXmd<Self::Hash>;
}

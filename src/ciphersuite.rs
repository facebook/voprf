// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! Defines the CipherSuite trait to specify the underlying primitives for VOPRF

use crate::{errors::InternalError, group::Group, hash::Hash};

static STR_VOPRF: &[u8] = b"VOPRF07-";

pub enum Mode {
    Base = 0,
    Verifiable = 1,
}

/// Configures the underlying primitives used in VOPRF
pub trait CipherSuite {
    /// A finite cyclic group along with a point representation that allows some
    /// customization on how to hash an input to a curve point. See `group::Group`.
    type Group: Group;
    /// The main hash function to use (for HKDF computations and hashing transcripts).
    type Hash: Hash;

    /// Generates the contextString parameter as defined in
    /// <https://www.ietf.org/archive/id/draft-irtf-cfrg-voprf-07.html>
    fn get_context_string(mode: Mode) -> Result<alloc::vec::Vec<u8>, InternalError> {
        use crate::serialization::i2osp;

        Ok([
            STR_VOPRF,
            &i2osp(mode as usize, 1)?,
            &i2osp(Self::Group::SUITE_ID, 2)?,
        ]
        .concat())
    }
}

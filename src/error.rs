// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Errors which are produced during an execution of the protocol

use displaydoc::Display;

/// [`Result`](core::result::Result) shorthand that uses [`Error`].
pub type Result<T, E = Error> = core::result::Result<T, E>;

/// Represents an error in the manipulation of internal cryptographic data
#[derive(Clone, Copy, Debug, Display, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Error {
    /// Size of input is empty or longer then [`u16::MAX`].
    Input,
    /// Size of info is longer then `u16::MAX - 21`.
    Info,
    /// Failure to deserialize bytes
    Deserialization,
    /// Batched items are more then [`u16::MAX`] or length don't match.
    Batch,
    /// In verifiable mode, occurs when the proof failed to verify
    ProofVerification,
    /// Size of seed is longer then [`u16::MAX`].
    Seed,
    /// The protocol has failed and can't be completed.
    Protocol,
    /// Issue with deriving a keypair
    DeriveKeyPair,
}

/// Only used to implement [`Group`](crate::Group).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum InternalError {
    /// Size of input is empty or longer then [`u16::MAX`].
    Input,
    /// `input` is longer then [`u16::MAX`].
    I2osp,
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

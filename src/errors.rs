// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! A list of error types which are produced during an execution of the protocol
use core::fmt::Debug;
#[cfg(feature = "std")]
use std::error::Error;

use displaydoc::Display;

/// Represents an error in the manipulation of internal cryptographic data
#[derive(Clone, Display, Eq, Hash, PartialEq)]
pub enum InternalError {
    /// Could not parse byte sequence for key
    InvalidByteSequence,
    /// Invalid length for {name}: expected {len}, but is actually {actual_len}.
    SizeError {
        /// name
        name: &'static str,
        /// length
        len: usize,
        /// actual
        actual_len: usize,
    },
    /// Could not decompress point.
    PointError,
    /// Computing the hash-to-curve function failed
    HashToCurveError,
    /// Failure to serialize or deserialize bytes
    SerializationError,
}

impl Debug for InternalError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidByteSequence => f.debug_tuple("InvalidByteSequence").finish(),
            Self::SizeError {
                name,
                len,
                actual_len,
            } => f
                .debug_struct("SizeError")
                .field("name", name)
                .field("len", len)
                .field("actual_len", actual_len)
                .finish(),
            Self::PointError => f.debug_tuple("PointError").finish(),
            Self::HashToCurveError => f.debug_tuple("HashToCurveError").finish(),
            Self::SerializationError => f.debug_tuple("SerializationError").finish(),
        }
    }
}

#[cfg(feature = "std")]
impl Error for InternalError {}

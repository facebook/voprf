// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

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
    /// Could not deserialize element, or deserialized to the identity element
    PointError,
    /// Computing the hash-to-curve function failed
    HashToCurveError,
    /// Failure to serialize or deserialize bytes
    SerializationError,
    /// Use of incompatible modes (base vs. verifiable)
    IncompatibleModeError,
    /**
     * Internal error thrown when different-lengthed slices are supplied
     * to the compute_composites() function.
     */
    MismatchedLengthsForCompositeInputs,
    /// In verifiable mode, occurs when the proof failed to verify
    ProofVerificationError,
    /// Encountered insufficient bytes when attempting to deserialize
    SizeError,
    /// Encountered a zero scalar
    ZeroScalarError,
}

impl Debug for InternalError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidByteSequence => f.debug_tuple("InvalidByteSequence").finish(),
            Self::PointError => f.debug_tuple("PointError").finish(),
            Self::HashToCurveError => f.debug_tuple("HashToCurveError").finish(),
            Self::SerializationError => f.debug_tuple("SerializationError").finish(),
            Self::IncompatibleModeError => f.debug_tuple("IncompatibleModeError").finish(),
            Self::MismatchedLengthsForCompositeInputs => f
                .debug_tuple("MismatchedLengthsForCompositeInputs")
                .finish(),
            Self::ProofVerificationError => f.debug_tuple("ProofVerificationError").finish(),
            Self::SizeError => f.debug_tuple("SizeError").finish(),
            Self::ZeroScalarError => f.debug_tuple("ZeroScalarError").finish(),
        }
    }
}

#[cfg(feature = "std")]
impl Error for InternalError {}

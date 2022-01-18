// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Errors which are produced during an execution of the protocol

use displaydoc::Display;

/// [`Result`](core::result::Result) shorthand that uses [`Error`].
pub type Result<T> = core::result::Result<T, Error>;

/// Represents an error in the manipulation of internal cryptographic data
#[derive(Clone, Copy, Debug, Display, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Error {
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
    /// Encountered an invalid scalar
    ScalarError,
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

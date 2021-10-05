// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Includes a series of tests for the group implementations

use crate::errors::InternalError;
use crate::group::Group;

// Test that the deserialization of a group element should throw an error
// if the identity element can be deserialized properly

#[test]
fn test_group_properties() -> Result<(), InternalError> {
    use curve25519_dalek::ristretto::RistrettoPoint;

    test_identity_element_error::<RistrettoPoint>()?;
    test_zero_scalar_error::<RistrettoPoint>()?;

    #[cfg(feature = "p256")]
    {
        use p256_::ProjectivePoint;

        test_identity_element_error::<ProjectivePoint>()?;
        test_zero_scalar_error::<ProjectivePoint>()?;
    }

    Ok(())
}

// Checks that the identity element cannot be deserialized
fn test_identity_element_error<G: Group>() -> Result<(), InternalError> {
    let identity = G::identity();
    let result = G::from_element_slice(&identity.to_arr());
    assert!(matches!(result, Err(InternalError::PointError)));

    Ok(())
}

// Checks that the zero scalar cannot be deserialized
fn test_zero_scalar_error<G: Group>() -> Result<(), InternalError> {
    let zero_scalar = G::scalar_zero();
    let result = G::from_scalar_slice(&G::scalar_as_bytes(zero_scalar));
    assert!(matches!(result, Err(InternalError::ZeroScalarError)));

    Ok(())
}

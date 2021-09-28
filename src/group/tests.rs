// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Includes a series of tests for the group implementations

use crate::errors::InternalError;
use crate::group::Group;
use crate::CipherSuite;

// Test that the deserialization of a group element should throw an error
// if the identity element can be deserialized properly

#[test]
fn test_group_properties() -> Result<(), InternalError> {
    use crate::tests::Ristretto255Sha512;

    test_identity_element_error::<Ristretto255Sha512>()?;
    test_zero_scalar_error::<Ristretto255Sha512>()?;

    #[cfg(feature = "p256")]
    {
        use crate::tests::P256Sha256;

        test_identity_element_error::<P256Sha256>()?;
        test_zero_scalar_error::<P256Sha256>()?;
    }

    Ok(())
}

// Checks that the identity element cannot be deserialized
fn test_identity_element_error<CS: CipherSuite>() -> Result<(), InternalError> {
    let identity = CS::Group::identity();
    let result = CS::Group::from_element_slice(&identity.to_arr());
    assert!(match result {
        Err(InternalError::PointError) => true,
        _ => false,
    });

    Ok(())
}

// Checks that the zero scalar cannot be deserialized
fn test_zero_scalar_error<CS: CipherSuite>() -> Result<(), InternalError> {
    let zero_scalar = CS::Group::scalar_zero();
    let result = CS::Group::from_scalar_slice(&CS::Group::scalar_as_bytes(zero_scalar));
    assert!(match result {
        Err(InternalError::ZeroScalarError) => true,
        _ => false,
    });

    Ok(())
}

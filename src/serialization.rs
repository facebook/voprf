// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::errors::InternalError;
use alloc::vec::Vec;

// Corresponds to the I2OSP() function from RFC8017
pub(crate) fn i2osp(input: usize, length: usize) -> Result<alloc::vec::Vec<u8>, InternalError> {
    let sizeof_usize = core::mem::size_of::<usize>();

    // Check if input >= 256^length
    if (sizeof_usize as u32 - input.leading_zeros() / 8) > length as u32 {
        return Err(InternalError::SerializationError);
    }

    if length <= sizeof_usize {
        return Ok((&input.to_be_bytes()[sizeof_usize - length..]).to_vec());
    }

    let mut output = alloc::vec![0u8; length];
    output.splice(
        length - sizeof_usize..length,
        input.to_be_bytes().iter().cloned(),
    );
    Ok(output)
}

// Computes I2OSP(len(input), max_bytes) || input
pub(crate) fn serialize(input: &[u8], max_bytes: usize) -> Result<Vec<u8>, InternalError> {
    Ok([&i2osp(input.len(), max_bytes)?, input].concat())
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    // Test the error condition for I2OSP
    #[test]
    fn test_i2osp_err_check() {
        assert!(i2osp(0, 1).is_ok());

        assert!(i2osp(255, 1).is_ok());
        assert!(i2osp(256, 1).is_err());
        assert!(i2osp(257, 1).is_err());

        assert!(i2osp(256 * 256 - 1, 2).is_ok());
        assert!(i2osp(256 * 256, 2).is_err());
        assert!(i2osp(256 * 256 + 1, 2).is_err());
    }
}

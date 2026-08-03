// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

use alloc::vec::Vec;
use core::cmp::min;
use rand_core::{TryCryptoRng, TryRng};

/// A simple implementation of `Rng` for testing purposes.
///
/// This generates a cyclic sequence (i.e. cycles over an initial buffer)
#[derive(Debug, Clone)]
pub struct CycleRng {
    v: Vec<u8>,
}

impl CycleRng {
    /// Create a `CycleRng`, yielding a sequence starting with `initial` and
    /// looping thereafter
    pub fn new(initial: Vec<u8>) -> Self {
        CycleRng { v: initial }
    }
}

fn rotate_left<T>(data: &mut [T], steps: usize) {
    if data.is_empty() {
        return;
    }
    let steps = steps % data.len();

    data[..steps].reverse();
    data[steps..].reverse();
    data.reverse();
}


impl TryRng for CycleRng {
    type Error = core::convert::Infallible;

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        let len = min(self.v.len(), dest.len());
        dest[..len].copy_from_slice(&self.v[..len]);
        rotate_left(&mut self.v, len);
        Ok(())
    }

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        unimplemented!()
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        unimplemented!()
    }
}

impl TryCryptoRng for CycleRng {}

// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use core::convert::TryFrom;

use digest::core_api::{Block, BlockSizeUser};
use digest::{Digest, FixedOutputReset};
use generic_array::typenum::{IsLess, NonZero, Unsigned, U65536};
use generic_array::{ArrayLength, GenericArray};

use crate::{Error, Result};

fn xor<L: ArrayLength<u8>>(x: GenericArray<u8, L>, y: GenericArray<u8, L>) -> GenericArray<u8, L> {
    x.into_iter().zip(y).map(|(x1, x2)| x1 ^ x2).collect()
}

/// Corresponds to the expand_message_xmd() function defined in
/// <https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-10.txt>
pub fn expand_message_xmd<H: BlockSizeUser + Digest + FixedOutputReset, L: ArrayLength<u8>>(
    msg: &[&[u8]],
    dst: &[u8],
) -> Result<GenericArray<u8, L>>
where
    // Constraint set by `expand_message_xmd`:
    // https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-13.html#section-5.4.1-6
    L: NonZero + IsLess<U65536>,
{
    // DST, a byte string of at most 255 bytes.
    let dst_len = u8::try_from(dst.len()).map_err(|_| Error::HashToCurveError)?;

    // b_in_bytes, b / 8 for b the output size of H in bits.
    let b_in_bytes = H::OutputSize::to_usize();

    // Constraint set by `expand_message_xmd`:
    // https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-13.html#section-5.4.1-4
    if b_in_bytes > H::BlockSize::USIZE {
        return Err(Error::HashToCurveError);
    }

    // ell = ceil(len_in_bytes / b_in_bytes)
    // ABORT if ell > 255
    let ell = u8::try_from((L::USIZE + b_in_bytes - 1) / b_in_bytes)
        .map_err(|_| Error::HashToCurveError)?;

    let mut hash = H::new();

    // b_0 = H(msg_prime)
    // msg_prime = Z_pad || msg || l_i_b_str || I2OSP(0, 1) || DST_prime
    // Z_pad = I2OSP(0, s_in_bytes)
    // s_in_bytes, the input block size of H, measured in bytes
    Digest::update(&mut hash, Block::<H>::default());
    for msg in msg {
        Digest::update(&mut hash, msg);
    }
    // l_i_b_str = I2OSP(len_in_bytes, 2)
    Digest::update(&mut hash, L::U16.to_be_bytes());
    Digest::update(&mut hash, [0]);
    // DST_prime = DST || I2OSP(len(DST), 1)
    Digest::update(&mut hash, dst);
    Digest::update(&mut hash, [dst_len]);
    let b_0 = hash.finalize_reset();

    let mut b_i = GenericArray::default();

    let mut uniform_bytes = GenericArray::default();

    // b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
    // for i in (2, ..., ell):
    for (i, chunk) in (1..(ell + 1)).zip(uniform_bytes.chunks_mut(b_in_bytes)) {
        // b_i = H(strxor(b_0, b_(i - 1)) || I2OSP(i, 1) || DST_prime)
        Digest::update(&mut hash, xor(b_0.clone(), b_i.clone()));
        Digest::update(&mut hash, [i]);
        // DST_prime = DST || I2OSP(len(DST), 1)
        Digest::update(&mut hash, dst);
        Digest::update(&mut hash, [dst_len]);
        b_i = hash.finalize_reset();
        // uniform_bytes = b_1 || ... || b_ell
        // return substr(uniform_bytes, 0, len_in_bytes)
        chunk.copy_from_slice(&b_i[..b_in_bytes.min(chunk.len())]);
    }

    Ok(uniform_bytes)
}

#[cfg(test)]
mod tests {
    use generic_array::typenum::{U128, U32};

    struct Params {
        msg: &'static str,
        len_in_bytes: usize,
        uniform_bytes: &'static str,
    }

    #[test]
    fn test_expand_message_xmd() {
        const DST: [u8; 27] = *b"QUUX-V01-CS02-with-expander";

        // Test vectors taken from Section K.1 of https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-10.txt
        let test_vectors: alloc::vec::Vec<Params> = alloc::vec![
            Params {
                msg: "",
                len_in_bytes: 0x20,
                uniform_bytes: "f659819a6473c1835b25ea59e3d38914c98b374f0970b7e4c\
                92181df928fca88",
            },
            Params {
                msg: "abc",
                len_in_bytes: 0x20,
                uniform_bytes: "1c38f7c211ef233367b2420d04798fa4698080a8901021a79\
                5a1151775fe4da7",
            },
            Params {
                msg: "abcdef0123456789",
                len_in_bytes: 0x20,
                uniform_bytes: "8f7e7b66791f0da0dbb5ec7c22ec637f79758c0a48170bfb7c4611bd304ece89",
            },
            Params {
                msg: "q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq\
                qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq\
                qqqqqqqqqqqqqqqqqqqqqqqqq",
                len_in_bytes: 0x20,
                uniform_bytes: "72d5aa5ec810370d1f0013c0df2f1d65699494ee2a39f72e\
                1716b1b964e1c642",
            },
            Params {
                msg: "a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                len_in_bytes: 0x20,
                uniform_bytes: "3b8e704fc48336aca4c2a12195b720882f2162a4b7b13a9c\
                350db46f429b771b",
            },
            Params {
                msg: "",
                len_in_bytes: 0x80,
                uniform_bytes: "8bcffd1a3cae24cf9cd7ab85628fd111bb17e3739d3b53f8\
                9580d217aa79526f1708354a76a402d3569d6a9d19ef3de4d0b991\
                e4f54b9f20dcde9b95a66824cbdf6c1a963a1913d43fd7ac443a02\
                fc5d9d8d77e2071b86ab114a9f34150954a7531da568a1ea8c7608\
                61c0cde2005afc2c114042ee7b5848f5303f0611cf297f",
            },
            Params {
                msg: "abc",
                len_in_bytes: 0x80,
                uniform_bytes: "fe994ec51bdaa821598047b3121c149b364b178606d5e72b\
                fbb713933acc29c186f316baecf7ea22212f2496ef3f785a27e84a\
                40d8b299cec56032763eceeff4c61bd1fe65ed81decafff4a31d01\
                98619c0aa0c6c51fca15520789925e813dcfd318b542f879944127\
                1f4db9ee3b8092a7a2e8d5b75b73e28fb1ab6b4573c192",
            },
            Params {
                msg: "abcdef0123456789",
                len_in_bytes: 0x80,
                uniform_bytes: "c9ec7941811b1e19ce98e21db28d22259354d4d0643e3011\
                75e2f474e030d32694e9dd5520dde93f3600d8edad94e5c3649030\
                88a7228cc9eff685d7eaac50d5a5a8229d083b51de4ccc3733917f\
                4b9535a819b445814890b7029b5de805bf62b33a4dc7e24acdf2c9\
                24e9fe50d55a6b832c8c84c7f82474b34e48c6d43867be",
            },
            Params {
                msg: "q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq\
                qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq\
                qqqqqqqqqqqqqqqqqqqqqqqqq",
                len_in_bytes: 0x80,
                uniform_bytes: "48e256ddba722053ba462b2b93351fc966026e6d6db49318\
                9798181c5f3feea377b5a6f1d8368d7453faef715f9aecb078cd40\
                2cbd548c0e179c4ed1e4c7e5b048e0a39d31817b5b24f50db58bb3\
                720fe96ba53db947842120a068816ac05c159bb5266c63658b4f00\
                0cbf87b1209a225def8ef1dca917bcda79a1e42acd8069",
            },
            Params {
                msg: "a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                len_in_bytes: 0x80,
                uniform_bytes: "396962db47f749ec3b5042ce2452b619607f27fd3939ece2\
                746a7614fb83a1d097f554df3927b084e55de92c7871430d6b95c2\
                a13896d8a33bc48587b1f66d21b128a1a8240d5b0c26dfe795a1a8\
                42a0807bb148b77c2ef82ed4b6c9f7fcb732e7f94466c8b51e52bf\
                378fba044a31f5cb44583a892f5969dcd73b3fa128816e",
            },
        ];

        for tv in test_vectors {
            let uniform_bytes = match tv.len_in_bytes {
                32 => super::expand_message_xmd::<sha2::Sha256, U32>(&[tv.msg.as_bytes()], &DST)
                    .map(|bytes| bytes.to_vec()),
                128 => super::expand_message_xmd::<sha2::Sha256, U128>(&[tv.msg.as_bytes()], &DST)
                    .map(|bytes| bytes.to_vec()),
                _ => unimplemented!(),
            }
            .unwrap();
            assert_eq!(tv.uniform_bytes, hex::encode(uniform_bytes));
        }
    }
}

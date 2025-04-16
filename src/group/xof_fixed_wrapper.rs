//! See <https://github.com/RustCrypto/traits/issues/1094>.

use core::marker::PhantomData;

use digest::core_api::BlockSizeUser;
use digest::{ExtendableOutput, FixedOutput, HashMarker, Output, OutputSizeUser, Update};
use hybrid_array::ArraySize;

#[derive(Debug, Default)]
pub struct XofFixedWrapper<T, O: ArraySize> {
    hash: T,
    size: PhantomData<O>,
}

impl<T: BlockSizeUser, O: ArraySize> BlockSizeUser for XofFixedWrapper<T, O> {
    type BlockSize = T::BlockSize;
}

impl<T: ExtendableOutput, O: ArraySize> ExtendableOutput for XofFixedWrapper<T, O> {
    type Reader = T::Reader;

    fn finalize_xof(self) -> Self::Reader {
        self.hash.finalize_xof()
    }
}

impl<T: ExtendableOutput, O: ArraySize> FixedOutput for XofFixedWrapper<T, O> {
    fn finalize_into(self, out: &mut Output<Self>) {
        self.hash.finalize_xof_into(out);
    }
}

impl<T, O: ArraySize> HashMarker for XofFixedWrapper<T, O> {}

impl<T, O: ArraySize> OutputSizeUser for XofFixedWrapper<T, O> {
    type OutputSize = O;
}

impl<T: Update, O: ArraySize> Update for XofFixedWrapper<T, O> {
    fn update(&mut self, data: &[u8]) {
        self.hash.update(data);
    }
}

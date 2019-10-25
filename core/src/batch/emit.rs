use super::{Batch, Disposition};
use crate::packets::Packet;

/// A batch that short-circuits the remainder of the pipeline and marks
/// all packets for transmit.
pub struct Emit<B: Batch> {
    batch: B,
}

impl<B: Batch> Emit<B> {
    #[inline]
    pub fn new(batch: B) -> Self {
        Emit { batch }
    }
}

impl<B: Batch> Batch for Emit<B> {
    type Item = B::Item;

    #[inline]
    fn replenish(&mut self) {
        self.batch.replenish();
    }

    #[inline]
    fn next(&mut self) -> Option<Disposition<Self::Item>> {
        self.batch
            .next()
            .map(|disp| disp.map(|pkt| Disposition::Emit(pkt.reset())))
    }
}

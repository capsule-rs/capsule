use super::{Batch, Disposition};
use crate::packets::Packet;
use crate::Result;

/// A batch that replaces each packet of the batch with another packet.
///
/// The original packet is dropped from the batch with the new packet in its
/// place. On error, the packet is `aborted` and will short-circuit the
/// remainder of the pipeline.
pub struct Replace<B: Batch, T: Packet, F>
where
    F: FnMut(&B::Item) -> Result<T>,
{
    batch: B,
    f: F,
    slot: Option<B::Item>,
}

impl<B: Batch, T: Packet, F> Replace<B, T, F>
where
    F: FnMut(&B::Item) -> Result<T>,
{
    #[inline]
    pub fn new(batch: B, f: F) -> Self {
        Replace {
            batch,
            f,
            slot: None,
        }
    }
}

impl<B: Batch, T: Packet, F> Batch for Replace<B, T, F>
where
    F: FnMut(&B::Item) -> Result<T>,
{
    type Item = T;

    #[inline]
    fn replenish(&mut self) {
        self.batch.replenish();
    }

    #[inline]
    fn next(&mut self) -> Option<Disposition<Self::Item>> {
        // internally the replace combinator will add a new packet to the
        // batch and mark the original as dropped. each packet in the
        // batch could become 2.
        if let Some(pkt) = self.slot.take() {
            // has a packet in the temp slot. marks it as dropped.
            Some(Disposition::Drop(pkt.reset()))
        } else {
            // nothing in the slot, fetches a new packet from source.
            self.batch.next().map(|disp| {
                disp.map(|orig| {
                    match (self.f)(&orig) {
                        Ok(new) => {
                            // keeps the original in the temp slot, we will mark it dropped
                            // in the interation immediately follows.
                            self.slot.replace(orig);
                            Disposition::Act(new)
                        }
                        Err(e) => Disposition::Abort(e),
                    }
                })
            })
        }
    }
}

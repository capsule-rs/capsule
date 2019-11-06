use super::{Batch, Disposition};
use crate::packets::Packet;

/// A batch that filters the packets of the underlying batch.
///
/// If the predicate evaluates to `false`, the packet is marked as dropped
/// and will short-circuit the remainder of the pipeline.
pub struct Filter<B: Batch, P>
where
    P: FnMut(&B::Item) -> bool,
{
    batch: B,
    predicate: P,
}

impl<B: Batch, P> Filter<B, P>
where
    P: FnMut(&B::Item) -> bool,
{
    #[inline]
    pub fn new(batch: B, predicate: P) -> Self {
        Filter { batch, predicate }
    }
}

impl<B: Batch, P> Batch for Filter<B, P>
where
    P: FnMut(&B::Item) -> bool,
{
    type Item = B::Item;

    #[inline]
    fn replenish(&mut self) {
        self.batch.replenish();
    }

    #[inline]
    fn next(&mut self) -> Option<Disposition<Self::Item>> {
        self.batch.next().map(|disp| {
            disp.map(|pkt| {
                if (self.predicate)(&pkt) {
                    Disposition::Act(pkt)
                } else {
                    Disposition::Drop(pkt.reset())
                }
            })
        })
    }
}

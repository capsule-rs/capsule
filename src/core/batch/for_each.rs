use super::{Batch, Disposition};
use crate::packets::Packet;
use crate::Result;

/// A batch that calls a closure on packets in the underlying batch.
pub struct ForEach<B: Batch, F>
where
    F: FnMut(&B::Item) -> Result<()>,
{
    batch: B,
    f: F,
}

impl<B: Batch, F> ForEach<B, F>
where
    F: FnMut(&B::Item) -> Result<()>,
{
    #[inline]
    pub fn new(batch: B, f: F) -> Self {
        ForEach { batch, f }
    }
}

impl<B: Batch, F> Batch for ForEach<B, F>
where
    F: FnMut(&B::Item) -> Result<()>,
{
    type Item = B::Item;

    #[inline]
    fn replenish(&mut self) {
        self.batch.replenish();
    }

    #[inline]
    fn next(&mut self) -> Option<Disposition<Self::Item>> {
        self.batch.next().map(|disp| {
            disp.map(|pkt| match (self.f)(&pkt) {
                Ok(_) => Disposition::Act(pkt),
                Err(e) => Disposition::Abort(pkt.reset(), e),
            })
        })
    }
}

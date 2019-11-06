use super::{Batch, Disposition};
use crate::packets::Packet;
use crate::Result;

/// A batch that maps the packets of the underlying batch.
///
/// On error, the packet is marked as `aborted` and will short-circuit the
/// remainder of the pipeline.
pub struct Map<B: Batch, T: Packet, F>
where
    F: FnMut(B::Item) -> Result<T>,
{
    batch: B,
    f: F,
}

impl<B: Batch, T: Packet, F> Map<B, T, F>
where
    F: FnMut(B::Item) -> Result<T>,
{
    #[inline]
    pub fn new(batch: B, f: F) -> Self {
        Map { batch, f }
    }
}

impl<B: Batch, T: Packet, F> Batch for Map<B, T, F>
where
    F: FnMut(B::Item) -> Result<T>,
{
    type Item = T;

    #[inline]
    fn replenish(&mut self) {
        self.batch.replenish();
    }

    #[inline]
    fn next(&mut self) -> Option<Disposition<Self::Item>> {
        self.batch.next().map(|disp| {
            disp.map(|orig| match (self.f)(orig) {
                Ok(new) => Disposition::Act(new),
                Err(e) => Disposition::Abort(e),
            })
        })
    }
}

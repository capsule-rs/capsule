use super::{Batch, Disposition};
use crate::packets::Packet;
use crate::{Mbuf, Result};

/// The outcome of the filter map.
pub enum Outcome<T> {
    /// Keeps the packet as mapped result.
    Keep(T),

    /// Drops the packet.
    Drop(Mbuf),
}

/// A batch that both filters and maps the packets of the underlying batch.
///
/// If the closure returns `Drop`, the packet is marked as dropped. On
/// error, the packet is marked as aborted. In both scenarios, it will
/// short-circuit the remainder of the pipeline.
pub struct FilterMap<B: Batch, T: Packet, F>
where
    F: FnMut(B::Item) -> Result<Outcome<T>>,
{
    batch: B,
    f: F,
}

impl<B: Batch, T: Packet, F> FilterMap<B, T, F>
where
    F: FnMut(B::Item) -> Result<Outcome<T>>,
{
    #[inline]
    pub fn new(batch: B, f: F) -> Self {
        FilterMap { batch, f }
    }
}

impl<B: Batch, T: Packet, F> Batch for FilterMap<B, T, F>
where
    F: FnMut(B::Item) -> Result<Outcome<T>>,
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
                Ok(Outcome::Keep(new)) => Disposition::Act(new),
                Ok(Outcome::Drop(mbuf)) => Disposition::Drop(mbuf),
                Err(e) => Disposition::Abort(e),
            })
        })
    }
}

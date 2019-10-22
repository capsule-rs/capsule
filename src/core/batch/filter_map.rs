use super::{Batch, Disposition};
use crate::packets::Packet;
use crate::Result;

/// A batch that both filters and maps the packets of the underlying batch.
///
/// If the closure returns `None`, the packet is marked as dropped. On
/// error, the packet is marked as aborted. In both scenarios, it will
/// short-circuit the remainder of the pipeline.
pub struct FilterMap<B: Batch, T: Packet, F>
where
    F: FnMut(B::Item) -> Result<Option<T>>,
{
    batch: B,
    f: F,
}

impl<B: Batch, T: Packet, F> FilterMap<B, T, F>
where
    F: FnMut(B::Item) -> Result<Option<T>>,
{
    #[inline]
    pub fn new(batch: B, f: F) -> Self {
        FilterMap { batch, f }
    }
}

impl<B: Batch, T: Packet, F> Batch for FilterMap<B, T, F>
where
    F: FnMut(B::Item) -> Result<Option<T>>,
{
    type Item = T;

    #[inline]
    fn replenish(&mut self) {
        self.batch.replenish();
    }

    #[inline]
    fn next(&mut self) -> Option<Disposition<Self::Item>> {
        self.batch.next().map(|disp| {
            disp.map(|orig| {
                let mbuf = orig.mbuf().clone();

                match (self.f)(orig) {
                    Ok(Some(new)) => {
                        std::mem::forget(mbuf);
                        Disposition::Act(new)
                    }
                    Ok(None) => Disposition::Drop(mbuf),
                    Err(e) => Disposition::Abort(mbuf, e),
                }
            })
        })
    }
}

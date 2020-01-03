use super::{Batch, Disposition};

/// A batch that calls a closure on packets in the underlying batch.
pub struct Inspect<B: Batch, F>
where
    F: FnMut(&Disposition<B::Item>),
{
    batch: B,
    f: F,
}

impl<B: Batch, F> Inspect<B, F>
where
    F: FnMut(&Disposition<B::Item>),
{
    #[inline]
    pub fn new(batch: B, f: F) -> Self {
        Inspect { batch, f }
    }
}

impl<B: Batch, F> Batch for Inspect<B, F>
where
    F: FnMut(&Disposition<B::Item>),
{
    type Item = B::Item;

    #[inline]
    fn replenish(&mut self) {
        self.batch.replenish();
    }

    #[inline]
    fn next(&mut self) -> Option<Disposition<Self::Item>> {
        self.batch.next().map(|disp| {
            (self.f)(&disp);
            disp
        })
    }
}

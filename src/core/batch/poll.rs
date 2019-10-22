use super::{Batch, Disposition, PacketRx};
use crate::Mbuf;
use std::collections::VecDeque;

/// A batch that polls a receiving source for new packets.
///
/// This marks the beginning of the pipeline.
pub struct Poll<Rx: PacketRx> {
    rx: Rx,
    packets: Option<VecDeque<Mbuf>>,
}

impl<Rx: PacketRx> Poll<Rx> {
    /// Creates a new `Poll` batch.
    #[inline]
    pub fn new(rx: Rx) -> Self {
        Poll { rx, packets: None }
    }
}

impl<Rx: PacketRx> Batch for Poll<Rx> {
    type Item = Mbuf;

    /// Replenishes the batch with new packets from the RX source.
    ///
    /// If there are still packets left in the current queue, they are lost.
    #[inline]
    fn replenish(&mut self) {
        // `VecDeque` is not the ideal structure here. We are relying on the
        // conversion from `Vec` to `VecDeque` to be allocation-free. but
        // unfortunately that's not always the case. We need an efficient and
        // allocation-free data structure with pop semantic.
        self.packets = Some(self.rx.receive().into());
    }

    #[inline]
    fn next(&mut self) -> Option<Disposition<Self::Item>> {
        if let Some(q) = self.packets.as_mut() {
            q.pop_front().map(Disposition::Act)
        } else {
            None
        }
    }
}

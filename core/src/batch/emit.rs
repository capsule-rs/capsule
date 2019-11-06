use super::{Batch, Disposition, PacketTx};
use crate::packets::Packet;

/// A batch that transmits the packets through the specified `PacketTx`.
pub struct Emit<B: Batch, Tx: PacketTx> {
    batch: B,
    tx: Tx,
}

impl<B: Batch, Tx: PacketTx> Emit<B, Tx> {
    #[inline]
    pub fn new(batch: B, tx: Tx) -> Self {
        Emit { batch, tx }
    }
}

impl<B: Batch, Tx: PacketTx> Batch for Emit<B, Tx> {
    type Item = B::Item;

    #[inline]
    fn replenish(&mut self) {
        self.batch.replenish();
    }

    #[inline]
    fn next(&mut self) -> Option<Disposition<Self::Item>> {
        self.batch.next().map(|disp| {
            disp.map(|pkt| {
                self.tx.transmit(vec![pkt.reset()]);
                Disposition::Emit
            })
        })
    }
}

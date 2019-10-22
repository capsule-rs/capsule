use super::{Batch, Disposition, PacketTx};
use crate::packets::Packet;
use crate::Mbuf;

/// Turns the batch pipeline into an executable task.
pub struct Send<B: Batch, Tx: PacketTx> {
    batch: B,
    tx: Tx,
}

impl<B: Batch, Tx: PacketTx> Send<B, Tx> {
    #[inline]
    pub fn new(batch: B, tx: Tx) -> Self {
        Send { batch, tx }
    }

    pub fn execute(&mut self) {
        // let's get a new batch
        self.batch.replenish();

        let mut transmit_q = Vec::with_capacity(64);
        let mut drop_q = Vec::with_capacity(64);

        // consume the whole batch to completion
        while let Some(disp) = self.batch.next() {
            match disp {
                Disposition::Act(packet) => transmit_q.push(packet.reset()),
                Disposition::Emit(mbuf) => transmit_q.push(mbuf),
                Disposition::Drop(mbuf) => drop_q.push(mbuf),
                Disposition::Abort(mbuf, err) => {
                    trace!(?err);
                    drop_q.push(mbuf);
                }
            }
        }

        if !transmit_q.is_empty() {
            self.tx.transmit(transmit_q);
        }

        if !drop_q.is_empty() {
            Mbuf::free_bulk(drop_q);
        }
    }
}

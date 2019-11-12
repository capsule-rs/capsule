use super::{Batch, Disposition, PacketTx, Pipeline};
use crate::packets::Packet;
use crate::Mbuf;
use futures::{future, Future};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio_executor::current_thread;

/// Turns the batch pipeline into an executable task.
pub struct Send<B: Batch, Tx: PacketTx> {
    name: String,
    batch: B,
    tx: Tx,
}

impl<B: Batch, Tx: PacketTx> Send<B, Tx> {
    #[inline]
    pub fn new(name: String, batch: B, tx: Tx) -> Self {
        Send { name, batch, tx }
    }

    fn run(&mut self) {
        // let's get a new batch
        self.batch.replenish();

        let mut transmit_q = Vec::with_capacity(64);
        let mut drop_q = Vec::with_capacity(64);

        // consume the whole batch to completion
        while let Some(disp) = self.batch.next() {
            match disp {
                Disposition::Act(packet) => transmit_q.push(packet.reset()),
                Disposition::Drop(mbuf) => drop_q.push(mbuf),
                // nothing to do for abort and emit.
                _ => (),
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

/// By implementing the `Future` trait, `Send` can be spawned onto the tokio
/// executor. Each time the future is polled, it processes one batch of
/// packets before returning the `Poll::Pending` status and yields.
impl<B: Batch + Unpin, Tx: PacketTx + Unpin> Future for Send<B, Tx> {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        // executes a batch of packets.
        self.get_mut().run();

        // now schedules the waker as a future and yields the core so other
        // futures have a chance to run.
        let waker = cx.waker().clone();
        current_thread::spawn(future::lazy(|_| waker.wake()));

        Poll::Pending
    }
}

impl<B: Batch + Unpin, Tx: PacketTx + Unpin> Pipeline for Send<B, Tx> {
    #[inline]
    fn name(&self) -> &str {
        &self.name
    }

    #[inline]
    fn run_once(&mut self) {
        self.run()
    }
}

use super::{Batch, Disposition, PacketTx, Pipeline};
#[cfg(feature = "metrics")]
use crate::metrics::{labels, Counter, SINK};
use crate::packets::Packet;
use crate::Mbuf;
use futures::{future, Future};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio_executor::current_thread;

/// Creates a new pipeline counter.
#[cfg(feature = "metrics")]
fn new_counter(name: &'static str, pipeline: &str) -> Counter {
    SINK.scoped("pipeline").counter_with_labels(
        name,
        labels!(
            "pipeline" => pipeline.to_owned(),
        ),
    )
}

/// Turns the batch pipeline into an executable task.
pub struct Send<B: Batch, Tx: PacketTx> {
    name: String,
    batch: B,
    tx: Tx,
    #[cfg(feature = "metrics")]
    processed: Counter,
    #[cfg(feature = "metrics")]
    dropped: Counter,
    #[cfg(feature = "metrics")]
    errors: Counter,
}

impl<B: Batch, Tx: PacketTx> Send<B, Tx> {
    #[cfg(not(feature = "metrics"))]
    #[inline]
    pub fn new(name: String, batch: B, tx: Tx) -> Self {
        Send { name, batch, tx }
    }

    #[cfg(feature = "metrics")]
    #[inline]
    pub fn new(name: String, batch: B, tx: Tx) -> Self {
        let processed = new_counter("processed", &name);
        let dropped = new_counter("dropped", &name);
        let errors = new_counter("errors", &name);
        Send {
            name,
            batch,
            tx,
            processed,
            dropped,
            errors,
        }
    }

    fn run(&mut self) {
        // let's get a new batch
        self.batch.replenish();

        let mut transmit_q = Vec::with_capacity(64);
        let mut drop_q = Vec::with_capacity(64);
        let mut emitted = 0u64;
        let mut aborted = 0u64;

        // consume the whole batch to completion
        while let Some(disp) = self.batch.next() {
            match disp {
                Disposition::Act(packet) => transmit_q.push(packet.reset()),
                Disposition::Drop(mbuf) => drop_q.push(mbuf),
                Disposition::Emit => emitted += 1,
                Disposition::Abort(_) => aborted += 1,
            }
        }

        #[cfg(feature = "metrics")]
        {
            self.processed.record(transmit_q.len() as u64 + emitted);
            self.dropped.record(drop_q.len() as u64);
            self.errors.record(aborted);
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

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
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

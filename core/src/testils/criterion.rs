use super::Rvg;
use crate::batch::PacketTx;
use crate::{Batch, Mbuf, Poll};
use criterion::{black_box, Bencher};
use proptest::strategy::Strategy;
use std::cmp;
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

pub trait BencherExt {
    fn iter_proptest_batched<R, S, O>(&mut self, strategy: S, routine: R, batch_size: usize)
    where
        R: FnMut(S::Value) -> O,
        S: Strategy;

    fn iter_proptest_combinators<R, S, O>(&mut self, strategy: S, routine: R, batch_size: usize)
    where
        R: FnMut(Poll<Receiver<Mbuf>>) -> O,
        S: Strategy<Value = Mbuf>,
        O: Batch;
}

impl BencherExt for Bencher<'_> {
    /// Similar to criterion's `iter_batched`, but uses a proptest strategy as
    /// the setup to randomly generate a vector of inputs.
    fn iter_proptest_batched<R, S: Strategy, O>(
        &mut self,
        strategy: S,
        mut routine: R,
        batch_size: usize,
    ) where
        R: FnMut(S::Value) -> O,
    {
        self.iter_custom(|mut iters| {
            let mut total_elapsed = Duration::from_secs(0);
            let mut gen = Rvg::deterministic();
            while iters > 0 {
                let batch_size = cmp::min(batch_size, iters as usize);
                let inputs = black_box(gen.generate_vec(&strategy, batch_size));
                let mut outputs = Vec::with_capacity(batch_size);
                let start = Instant::now();
                outputs.extend(inputs.into_iter().map(&mut routine));
                total_elapsed += start.elapsed();

                black_box(outputs);

                iters -= batch_size as u64;
            }
            total_elapsed
        })
    }

    /// Similar to criterion's `iter_batched`, but uses a proptest strategy,
    /// that returns an mbuf, as the setup to randomly generate a batch
    /// inputs that can be polled for benchmarking pipeline-combinations of
    /// combinators.
    fn iter_proptest_combinators<R, S: Strategy<Value = Mbuf>, O: Batch>(
        &mut self,
        strategy: S,
        mut routine: R,
        batch_size: usize,
    ) where
        R: FnMut(Poll<Receiver<Mbuf>>) -> O,
    {
        self.iter_custom(|mut iters| {
            let mut total_elapsed = Duration::from_secs(0);
            let mut gen = Rvg::deterministic();
            while iters > 0 {
                let batch_size = cmp::min(batch_size, iters as usize);
                let inputs = black_box(gen.generate_vec(&strategy, batch_size));
                let mut outputs = Vec::with_capacity(batch_size);

                let (mut tx, rx) = mpsc::channel();
                tx.transmit(inputs.into_iter().collect::<Vec<_>>());
                let mut new_batch = Poll::new(rx);
                new_batch.replenish();

                let start = Instant::now();
                let mut batch = routine(new_batch);

                while let Some(disp) = batch.next() {
                    outputs.push(disp)
                }

                total_elapsed += start.elapsed();

                black_box(batch);
                black_box(outputs);

                iters -= batch_size as u64;
            }
            total_elapsed
        })
    }
}

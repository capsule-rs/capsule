use super::Rvg;
use crate::batch::PacketTx;
use crate::{Batch, Mbuf, Poll};
use criterion::profiler::Profiler;
use criterion::{black_box, Bencher};
use flame;
use proptest::strategy::Strategy;
use std::cmp;
use std::fs::File;
use std::path::Path;
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

/// Profiler to use with criterion's profile configuration
pub struct FlameProfiler;

/// Profiler-extension for benchmarks. It only takes affect when called via:
///
/// `cargo bench --bench combinators -- --profile-time 10`
///
/// Where `profile-time` is recorded for the amount of time for each individual
/// bench. When run with this flag, criterion analysis is turned-off, and
/// profiling becomes the focus.
impl Profiler for FlameProfiler {
    fn start_profiling(&mut self, benchmark_id: &str, _benchmark_dir: &Path) {
        flame::start(benchmark_id.to_string());
    }

    fn stop_profiling(&mut self, benchmark_id: &str, _benchmark_dir: &Path) {
        flame::end(benchmark_id.to_string());
        flame::dump_html(File::create("flamegraph.html").unwrap()).unwrap();
    }
}

/// Extend criterion's Bencher with new iters
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

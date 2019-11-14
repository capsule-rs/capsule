use super::Rvg;
use criterion::{black_box, Bencher};
use proptest::strategy::Strategy;
use std::cmp;
use std::time::{Duration, Instant};

pub trait BencherExt {
    fn iter_proptest_batched<R, S, O>(&mut self, strategy: S, routine: R, batch_size: usize)
    where
        R: FnMut(S::Value) -> O,
        S: Strategy;
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
}

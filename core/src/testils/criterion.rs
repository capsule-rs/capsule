/*
* Copyright 2019 Comcast Cable Communications Management, LLC
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*
* SPDX-License-Identifier: Apache-2.0
*/

//! Iterator extensions to [criterion], leveraging proptest strategy
//! generators.
//!
//! [criterion]: https://crates.io/crates/criterion

use super::Rvg;
use criterion::{black_box, Bencher};
use proptest::strategy::Strategy;
use std::cmp;
use std::time::{Duration, Instant};

/// Criterion `Bencher` extension trait.
pub trait BencherExt {
    /// Times a `routine` with an input generated via a `proptest strategy`
    /// batch of input, and then times the iteration of the benchmark over the
    /// input. See [`BatchSize`] for details on choosing the batch size. The
    /// routine consumes its input.
    ///
    /// [`BatchSize`]: https://docs.rs/criterion/latest/criterion/enum.BatchSize.html
    fn iter_proptest_batched<R, S, O>(&mut self, strategy: S, routine: R, batch_size: usize)
    where
        R: FnMut(S::Value) -> O,
        S: Strategy;
}

impl BencherExt for Bencher<'_> {
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

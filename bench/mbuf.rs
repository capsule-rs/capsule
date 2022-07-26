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

use anyhow::Result;
use capsule::packets::Mbuf;
use criterion::{criterion_group, criterion_main, Criterion};

const BATCH_SIZE: usize = 100;

fn alloc() -> Result<Vec<Mbuf>> {
    (0..BATCH_SIZE)
        .map(|_| Mbuf::new())
        .collect::<Result<Vec<Mbuf>>>()
}

fn alloc_bulk() -> Result<Vec<Mbuf>> {
    Mbuf::alloc_bulk(BATCH_SIZE)
}

#[capsule::bench(mempool_capacity = 511)]
fn alloc_batch(c: &mut Criterion) {
    let mut group = c.benchmark_group("mbuf::alloc_vs_alloc_bulk");
    group.bench_function("mbuf::alloc", |b| b.iter_with_large_drop(alloc));
    group.bench_function("mbuf::alloc_bulk", |b| b.iter_with_large_drop(alloc_bulk));

    group.finish()
}

fn bench_config() -> Criterion {
    Criterion::default().with_plots()
}

criterion_group! {
    name = benches;
    config=bench_config();
    targets=alloc_batch,
}

criterion_main!(benches);

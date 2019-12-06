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

use capsule::batch::Either;
use capsule::packets::ip::v4::Ipv4;
use capsule::packets::{Ethernet, Packet};
use capsule::testils::criterion::BencherExt;
use capsule::testils::proptest::*;
use capsule::{compose, Batch, Mbuf, Result};
use criterion::{criterion_group, criterion_main, Criterion};
use proptest::prelude::*;
use proptest::strategy;

const BATCH_SIZE: usize = 500;

fn filter_true(batch: impl Batch<Item = Mbuf>) -> impl Batch<Item = Mbuf> {
    batch.filter(|_p| true)
}

fn filter_false(batch: impl Batch<Item = Mbuf>) -> impl Batch<Item = Mbuf> {
    batch.filter(|_p| false)
}

#[capsule::bench(mempool_capacity = 511)]
fn filters_batch(c: &mut Criterion) {
    let mut group = c.benchmark_group("combinators::filter");

    group.bench_function("combinators::filter_true", |b| {
        let s = any::<Mbuf>();
        b.iter_proptest_combinators(s, filter_true, BATCH_SIZE)
    });

    group.bench_function("combinators::filter_false", |b| {
        let s = any::<Mbuf>();
        b.iter_proptest_combinators(s, filter_false, BATCH_SIZE)
    });

    group.finish()
}

fn filter_map(batch: impl Batch<Item = Mbuf>) -> impl Batch<Item = Ethernet> {
    batch.filter_map(|p| {
        let ethernet = p.parse::<Ethernet>()?;
        Ok(Either::Keep(ethernet))
    })
}

fn map_then_filter(batch: impl Batch<Item = Mbuf>) -> impl Batch<Item = Ethernet> {
    batch.map(|p| p.parse::<Ethernet>()).filter(|_p| true)
}

#[capsule::bench(mempool_capacity = 511)]
fn filter_map_vs_map_then_filter_batch(c: &mut Criterion) {
    let mut group = c.benchmark_group("combinators::filter_map_vs_map_then_filter");

    group.bench_function("combinators::filter_map", |b| {
        let s = v4_udp();
        b.iter_proptest_combinators(s, filter_map, BATCH_SIZE)
    });

    group.bench_function("combinators::map_then_filter", |b| {
        let s = v4_udp();
        b.iter_proptest_combinators(s, map_then_filter, BATCH_SIZE)
    });

    group.finish()
}

fn map(batch: impl Batch<Item = Mbuf>) -> impl Batch<Item = Ethernet> {
    batch.map(|p| p.parse::<Ethernet>())
}

fn no_batch_map(mbuf: Mbuf) -> Result<Ethernet> {
    mbuf.parse::<Ethernet>()
}

#[capsule::bench(mempool_capacity = 511)]
fn map_batch_vs_parse(c: &mut Criterion) {
    let mut group = c.benchmark_group("combinators::map_batch_vs_parse");

    group.bench_function("combinators::map", |b| {
        let s = v4_udp();
        b.iter_proptest_combinators(s, map, BATCH_SIZE)
    });

    group.bench_function("combinators::no_batch_map", |b| {
        let s = v4_udp();
        b.iter_proptest_batched(s, no_batch_map, BATCH_SIZE)
    });
}

#[capsule::bench(mempool_capacity = 1023)]
fn map_batches(c: &mut Criterion) {
    let mut group = c.benchmark_group("combinators::map_on_diff_batch_sizes");

    group.bench_function("combinators::map_10", |b| {
        let s = v4_udp();
        b.iter_proptest_combinators(s, map, 10)
    });

    group.bench_function("combinators::map_50", |b| {
        let s = v4_udp();
        b.iter_proptest_combinators(s, map, 50)
    });

    group.bench_function("combinators::map_150", |b| {
        let s = v4_udp();
        b.iter_proptest_combinators(s, map, 150)
    });

    group.bench_function("combinators::map_500", |b| {
        let s = v4_udp();
        b.iter_proptest_combinators(s, map, 500)
    });

    group.bench_function("combinators::map_1000", |b| {
        let s = v4_udp();
        b.iter_proptest_combinators(s, map, 1000)
    });

    group.finish()
}

fn map_parse_errors(batch: impl Batch<Item = Mbuf>) -> impl Batch<Item = Ipv4> {
    batch.map(|p| p.parse::<Ethernet>()?.parse::<Ipv4>())
}

#[capsule::bench(mempool_capacity = 511)]
fn map_errors(c: &mut Criterion) {
    let mut group = c.benchmark_group("combinators::map_errors_vs_no_errors");

    group.bench_function("combinators::map_no_errors", |b| {
        let s = v4_udp();
        b.iter_proptest_combinators(s, map_parse_errors, BATCH_SIZE)
    });

    group.bench_function("combinators::map_with_errors", |b| {
        let s = strategy::Union::new_weighted(vec![(8, v4_udp().boxed()), (2, v6_udp().boxed())]);
        b.iter_proptest_combinators(s, map_parse_errors, BATCH_SIZE)
    });
}

static mut COUNTER: u32 = 0;
fn group_by(batch: impl Batch<Item = Mbuf>) -> impl Batch<Item = Mbuf> {
    unsafe { COUNTER += 1 };

    unsafe {
        batch.group_by(
            |_p| COUNTER % 2,
            |groups| {
                compose!(groups {
                    0 => |group| {
                        group
                    }
                    _ => |group| {
                        group
                    }
                })
            },
        )
    }
}

#[capsule::bench(mempool_capacity = 511)]
fn group_by_batch(c: &mut Criterion) {
    c.bench_function("combinators::group_by", |b| {
        let s = any::<Mbuf>();
        b.iter_proptest_combinators(s, group_by, BATCH_SIZE)
    });
}

fn replace(batch: impl Batch<Item = Mbuf>) -> impl Batch<Item = Mbuf> {
    batch.replace(|_p| Mbuf::new())
}

fn no_batch_replace(_mbuf: Mbuf) -> Result<Mbuf> {
    Mbuf::new()
}

#[capsule::bench(mempool_capacity = 511)]
fn replace_batch(c: &mut Criterion) {
    let mut group = c.benchmark_group("combinators::replace_with_new_mbuf_vs_create_new_mbuf");

    group.bench_function("combinators::replace", |b| {
        let s = any::<Mbuf>();
        b.iter_proptest_combinators(s, replace, BATCH_SIZE)
    });

    group.bench_function("combinators::no_batch_replace", |b| {
        let s = any::<Mbuf>();
        b.iter_proptest_batched(s, no_batch_replace, BATCH_SIZE)
    });

    group.finish()
}

fn bench_config() -> Criterion {
    Criterion::default().with_plots()
}

criterion_group! {
    name = benches;
    config=bench_config();
    targets=filters_batch,
            filter_map_vs_map_then_filter_batch,
            map_batch_vs_parse,
            group_by_batch,
            replace_batch,
            map_batches,
            map_errors,
}

criterion_main!(benches);

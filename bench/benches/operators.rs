use criterion::{criterion_group, criterion_main, Criterion};
use nb2::batch::Either;
use nb2::packets::{Ethernet, Packet};
use nb2::testils::criterion::BencherExt;
use nb2::testils::proptest::*;
use nb2::{compose, Batch, Mbuf};
use proptest::prelude::*;
use proptest::strategy;

const BATCH_SIZE: usize = 500;
static mut COUNTER: u32 = 0;

fn filter_true(batch: impl Batch<Item = Mbuf>) -> impl Batch<Item = Mbuf> {
    batch.filter(|_p| true)
}

fn filter_false(batch: impl Batch<Item = Mbuf>) -> impl Batch<Item = Mbuf> {
    batch.filter(|_p| false)
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

fn map(batch: impl Batch<Item = Mbuf>) -> impl Batch<Item = Ethernet> {
    batch.map(|p| p.parse::<Ethernet>())
}

fn group_by(batch: impl Batch<Item = Mbuf>) -> impl Batch<Item = Mbuf> {
    unsafe { COUNTER += 1 };

    unsafe {
        batch.group_by(
            |_p| COUNTER,
            |groups| {
                compose!(groups {
                    0 => |group| {
                        group.for_each(|_p| Ok(()))
                    }
                    _ => |group| {
                        group.for_each(|_p| Ok(()))
                    }
                })
            },
        )
    }
}

fn replace(batch: impl Batch<Item = Mbuf>) -> impl Batch<Item = Mbuf> {
    batch.replace(|_p| Mbuf::new())
}

fn no_batch_replace(_mbuf: Mbuf) -> Mbuf {
    Mbuf::new().unwrap()
}

#[nb2::bench(mempool_capacity = 511)]
fn filters_batch(c: &mut Criterion) {
    let mut group = c.benchmark_group("operators::filter");

    group.bench_function("operators::filter_true", |b| {
        let s = v4_udp();
        b.iter_proptest_polled(s, filter_true, BATCH_SIZE)
    });

    group.bench_function("operators::filter_false", |b| {
        let s = v4_udp();
        b.iter_proptest_polled(s, filter_false, BATCH_SIZE)
    });

    group.finish()
}

#[nb2::bench(mempool_capacity = 511)]
fn filter_map_vs_map_then_filter_batch(c: &mut Criterion) {
    let mut group = c.benchmark_group("operators::filter_map_vs_map_then_filter");

    group.bench_function("operators::filter_map", |b| {
        let s = strategy::Union::new_weighted(vec![(9, v4_udp().boxed()), (1, v6_udp().boxed())]);
        b.iter_proptest_polled(s, filter_map, BATCH_SIZE)
    });

    group.bench_function("operators::map_then_filter", |b| {
        let s = strategy::Union::new_weighted(vec![(9, v4_udp().boxed()), (1, v6_udp().boxed())]);
        b.iter_proptest_polled(s, map_then_filter, BATCH_SIZE)
    });

    group.finish()
}

#[nb2::bench(mempool_capacity = 511)]
fn map_batch(c: &mut Criterion) {
    c.bench_function("operators::map", |b| {
        let s = strategy::Union::new_weighted(vec![(9, v4_udp().boxed()), (1, v6_udp().boxed())]);
        b.iter_proptest_polled(s, map, BATCH_SIZE)
    });
}

#[nb2::bench(mempool_capacity = 511)]
fn group_by_batch(c: &mut Criterion) {
    c.bench_function("operators::group_by", |b| {
        let s = v4_udp();
        b.iter_proptest_polled(s, group_by, BATCH_SIZE)
    });
}

#[nb2::bench(mempool_capacity = 511)]
fn replace_batch(c: &mut Criterion) {
    let mut group = c.benchmark_group("operators::replace_with_new_mbuf_vs_create_new_mbuf");

    group.bench_function("operators::replace", |b| {
        let s = v4_udp();
        b.iter_proptest_polled(s, replace, BATCH_SIZE)
    });

    group.bench_function("operators::no_batch_replace", |b| {
        let s = v4_udp();
        b.iter_proptest_batched(s, no_batch_replace, BATCH_SIZE)
    });

    group.finish()
}

#[nb2::bench(mempool_capacity = 1023)]
fn map_batches(c: &mut Criterion) {
    let mut group = c.benchmark_group("operators::map_on_diff_batch_sizes");

    group.bench_function("operators::map_10", |b| {
        let s = strategy::Union::new_weighted(vec![(9, v4_udp().boxed()), (1, v6_udp().boxed())]);
        b.iter_proptest_polled(s, map, 10)
    });

    group.bench_function("operators::map_50", |b| {
        let s = strategy::Union::new_weighted(vec![(9, v4_udp().boxed()), (1, v6_udp().boxed())]);
        b.iter_proptest_polled(s, map, 50)
    });

    group.bench_function("operators::map_150", |b| {
        let s = strategy::Union::new_weighted(vec![(9, v4_udp().boxed()), (1, v6_udp().boxed())]);
        b.iter_proptest_polled(s, map, 150)
    });

    group.bench_function("operators::map_500", |b| {
        let s = strategy::Union::new_weighted(vec![(9, v4_udp().boxed()), (1, v6_udp().boxed())]);
        b.iter_proptest_polled(s, map, 500)
    });

    group.bench_function("operators::map_1000", |b| {
        let s = strategy::Union::new_weighted(vec![(9, v4_udp().boxed()), (1, v6_udp().boxed())]);
        b.iter_proptest_polled(s, map, 1000)
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
            map_batch,
            group_by_batch,
            replace_batch,
            map_batches,
}

criterion_main!(benches);

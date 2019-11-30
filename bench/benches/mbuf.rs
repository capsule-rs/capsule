use criterion::{criterion_group, criterion_main, Criterion};
use nb2::testils::criterion::BencherExt;
use nb2::testils::proptest::*;
use nb2::Mbuf;
use nb2::Result;

const BATCH_SIZE: usize = 100;

fn alloc_once(_mbuf: Mbuf) -> Result<Mbuf> {
    Mbuf::new()
}

fn alloc() -> () {
    for _i in 0..BATCH_SIZE {
        let _ = Mbuf::new();
    }
}

fn alloc_bulk() -> Result<Vec<Mbuf>> {
    Mbuf::alloc_bulk(BATCH_SIZE)
}

#[nb2::bench(mempool_capacity = 511)]
fn alloc_once_batch(c: &mut Criterion) {
    c.bench_function("mbuf::alloc", |b| {
        let s = v4_udp();
        b.iter_proptest_batched(s, alloc_once, BATCH_SIZE)
    });
}

#[nb2::bench(mempool_capacity = 511)]
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
    targets=alloc_once_batch,
            alloc_batch,
}

criterion_main!(benches);

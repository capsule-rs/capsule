use criterion::{criterion_group, criterion_main, Criterion};
use nb2::testils::criterion::FlameProfiler;
use nb2::Mbuf;
use nb2::Result;

const BATCH_SIZE: usize = 100;

fn alloc() -> Result<Vec<Mbuf>> {
    (0..BATCH_SIZE)
        .map(|_| Mbuf::new())
        .collect::<Result<Vec<Mbuf>>>()
}

fn alloc_bulk() -> Result<Vec<Mbuf>> {
    Mbuf::alloc_bulk(BATCH_SIZE)
}

#[nb2::bench(mempool_capacity = 511)]
fn alloc_batch(c: &mut Criterion) {
    let mut group = c.benchmark_group("mbuf::alloc_vs_alloc_bulk");
    group.bench_function("mbuf::alloc", |b| b.iter_with_large_drop(alloc));
    group.bench_function("mbuf::alloc_bulk", |b| b.iter_with_large_drop(alloc_bulk));

    group.finish()
}

fn bench_config() -> Criterion {
    Criterion::default()
        .with_plots()
        .with_profiler(FlameProfiler)
}

criterion_group! {
    name = benches;
    config=bench_config();
    targets=alloc_batch,
}

criterion_main!(benches);

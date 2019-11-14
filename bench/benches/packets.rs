use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use nb2::packets::ip::v4::Ipv4;
use nb2::packets::ip::v6::{Ipv6, SegmentRouting};
use nb2::packets::{Ethernet, Packet, Udp};
use nb2::testils::criterion::BencherExt;
use nb2::testils::proptest::*;
use nb2::testils::{PacketExt, Rvg};
use nb2::Mbuf;
use nb2::{fieldmap, Result};
use proptest::prelude::*;
use std::net::Ipv6Addr;

const BATCH_SIZE: usize = 500;

fn single_parse_udp(ipv4: Ipv4) -> Udp<Ipv4> {
    ipv4.parse::<Udp<Ipv4>>().unwrap()
}

fn multi_parse_udp(mbuf: Mbuf) -> Udp<Ipv4> {
    let ethernet = mbuf.parse::<Ethernet>().unwrap();
    let ipv4 = ethernet.parse::<Ipv4>().unwrap();
    ipv4.parse::<Udp<Ipv4>>().unwrap()
}

fn single_parse_srh(ipv6: Ipv6) -> SegmentRouting<Ipv6> {
    ipv6.parse::<SegmentRouting<Ipv6>>().unwrap()
}

fn multi_parse_srh(mbuf: Mbuf) -> SegmentRouting<Ipv6> {
    let ethernet = mbuf.parse::<Ethernet>().unwrap();
    let ipv6 = ethernet.parse::<Ipv6>().unwrap();
    ipv6.parse::<SegmentRouting<Ipv6>>().unwrap()
}

fn deparse_udp(udp: Udp<Ipv4>) -> Mbuf {
    let d_ipv4 = udp.deparse();
    let d_eth = d_ipv4.deparse();
    d_eth.deparse()
}

fn single_peek_udp(ipv4: Ipv4) -> Ipv4 {
    ipv4.peek::<Udp<Ipv4>>().unwrap();
    ipv4
}

fn multi_peek_udp(mbuf: Mbuf) -> Mbuf {
    let ethernet = mbuf.peek::<Ethernet>().unwrap();
    let ipv4 = ethernet.peek::<Ipv4>().unwrap();
    ipv4.peek::<Udp<Ipv4>>().unwrap();
    mbuf
}

fn reset_udp(udp: Udp<Ipv4>) -> Mbuf {
    udp.reset()
}

fn multi_push_udp(mbuf: Mbuf) -> Udp<Ipv4> {
    let ethernet = mbuf.push::<Ethernet>().unwrap();
    let ipv4 = ethernet.push::<Ipv4>().unwrap();
    ipv4.push::<Udp<Ipv4>>().unwrap()
}

fn single_push_udp(ipv4: Ipv4) -> Udp<Ipv4> {
    ipv4.push::<Udp<Ipv4>>().unwrap()
}

fn single_remove_udp(udp: Udp<Ipv4>) -> Ipv4 {
    udp.remove().unwrap()
}

fn multi_remove_udp(udp: Udp<Ipv4>) -> Mbuf {
    let ipv4 = udp.remove().unwrap();
    let ethernet = ipv4.remove().unwrap();
    ethernet.remove().unwrap()
}

fn set_srh_segments(mut args: (SegmentRouting<Ipv6>, Vec<Ipv6Addr>)) -> Result<()> {
    args.0.set_segments(&args.1)
}

#[nb2::bench(mempool_capacity = 511)]
fn single_peek_vs_parse(c: &mut Criterion) {
    let mut group = c.benchmark_group("Single Peek vs Parse on Udp Packets");

    group.bench_function("packets::single_parse_udp", |b| {
        let s = v4_udp().prop_map(|v| {
            let packet = v.into_v4_udp();
            packet.deparse()
        });
        b.iter_proptest_batched(s, single_parse_udp, BATCH_SIZE)
    });

    group.bench_function("packets::single_peek_udp", |b| {
        let s = v4_udp().prop_map(|v| {
            let packet = v.into_v4_udp();
            packet.deparse()
        });
        b.iter_proptest_batched(s, single_peek_udp, BATCH_SIZE)
    });

    group.finish()
}

#[nb2::bench(mempool_capacity = 511)]
fn multi_peek_vs_parse(c: &mut Criterion) {
    let mut group = c.benchmark_group("Multi Peek vs Parse on Udp Packets");

    group.bench_function("packets::multi_parse_udp", |b| {
        let s = v4_udp();
        b.iter_proptest_batched(s, multi_parse_udp, BATCH_SIZE)
    });

    group.bench_function("packets::multi_peek_udp", |b| {
        let s = v4_udp();
        b.iter_proptest_batched(s, multi_peek_udp, BATCH_SIZE)
    });

    group.finish()
}

#[nb2::bench(mempool_capacity = 511)]
fn single_parse_srh_segments_sizes(c: &mut Criterion) {
    let mut group =
        c.benchmark_group("Comparison on parsing to an SRH header across segment sizes");

    let mut rvg = Rvg::new();

    group.bench_function("packets::single_parse_srh::size=1", |b| {
        let segments = rvg.generate_vec(&any::<Ipv6Addr>(), 1);
        let s = sr_tcp_with(fieldmap! {field::sr_segments => segments})
            .prop_map(|v| v.into_sr().deparse());
        b.iter_proptest_batched(s, single_parse_srh, BATCH_SIZE)
    });

    group.bench_function("packets::single_parse_srh::size=2", |b| {
        let segments = rvg.generate_vec(&any::<Ipv6Addr>(), 2);
        let s = sr_tcp_with(fieldmap! {field::sr_segments => segments})
            .prop_map(|v| v.into_sr().deparse());
        b.iter_proptest_batched(s, single_parse_srh, BATCH_SIZE)
    });

    group.bench_function("packets::single_parse_srh::size=4", |b| {
        let segments = rvg.generate_vec(&any::<Ipv6Addr>(), 4);
        let s = sr_tcp_with(fieldmap! {field::sr_segments => segments})
            .prop_map(|v| v.into_sr().deparse());
        b.iter_proptest_batched(s, single_parse_srh, BATCH_SIZE)
    });

    group.bench_function("packets::single_parse_srh::size=8", |b| {
        let segments = rvg.generate_vec(&any::<Ipv6Addr>(), 8);
        let s = sr_tcp_with(fieldmap! {field::sr_segments => segments})
            .prop_map(|v| v.into_sr().deparse());
        b.iter_proptest_batched(s, single_parse_srh, BATCH_SIZE)
    });

    group.finish()
}

#[nb2::bench(mempool_capacity = 511)]
fn multi_parse_upto_variable_srh(c: &mut Criterion) {
    c.bench_function("packets::multi_parse_srh", |b| {
        let s = sr_tcp();
        b.iter_proptest_batched(s, multi_parse_srh, BATCH_SIZE)
    });
}

#[nb2::bench(mempool_capacity = 511)]
fn set_srh_segments_sizes(c: &mut Criterion) {
    let mut group =
        c.benchmark_group("Comparison on setting segments on an SRH header across segment sizes");

    let mut rvg = Rvg::new();

    group.bench_function("packets::set_srh_segments::size=1", |b| {
        let segments = rvg.generate_vec(&any::<Ipv6Addr>(), 1);
        let s = (sr_tcp().prop_map(|v| v.into_sr()), Just(segments));
        b.iter_proptest_batched(s, set_srh_segments, BATCH_SIZE)
    });

    group.bench_function("packets::set_srh_segments::size=2", |b| {
        let segments = rvg.generate_vec(&any::<Ipv6Addr>(), 2);
        let s = (sr_tcp().prop_map(|v| v.into_sr()), Just(segments));
        b.iter_proptest_batched(s, set_srh_segments, BATCH_SIZE)
    });

    group.bench_function("packets::set_srh_segments::size=4", |b| {
        let segments = rvg.generate_vec(&any::<Ipv6Addr>(), 4);
        let s = (sr_tcp().prop_map(|v| v.into_sr()), Just(segments));
        b.iter_proptest_batched(s, set_srh_segments, BATCH_SIZE)
    });

    group.bench_function("packets::set_srh_segments::size=8", |b| {
        let segments = rvg.generate_vec(&any::<Ipv6Addr>(), 8);
        let s = (sr_tcp().prop_map(|v| v.into_sr()), Just(segments));
        b.iter_proptest_batched(s, set_srh_segments, BATCH_SIZE)
    });

    group.finish()
}

#[nb2::bench(mempool_capacity = 511)]
fn deparse(c: &mut Criterion) {
    c.bench_function("packets::deparse_udp", |b| {
        let s = v4_udp().prop_map(|v| v.into_v4_udp());
        b.iter_proptest_batched(s, deparse_udp, BATCH_SIZE)
    });
}

#[nb2::bench(mempool_capacity = 511)]
fn single_push(c: &mut Criterion) {
    c.bench_function("packets::single_push_udp", |b| {
        let s = v4_udp().prop_map(|v| {
            let udp = v.into_v4_udp();
            udp.remove().unwrap()
        });
        b.iter_proptest_batched(s, single_push_udp, BATCH_SIZE)
    });
}

#[nb2::bench(mempool_capacity = 511)]
fn multi_push(c: &mut Criterion) {
    c.bench_function("packets::multi_push_udp", |b| {
        b.iter_batched(
            || Mbuf::new().unwrap(),
            |mbuf| multi_push_udp(mbuf),
            BatchSize::NumIterations(BATCH_SIZE as u64),
        )
    });
}

#[nb2::bench(mempool_capacity = 511)]
fn single_remove(c: &mut Criterion) {
    c.bench_function("packets::single_remove_from_udp", |b| {
        let s = v4_udp().prop_map(|v| v.into_v4_udp());
        b.iter_proptest_batched(s, single_remove_udp, BATCH_SIZE)
    });
}

#[nb2::bench(mempool_capacity = 511)]
fn multi_remove(c: &mut Criterion) {
    c.bench_function("packets::multi_remove_from_udp", |b| {
        let s = v4_udp().prop_map(|v| v.into_v4_udp());
        b.iter_proptest_batched(s, multi_remove_udp, BATCH_SIZE)
    });
}

#[nb2::bench(mempool_capacity = 511)]
fn reset(c: &mut Criterion) {
    c.bench_function("packets::reset_udp", |b| {
        let s = v4_udp().prop_map(|v| v.into_v4_udp());
        b.iter_proptest_batched(s, reset_udp, BATCH_SIZE)
    });
}

fn bench_config() -> Criterion {
    Criterion::default().with_plots()
}

criterion_group! {
    name = benches;
    config=bench_config();
    targets=single_peek_vs_parse,
            multi_peek_vs_parse,
            single_parse_srh_segments_sizes,
            multi_parse_upto_variable_srh,
            set_srh_segments_sizes,
            deparse,
            single_push,
            multi_push,
            single_remove,
            multi_remove,
            reset,
}

criterion_main!(benches);

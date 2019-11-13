use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use nb2::packets::ip::v4::Ipv4;
use nb2::packets::{Ethernet, Packet, Udp};
use nb2::testils::criterion::BencherExt;
use nb2::testils::proptest::*;
use nb2::testils::PacketExt;
use nb2::Mbuf;
use proptest::prelude::*;

const BATCH_SIZE: usize = 500;

fn parse_packet(mbuf: Mbuf) -> Udp<Ipv4> {
    let ethernet = mbuf.parse::<Ethernet>().unwrap();
    let ipv4 = ethernet.parse::<Ipv4>().unwrap();
    ipv4.parse::<Udp<Ipv4>>().unwrap()
}

fn deparse_packet(udp: Udp<Ipv4>) -> Mbuf {
    let d_ipv4 = udp.deparse();
    let d_eth = d_ipv4.deparse();
    d_eth.deparse()
}

fn peek_through_packet(mbuf: Mbuf) -> Mbuf {
    let ethernet = mbuf.peek::<Ethernet>().unwrap();
    let ipv4 = ethernet.peek::<Ipv4>().unwrap();
    ipv4.peek::<Udp<Ipv4>>().unwrap();
    mbuf
}

fn peek_into_packet(ipv4: Ipv4) -> Ipv4 {
    ipv4.peek::<Udp<Ipv4>>().unwrap();
    ipv4
}

fn reset_packet(udp: Udp<Ipv4>) -> Mbuf {
    udp.reset()
}

fn push_into_mbuf(mbuf: Mbuf) -> Udp<Ipv4> {
    let ethernet = mbuf.push::<Ethernet>().unwrap();
    let ipv4 = ethernet.push::<Ipv4>().unwrap();
    ipv4.push::<Udp<Ipv4>>().unwrap()
}

fn push_into_packet(ipv4: Ipv4) -> Udp<Ipv4> {
    ipv4.push::<Udp<Ipv4>>().unwrap()
}

fn remove_from_packet(udp: Udp<Ipv4>) -> Ipv4 {
    udp.remove().unwrap()
}

#[nb2::bench(mempool_capacity = 511)]
fn parse_benchmarks(c: &mut Criterion) {
    c.bench_function("packets::parse_packets", |b| {
        let s = v4_udp();
        b.prop_iter_batched(BATCH_SIZE, s, parse_packet)
    });

    c.bench_function("packets::deparse_packets", |b| {
        let s = v4_udp().prop_map(|v| v.into_v4_udp());
        b.prop_iter_batched(BATCH_SIZE, s, deparse_packet)
    });
}

#[nb2::bench(mempool_capacity = 511)]
fn peek_benchmarks(c: &mut Criterion) {
    c.bench_function("packets::peek_through_packets", |b| {
        let s = v4_udp();
        b.prop_iter_batched(BATCH_SIZE, s, peek_through_packet)
    });

    c.bench_function("packets::peek_into_packets", |b| {
        let s = v4_udp().prop_map(|v| {
            let packet = v.into_v4_udp();
            packet.deparse()
        });
        b.prop_iter_batched(BATCH_SIZE, s, peek_into_packet)
    });
}

#[nb2::bench(mempool_capacity = 511)]
fn push_benchmarks(c: &mut Criterion) {
    c.bench_function("packets::push_into_mbuf", |b| {
        b.iter_batched(
            || Mbuf::new().unwrap(),
            |mbuf| push_into_mbuf(mbuf),
            BatchSize::NumIterations(BATCH_SIZE as u64),
        )
    });

    c.bench_function("packets::push_into_packet", |b| {
        let s = v4_udp().prop_map(|v| {
            let udp = v.into_v4_udp();
            udp.remove().unwrap()
        });
        b.prop_iter_batched(BATCH_SIZE, s, push_into_packet)
    });
}

#[nb2::bench(mempool_capacity = 511)]
fn remove_benchmark(c: &mut Criterion) {
    c.bench_function("packets::remove_from_packet", |b| {
        let s = v4_udp().prop_map(|v| v.into_v4_udp());
        b.prop_iter_batched(BATCH_SIZE, s, remove_from_packet)
    });
}

#[nb2::bench(mempool_capacity = 511)]
fn reset_benchmark(c: &mut Criterion) {
    c.bench_function("packets::reset_packets", |b| {
        let s = v4_udp().prop_map(|v| v.into_v4_udp());
        b.prop_iter_batched(BATCH_SIZE, s, reset_packet)
    });
}

fn bench_config() -> Criterion {
    Criterion::default().with_plots()
}

criterion_group! {
    name = benches;
    config=bench_config();
    targets=parse_benchmarks,
            peek_benchmarks,
            push_benchmarks,
            remove_benchmark,
            reset_benchmark,
}

criterion_main!(benches);

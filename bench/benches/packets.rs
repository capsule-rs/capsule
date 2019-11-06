use criterion::{criterion_group, criterion_main, Criterion};
use nb2::packets::ip::v4::Ipv4;
use nb2::packets::{Ethernet, Packet, Udp};
use nb2::testils::criterion::BencherExt;
use nb2::testils::proptest::*;
use nb2::testils::PacketExt;
use nb2::Mbuf;
use proptest::prelude::*;

const BATCH_SIZE: usize = 500;

fn parse_udp_packet(mbuf: Mbuf) {
    let ethernet = mbuf.parse::<Ethernet>().unwrap();
    let ipv4 = ethernet.parse::<Ipv4>().unwrap();
    ipv4.parse::<Udp<Ipv4>>().unwrap();
}

fn deparse_udp_packet(udp: Udp<Ipv4>) {
    let d_ipv4 = udp.deparse();
    let d_eth = d_ipv4.deparse();
    d_eth.deparse();
}

#[nb2::bench(mempool_capacity = 512)]
fn parse_benchmark(c: &mut Criterion) {
    c.bench_function("packets::parse_udp_packets", move |b| {
        let s = v4_udp();
        b.iter_batches(BATCH_SIZE, s, parse_udp_packet)
    });

    c.bench_function("packets::deparse_udp_packets", move |b| {
        let s = v4_udp().prop_map(|v| v.into_v4_udp());
        b.iter_batches(BATCH_SIZE, s, deparse_udp_packet)
    });
}

fn bench_config() -> Criterion {
    Criterion::default()
}

criterion_group! {
    name = benches;
    config=bench_config();
    targets=parse_benchmark
}

criterion_main!(benches);

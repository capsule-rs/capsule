use criterion::{black_box, criterion_group, criterion_main, Criterion};
use nb2::packets::ip::v4::Ipv4;
use nb2::packets::{Ethernet, Packet, Udp};
use nb2::testils::byte_arrays::UDP_PACKET;
use nb2::Mbuf;

fn parse_ipv4_packet() {
    let packet = Mbuf::from_bytes(&UDP_PACKET).unwrap();
    let ethernet = packet.parse::<Ethernet>().unwrap();
    let ipv4 = ethernet.parse::<Ipv4>().unwrap();
    ipv4.parse::<Udp<Ipv4>>().unwrap();
}

#[nb2::bench]
fn parse_benchmark(c: &mut Criterion) {
    c.bench_function("packets::parse_ipv4_packet", |b| {
        b.iter(|| black_box(parse_ipv4_packet()));
    });
}

criterion_group!(benches, parse_benchmark);
criterion_main!(benches);

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

use capsule::packets::ip::v4::Ipv4;
use capsule::packets::{Ethernet, Packet, Udp};
use capsule::testils::criterion::BencherExt;
use capsule::testils::proptest::*;
use capsule::testils::PacketExt;
use capsule::Mbuf;
use criterion::{criterion_group, criterion_main, Criterion};
use proptest::prelude::*;

const BATCH_SIZE: usize = 500;

fn parse_udp_packet(mbuf: Mbuf) -> Udp<Ipv4> {
    let ethernet = mbuf.parse::<Ethernet>().unwrap();
    let ipv4 = ethernet.parse::<Ipv4>().unwrap();
    ipv4.parse::<Udp<Ipv4>>().unwrap()
}

fn deparse_udp_packet(udp: Udp<Ipv4>) -> Mbuf {
    let d_ipv4 = udp.deparse();
    let d_eth = d_ipv4.deparse();
    d_eth.deparse()
}

#[capsule::bench(mempool_capacity = 512)]
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

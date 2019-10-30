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
use capsule::testils::byte_arrays::UDP_PACKET;
use capsule::Mbuf;
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn parse_ipv4_packet() {
    let packet = Mbuf::from_bytes(&UDP_PACKET).unwrap();
    let ethernet = packet.parse::<Ethernet>().unwrap();
    let ipv4 = ethernet.parse::<Ipv4>().unwrap();
    ipv4.parse::<Udp<Ipv4>>().unwrap();
}

#[capsule::bench]
fn parse_benchmark(c: &mut Criterion) {
    c.bench_function("packets::parse_ipv4_packet", |b| {
        b.iter(|| black_box(parse_ipv4_packet()));
    });
}

criterion_group!(benches, parse_benchmark);
criterion_main!(benches);

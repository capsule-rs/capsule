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

use anyhow::Result;
use capsule::fieldmap;
use capsule::packets::ethernet::Ethernet;
use capsule::packets::ip::v4::Ipv4;
use capsule::packets::ip::v6::{Ipv6, SegmentRouting};
use capsule::packets::udp::Udp4;
use capsule::packets::{Mbuf, Packet};
use capsule::testils::criterion::BencherExt;
use capsule::testils::proptest::*;
use capsule::testils::{PacketExt, Rvg};
use criterion::{criterion_group, criterion_main, Criterion};
use proptest::prelude::*;
use std::net::Ipv6Addr;

const BATCH_SIZE: usize = 500;

fn single_parse_udp(ip4: Ipv4) -> Udp4 {
    ip4.parse::<Udp4>().unwrap()
}

fn single_peek_udp(ip4: Ipv4) -> Ipv4 {
    ip4.peek::<Udp4>().unwrap();
    ip4
}

#[capsule::bench(mempool_capacity = 511)]
fn single_peek_vs_parse(c: &mut Criterion) {
    let mut group = c.benchmark_group("packets::single_peek_vs_parse_on_udp");

    group.bench_function("packets::single_parse_udp", |b| {
        let s = udp4().prop_map(|v| {
            let packet = v.into_udp4();
            packet.deparse()
        });
        b.iter_proptest_batched(s, single_parse_udp, BATCH_SIZE)
    });

    group.bench_function("packets::single_peek_udp", |b| {
        let s = udp4().prop_map(|v| {
            let packet = v.into_udp4();
            packet.deparse()
        });
        b.iter_proptest_batched(s, single_peek_udp, BATCH_SIZE)
    });

    group.finish()
}

fn multi_parse_udp(mbuf: Mbuf) -> Udp4 {
    let ethernet = mbuf.parse::<Ethernet>().unwrap();
    let ip4 = ethernet.parse::<Ipv4>().unwrap();
    ip4.parse::<Udp4>().unwrap()
}

fn multi_peek_udp(mbuf: Mbuf) -> Mbuf {
    let ethernet = mbuf.peek::<Ethernet>().unwrap();
    let ip4 = ethernet.peek::<Ipv4>().unwrap();
    ip4.peek::<Udp4>().unwrap();
    mbuf
}

#[capsule::bench(mempool_capacity = 511)]
fn multi_peek_vs_parse(c: &mut Criterion) {
    let mut group = c.benchmark_group("packets::multi_peek_vs_parse_on_udp_packets");

    group.bench_function("packets::multi_parse_udp", |b| {
        let s = udp4();
        b.iter_proptest_batched(s, multi_parse_udp, BATCH_SIZE)
    });

    group.bench_function("packets::multi_peek_udp", |b| {
        let s = udp4();
        b.iter_proptest_batched(s, multi_peek_udp, BATCH_SIZE)
    });

    group.finish()
}

fn single_parse_sr(ip6: Ipv6) -> SegmentRouting<Ipv6> {
    ip6.parse::<SegmentRouting<Ipv6>>().unwrap()
}

#[capsule::bench(mempool_capacity = 511)]
fn single_parse_sr_segments_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("packets::parsing_on_sr_across_segment_sizes");

    let mut rvg = Rvg::new();

    group.bench_function("packets::single_parse_sr::size=1", |b| {
        let segments = rvg.generate_vec(&any::<Ipv6Addr>(), 1);
        let s = sr_tcp_with(fieldmap! {field::sr_segments => segments})
            .prop_map(|v| v.into_sr().deparse());
        b.iter_proptest_batched(s, single_parse_sr, BATCH_SIZE)
    });

    group.bench_function("packets::single_parse_sr::size=2", |b| {
        let segments = rvg.generate_vec(&any::<Ipv6Addr>(), 2);
        let s = sr_tcp_with(fieldmap! {field::sr_segments => segments})
            .prop_map(|v| v.into_sr().deparse());
        b.iter_proptest_batched(s, single_parse_sr, BATCH_SIZE)
    });

    group.bench_function("packets::single_parse_sr::size=4", |b| {
        let segments = rvg.generate_vec(&any::<Ipv6Addr>(), 4);
        let s = sr_tcp_with(fieldmap! {field::sr_segments => segments})
            .prop_map(|v| v.into_sr().deparse());
        b.iter_proptest_batched(s, single_parse_sr, BATCH_SIZE)
    });

    group.bench_function("packets::single_parse_sr::size=8", |b| {
        let segments = rvg.generate_vec(&any::<Ipv6Addr>(), 8);
        let s = sr_tcp_with(fieldmap! {field::sr_segments => segments})
            .prop_map(|v| v.into_sr().deparse());
        b.iter_proptest_batched(s, single_parse_sr, BATCH_SIZE)
    });

    group.finish()
}

fn multi_parse_sr(mbuf: Mbuf) -> SegmentRouting<Ipv6> {
    let ethernet = mbuf.parse::<Ethernet>().unwrap();
    let ip6 = ethernet.parse::<Ipv6>().unwrap();
    ip6.parse::<SegmentRouting<Ipv6>>().unwrap()
}

#[capsule::bench(mempool_capacity = 511)]
fn multi_parse_upto_variable_sr(c: &mut Criterion) {
    c.bench_function("packets::multi_parse_sr", |b| {
        let s = sr_tcp();
        b.iter_proptest_batched(s, multi_parse_sr, BATCH_SIZE)
    });
}

fn deparse_udp(udp: Udp4) -> Mbuf {
    let d_ipv4 = udp.deparse();
    let d_eth = d_ipv4.deparse();
    d_eth.deparse()
}

#[capsule::bench(mempool_capacity = 511)]
fn deparse(c: &mut Criterion) {
    c.bench_function("packets::deparse_udp", |b| {
        let s = udp4().prop_map(|v| v.into_udp4());
        b.iter_proptest_batched(s, deparse_udp, BATCH_SIZE)
    });
}

fn reset_udp(udp: Udp4) -> Mbuf {
    udp.reset()
}

#[capsule::bench(mempool_capacity = 511)]
fn reset(c: &mut Criterion) {
    c.bench_function("packets::reset_udp", |b| {
        let s = udp4().prop_map(|v| v.into_udp4());
        b.iter_proptest_batched(s, reset_udp, BATCH_SIZE)
    });
}

fn multi_push_udp(mbuf: Mbuf) -> Udp4 {
    let ethernet = mbuf.push::<Ethernet>().unwrap();
    let ip4 = ethernet.push::<Ipv4>().unwrap();
    ip4.push::<Udp4>().unwrap()
}

#[capsule::bench(mempool_capacity = 511)]
fn multi_push(c: &mut Criterion) {
    c.bench_function("packets::multi_push_udp", |b| {
        let s = any::<Mbuf>();
        b.iter_proptest_batched(s, multi_push_udp, BATCH_SIZE)
    });
}

fn single_push_udp(ip4: Ipv4) -> Udp4 {
    ip4.push::<Udp4>().unwrap()
}

#[capsule::bench(mempool_capacity = 511)]
fn single_push(c: &mut Criterion) {
    c.bench_function("packets::single_push_udp", |b| {
        let s = udp4().prop_map(|v| {
            let udp = v.into_udp4();
            udp.remove().unwrap()
        });
        b.iter_proptest_batched(s, single_push_udp, BATCH_SIZE)
    });
}

fn single_remove_udp(udp: Udp4) -> Ipv4 {
    udp.remove().unwrap()
}

#[capsule::bench(mempool_capacity = 511)]
fn single_remove(c: &mut Criterion) {
    c.bench_function("packets::single_remove_from_udp", |b| {
        let s = udp4().prop_map(|v| v.into_udp4());
        b.iter_proptest_batched(s, single_remove_udp, BATCH_SIZE)
    });
}

fn multi_remove_udp(udp: Udp4) -> Mbuf {
    let ip4 = udp.remove().unwrap();
    let ethernet = ip4.remove().unwrap();
    ethernet.remove().unwrap()
}

#[capsule::bench(mempool_capacity = 511)]
fn multi_remove(c: &mut Criterion) {
    c.bench_function("packets::multi_remove_from_udp", |b| {
        let s = udp4().prop_map(|v| v.into_udp4());
        b.iter_proptest_batched(s, multi_remove_udp, BATCH_SIZE)
    });
}

fn set_sr_segments(mut args: (SegmentRouting<Ipv6>, Vec<Ipv6Addr>)) -> Result<()> {
    args.0.set_segments(&args.1)
}

#[capsule::bench(mempool_capacity = 511)]
fn set_sr_segments_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("packets::setting_segments_on_sr_across_segment_sizes");

    let mut rvg = Rvg::new();

    group.bench_function("packets::set_sr_segments::size=1", |b| {
        let segments = rvg.generate_vec(&any::<Ipv6Addr>(), 1);
        let s = (sr_tcp().prop_map(|v| v.into_sr()), Just(segments));
        b.iter_proptest_batched(s, set_sr_segments, BATCH_SIZE)
    });

    group.bench_function("packets::set_sr_segments::size=2", |b| {
        let segments = rvg.generate_vec(&any::<Ipv6Addr>(), 2);
        let s = (sr_tcp().prop_map(|v| v.into_sr()), Just(segments));
        b.iter_proptest_batched(s, set_sr_segments, BATCH_SIZE)
    });

    group.bench_function("packets::set_sr_segments::size=4", |b| {
        let segments = rvg.generate_vec(&any::<Ipv6Addr>(), 4);
        let s = (sr_tcp().prop_map(|v| v.into_sr()), Just(segments));
        b.iter_proptest_batched(s, set_sr_segments, BATCH_SIZE)
    });

    group.bench_function("packets::set_sr_segments::size=8", |b| {
        let segments = rvg.generate_vec(&any::<Ipv6Addr>(), 8);
        let s = (sr_tcp().prop_map(|v| v.into_sr()), Just(segments));
        b.iter_proptest_batched(s, set_sr_segments, BATCH_SIZE)
    });

    group.finish()
}

fn bench_config() -> Criterion {
    Criterion::default().with_plots()
}

criterion_group! {
    name = benches;
    config=bench_config();
    targets=single_peek_vs_parse,
            multi_peek_vs_parse,
            single_parse_sr_segments_sizes,
            multi_parse_upto_variable_sr,
            set_sr_segments_sizes,
            deparse,
            single_push,
            multi_push,
            single_remove,
            multi_remove,
            reset,
}

criterion_main!(benches);

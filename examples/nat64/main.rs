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
use bimap::BiMap;
use capsule::net::MacAddr;
use capsule::packets::ethernet::Ethernet;
use capsule::packets::ip::v4::Ip4;
use capsule::packets::ip::v6::{Ip6, Ipv6Packet};
use capsule::packets::ip::ProtocolNumbers;
use capsule::packets::tcp::{Tcp4, Tcp6};
use capsule::packets::{Mbuf, Packet, Postmark};
use capsule::runtime::{self, Outbox, Runtime};
use colored::Colorize;
use once_cell::sync::Lazy;
use signal_hook::consts;
use signal_hook::flag;
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use tracing::{info, Level};
use tracing_subscriber::fmt;

static PORTS: Lazy<Mutex<BiMap<(Ipv6Addr, u16), u16>>> = Lazy::new(|| Mutex::new(BiMap::new()));
static MACS: Lazy<Mutex<HashMap<Ipv6Addr, MacAddr>>> = Lazy::new(|| Mutex::new(HashMap::new()));

/// Maps the destination IPv6 address to its IPv4 counterpart by stripping
/// off the 96-bit prefix.
fn map_6to4(addr: Ipv6Addr) -> Ipv4Addr {
    let segments = addr.segments();
    let mapped = (segments[6] as u32) << 16 | (segments[7] as u32);
    mapped.into()
}

/// Looks up the assigned port for an IPv6 source.
fn get_ip4_port(mac: MacAddr, ip: Ipv6Addr, port: u16) -> u16 {
    static NEXT_PORT: AtomicU16 = AtomicU16::new(1025);

    let key = (ip, port);
    let mut ports = PORTS.lock().unwrap();

    if let Some(value) = ports.get_by_left(&key) {
        *value
    } else {
        let port = NEXT_PORT.fetch_add(1, Ordering::Relaxed);
        MACS.lock().unwrap().insert(ip, mac);
        ports.insert(key, port);
        port
    }
}

fn nat_6to4(packet: Mbuf, cap1: &Outbox) -> Result<Postmark> {
    const SRC_IP: Ipv4Addr = Ipv4Addr::new(10, 100, 1, 11);
    const DST_MAC: MacAddr = MacAddr::new(0x02, 0x00, 0x00, 0xff, 0xff, 0xff);

    let ethernet = packet.parse::<Ethernet>()?;
    let ip6 = ethernet.parse::<Ip6>()?;

    if ip6.next_header() == ProtocolNumbers::Tcp {
        let dscp = ip6.dscp();
        let ecn = ip6.ecn();
        let ttl = ip6.hop_limit() - 1;
        let protocol = ip6.next_header();
        let src_ip = ip6.src();
        let dst_ip = map_6to4(ip6.dst());
        let src_mac = ip6.envelope().src();

        let mut ethernet = ip6.remove()?;
        ethernet.swap_addresses();
        ethernet.set_dst(DST_MAC);

        let mut ip4 = ethernet.push::<Ip4>()?;
        ip4.set_dscp(dscp);
        ip4.set_ecn(ecn);
        ip4.set_ttl(ttl);
        ip4.set_protocol(protocol);
        ip4.set_src(SRC_IP);
        ip4.set_dst(dst_ip);

        let mut tcp = ip4.parse::<Tcp4>()?;
        let port = tcp.src_port();
        tcp.set_src_port(get_ip4_port(src_mac, src_ip, port));
        tcp.reconcile_all();

        let fmt = format!("{:?}", tcp.envelope()).magenta();
        info!("{}", fmt);
        let fmt = format!("{:?}", tcp).bright_blue();
        info!("{}", fmt);

        let _ = cap1.push(tcp);
        Ok(Postmark::Emit)
    } else {
        Ok(Postmark::Drop(ip6.reset()))
    }
}

/// Maps the source IPv4 address to its IPv6 counterpart with well-known
/// prefix `64:ff9b::/96`.
fn map_4to6(addr: Ipv4Addr) -> Ipv6Addr {
    let octets = addr.octets();
    Ipv6Addr::new(
        0x64,
        0xff9b,
        0x0,
        0x0,
        0x0,
        0x0,
        (octets[0] as u16) << 8 | (octets[1] as u16),
        (octets[2] as u16) << 8 | (octets[3] as u16),
    )
}

/// Looks up the IPv6 destination
fn get_ip6_dst(port: u16) -> Option<(MacAddr, Ipv6Addr, u16)> {
    PORTS
        .lock()
        .unwrap()
        .get_by_right(&port)
        .and_then(|(ip, port)| MACS.lock().unwrap().get(ip).map(|mac| (*mac, *ip, *port)))
}

fn nat_4to6(packet: Mbuf, cap0: &Outbox) -> Result<Postmark> {
    let ethernet = packet.parse::<Ethernet>()?;
    let ip4 = ethernet.parse::<Ip4>()?;

    if ip4.protocol() == ProtocolNumbers::Tcp && ip4.fragment_offset() == 0 && !ip4.more_fragments()
    {
        let tcp = ip4.peek::<Tcp4>()?;

        if let Some((dst_mac, dst_ip, port)) = get_ip6_dst(tcp.dst_port()) {
            let dscp = ip4.dscp();
            let ecn = ip4.ecn();
            let next_header = ip4.protocol();
            let hop_limit = ip4.ttl() - 1;
            let src_ip = map_4to6(ip4.src());

            let mut ethernet = ip4.remove()?;
            ethernet.swap_addresses();
            ethernet.set_dst(dst_mac);

            let mut ip6 = ethernet.push::<Ip6>()?;
            ip6.set_dscp(dscp);
            ip6.set_ecn(ecn);
            ip6.set_next_header(next_header);
            ip6.set_hop_limit(hop_limit);
            ip6.set_src(src_ip);
            ip6.set_dst(dst_ip);

            let mut tcp = ip6.parse::<Tcp6>()?;
            tcp.set_dst_port(port);
            tcp.reconcile_all();

            let fmt = format!("{:?}", tcp.envelope()).cyan();
            info!("{}", fmt);
            let fmt = format!("{:?}", tcp).bright_blue();
            info!("{}", fmt);

            let _ = cap0.push(tcp);
            Ok(Postmark::Emit)
        } else {
            Ok(Postmark::Drop(ip4.reset()))
        }
    } else {
        Ok(Postmark::Drop(ip4.reset()))
    }
}

fn main() -> Result<()> {
    let subscriber = fmt::Subscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let config = runtime::load_config()?;
    let runtime = Runtime::from_config(config)?;

    let cap1 = runtime.ports().get("cap1")?.outbox()?;
    runtime.set_port_pipeline("cap0", move |packet| nat_6to4(packet, &cap1))?;

    let cap0 = runtime.ports().get("cap0")?.outbox()?;
    runtime.set_port_pipeline("cap1", move |packet| nat_4to6(packet, &cap0))?;

    let _guard = runtime.execute()?;

    let term = Arc::new(AtomicBool::new(false));
    flag::register(consts::SIGINT, Arc::clone(&term))?;
    info!("ctrl-c to quit ...");
    while !term.load(Ordering::Relaxed) {}

    Ok(())
}

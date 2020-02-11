use chashmap::CHashMap;
use nb2::batch::Either;
use nb2::config::load_config;
use nb2::packets::ip::v4::Ipv4;
use nb2::packets::ip::v6::{Ipv6, Ipv6Packet};
use nb2::packets::ip::ProtocolNumbers;
use nb2::packets::{EtherTypes, Ethernet, Packet, Tcp};
use nb2::{compose, Batch, Pipeline, Poll, PortQueue, Result, Runtime};
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU16, Ordering};
use tracing::{debug, Level};
use tracing_subscriber::fmt;

const V4_ADDR: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 1);

static PORT_MAP: Lazy<CHashMap<(Ipv6Addr, u16), u16>> = Lazy::new(CHashMap::new);
static ADDR_MAP: Lazy<CHashMap<u16, (Ipv6Addr, u16)>> = Lazy::new(CHashMap::new);

/// Looks up the assigned port for a source IPv6 address and port tuple.
fn assigned_port(addr: Ipv6Addr, port: u16) -> u16 {
    static NEXT_PORT: AtomicU16 = AtomicU16::new(1025);

    let key = (addr, port);
    if let Some(value) = PORT_MAP.get(&key) {
        *value
    } else {
        let port = NEXT_PORT.fetch_add(1, Ordering::Relaxed);
        PORT_MAP.insert_new(key, port);
        ADDR_MAP.insert_new(port, key);
        port
    }
}

/// Looks up the IPv6 address and port the gateway port is assigned to.
fn assigned_addr(port: u16) -> Option<(Ipv6Addr, u16)> {
    // appears to be a false positive, bug filed with clippy
    // https://github.com/rust-lang/rust-clippy/issues/4824
    #[allow(clippy::map_clone)]
    ADDR_MAP.get(&port).map(|v| *v)
}

/// Maps the source IPv4 address to its IPv6 counterpart with well-known
/// prefix `64:ff9b::/96`.
fn map4to6(addr: Ipv4Addr) -> Ipv6Addr {
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

/// Maps the destination IPv6 address to its IPv4 counterpart by stripping
/// off the 96-bit prefix.
#[inline]
fn map6to4(addr: Ipv6Addr) -> Ipv4Addr {
    let segments = addr.segments();
    let mapped = (segments[6] as u32) << 16 | (segments[7] as u32);
    mapped.into()
}

#[inline]
fn nat_4to6(ethernet: Ethernet) -> Result<Either<Ethernet>> {
    let v4 = ethernet.parse::<Ipv4>()?;
    if v4.protocol() == ProtocolNumbers::Tcp && v4.fragment_offset() == 0 && !v4.more_fragments() {
        let tcp = v4.peek::<Tcp<Ipv4>>()?;
        if let Some((dst, port)) = assigned_addr(tcp.dst_port()) {
            let dscp = v4.dscp();
            let ecn = v4.ecn();
            let next_header = v4.protocol();
            let hop_limit = v4.ttl() - 1;
            let src = map4to6(v4.src());

            let ethernet = v4.remove()?;
            let mut v6 = ethernet.push::<Ipv6>()?;
            v6.set_dscp(dscp);
            v6.set_ecn(ecn);
            v6.set_next_header(next_header);
            v6.set_hop_limit(hop_limit);
            v6.set_src(src);
            v6.set_dst(dst);

            let mut tcp = v6.parse::<Tcp<Ipv6>>()?;
            tcp.set_dst_port(port);
            tcp.cascade();

            Ok(Either::Keep(tcp.deparse().deparse()))
        } else {
            Ok(Either::Drop(v4.reset()))
        }
    } else {
        Ok(Either::Drop(v4.reset()))
    }
}

#[inline]
fn nat_6to4(ethernet: Ethernet) -> Result<Either<Ethernet>> {
    let v6 = ethernet.parse::<Ipv6>()?;
    if v6.next_header() == ProtocolNumbers::Tcp {
        let dscp = v6.dscp();
        let ecn = v6.ecn();
        let ttl = v6.hop_limit() - 1;
        let protocol = v6.next_header();
        let src = v6.src();
        let dst = map6to4(v6.dst());

        let ethernet = v6.remove()?;
        let mut v4 = ethernet.push::<Ipv4>()?;
        v4.set_dscp(dscp);
        v4.set_ecn(ecn);
        v4.set_ttl(ttl);
        v4.set_protocol(protocol);
        v4.set_src(V4_ADDR);
        v4.set_dst(dst);

        let mut tcp = v4.parse::<Tcp<Ipv4>>()?;
        let port = tcp.src_port();
        tcp.set_src_port(assigned_port(src, port));
        tcp.cascade();

        Ok(Either::Keep(tcp.deparse().deparse()))
    } else {
        Ok(Either::Drop(v6.reset()))
    }
}

fn install(qs: HashMap<String, PortQueue>) -> impl Pipeline {
    Poll::new(qs["eth1"].clone())
        .map(|packet| packet.parse::<Ethernet>())
        .group_by(
            |ethernet| ethernet.ether_type(),
            |groups| {
                compose!( groups {
                    EtherTypes::Ipv4 => |group| {
                        group.filter_map(nat_4to6)
                    },
                    EtherTypes::Ipv6 => |group| {
                        group.filter_map(nat_6to4)
                    },
                    _ => |group| {
                        group.filter(|_| false)
                    }
                })
            },
        )
        .send(qs["eth2"].clone())
}

fn main() -> Result<()> {
    let subscriber = fmt::Subscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let config = load_config()?;
    debug!(?config);

    Runtime::build(config)?
        .add_pipeline_to_core(1, install)?
        .execute()
}

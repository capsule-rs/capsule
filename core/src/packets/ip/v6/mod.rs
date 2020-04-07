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

//! Internet Protocol v6 and extension headers.

mod fragment;
mod srh;

pub use self::fragment::*;
pub use self::srh::*;

use crate::packets::checksum::PseudoHeader;
use crate::packets::ip::{IpPacket, IpPacketError, ProtocolNumber, DEFAULT_IP_TTL};
use crate::packets::{EtherTypes, Ethernet, Header, Internal, Packet, PacketBase, ParseError};
use crate::{ensure, SizeOf};
use failure::Fallible;
use std::fmt;
use std::net::{IpAddr, Ipv6Addr};
use std::ptr::NonNull;

/// The minimum IPv6 MTU defined in [`IETF RFC 2460`].
///
/// [`IETF RFC 2460`]: https://tools.ietf.org/html/rfc2460#section-5
pub const IPV6_MIN_MTU: usize = 1280;

// Masks
const DSCP: u32 = 0x0fc0_0000;
const ECN: u32 = 0x0030_0000;
const FLOW: u32 = 0xfffff;

/// Internet Protocol v6 based on [`IETF RFC 8200`].
///
/// ```
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |Version|    DSCP   |ECN|              Flow Label               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |         Payload Length        |  Next Header  |   Hop Limit   |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |            Source Address (128 bits IPv6 address)             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |          Destination Address (128 bits IPv6 address)          |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// - *Version*:              4-bit Internet Protocol version number = 6.
///
/// - *DSCP*:                 6-bit Differentiated services codepoint defined
///                           in [`IETF RFC 2474`]. Used to select the per hop
///                           behavior a packet experiences at each node.
///
/// - *ECN*:                  2-bit Explicit congestion notification codepoint
///                           defined in [`IETF RFC 3168`].
///
/// - *Flow Label*:           20-bit flow label.
///
/// - *Payload Length*:       16-bit unsigned integer.  Length of the IPv6
///                           payload, i.e., the rest of the packet following
///                           this IPv6 header, in octets. (*Note* that any
///                           extension headers present are considered part of
///                           the payload, i.e., included in the length count.)
///
/// - *Next Header*:          8-bit selector.  Identifies the type of header
///                           immediately following the IPv6 header. Uses the
///                           same values as the IPv4 Protocol field
///                           [RFC-1700 et seq.].
///
/// - *Hop Limit*:            8-bit unsigned integer. Decremented by 1 by
///                           each node that forwards the packet. The packet
///                           is discarded if Hop Limit is decremented to zero.
///
/// - *Source Address*:       128-bit address of the originator of the packet.
///
/// - *Destination Address*:  128-bit address of the intended recipient of the
///                           packet (possibly not the ultimate recipient, if
///                           a Routing header is present).
///
/// [`IETF RFC 8200`]: https://tools.ietf.org/html/rfc8200#section-3
/// [`IETF RFC 2474`]: https://tools.ietf.org/html/rfc2474
/// [`IETF RFC 3168`]: https://tools.ietf.org/html/rfc3168
pub struct Ipv6 {
    envelope: Ethernet,
    header: NonNull<Ipv6Header>,
    offset: usize,
}

impl Ipv6 {
    /// Returns the protocol version. Should always be `6`.
    #[inline]
    pub fn version(&self) -> u8 {
        ((u32::from_be(self.header().version_to_flow_label) & 0xf000_0000) >> 28) as u8
    }

    /// Returns the differentiated services codepoint.
    #[inline]
    pub fn dscp(&self) -> u8 {
        ((u32::from_be(self.header().version_to_flow_label) & DSCP) >> 22) as u8
    }

    /// Sets the differentiated services codepoint.
    #[inline]
    pub fn set_dscp(&mut self, dscp: u8) {
        self.header_mut().version_to_flow_label = u32::to_be(
            (u32::from_be(self.header().version_to_flow_label) & !DSCP)
                | ((u32::from(dscp) << 22) & DSCP),
        );
    }

    /// Returns the explicit congestion notification codepoint.
    #[inline]
    pub fn ecn(&self) -> u8 {
        ((u32::from_be(self.header().version_to_flow_label) & ECN) >> 20) as u8
    }

    /// Sets the explicit congestion notification codepoint.
    #[inline]
    pub fn set_ecn(&mut self, ecn: u8) {
        self.header_mut().version_to_flow_label = u32::to_be(
            (u32::from_be(self.header().version_to_flow_label) & !ECN)
                | ((u32::from(ecn) << 20) & ECN),
        );
    }

    /// Returns the flow label.
    #[inline]
    pub fn flow_label(&self) -> u32 {
        u32::from_be(self.header().version_to_flow_label) & FLOW
    }

    /// Sets the flow label.
    #[inline]
    pub fn set_flow_label(&mut self, flow_label: u32) {
        self.header_mut().version_to_flow_label = u32::to_be(
            (u32::from_be(self.header().version_to_flow_label) & !FLOW) | (flow_label & FLOW),
        );
    }

    /// Returns the length of the payload measured in octets.
    #[inline]
    pub fn payload_length(&self) -> u16 {
        u16::from_be(self.header().payload_length)
    }

    /// Sets the length of the payload.
    #[inline]
    fn set_payload_length(&mut self, payload_length: u16) {
        self.header_mut().payload_length = u16::to_be(payload_length);
    }

    /// Returns the packet's hop limit.
    #[inline]
    pub fn hop_limit(&self) -> u8 {
        self.header().hop_limit
    }

    /// Sets the packet's hop limit.
    #[inline]
    pub fn set_hop_limit(&mut self, hop_limit: u8) {
        self.header_mut().hop_limit = hop_limit;
    }

    /// Returns the source address.
    #[inline]
    pub fn src(&self) -> Ipv6Addr {
        self.header().src
    }

    /// Sets the source address.
    #[inline]
    pub fn set_src(&mut self, src: Ipv6Addr) {
        self.header_mut().src = src;
    }

    /// Returns the destination address.
    #[inline]
    pub fn dst(&self) -> Ipv6Addr {
        self.header().dst
    }

    /// Sets the destination address.
    #[inline]
    pub fn set_dst(&mut self, dst: Ipv6Addr) {
        self.header_mut().dst = dst;
    }
}

impl fmt::Debug for Ipv6 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ipv6")
            .field("src", &format!("{}", self.src()))
            .field("dst", &format!("{}", self.dst()))
            .field("dscp", &self.dscp())
            .field("ecn", &self.ecn())
            .field("flow_label", &self.flow_label())
            .field("payload_length", &self.payload_length())
            .field("next_header", &format!("{}", self.next_header()))
            .field("hop_limit", &self.hop_limit())
            .field("$offset", &self.offset())
            .field("$len", &self.len())
            .field("$header_len", &self.header_len())
            .finish()
    }
}

impl PacketBase for Ipv6 {
    fn clone(&self, internal: Internal) -> Self {
        Ipv6 {
            envelope: self.envelope.clone(internal),
            header: self.header,
            offset: self.offset,
        }
    }
}

impl Packet for Ipv6 {
    type Header = Ipv6Header;
    type Envelope = Ethernet;

    #[inline]
    fn envelope(&self) -> &Self::Envelope {
        &self.envelope
    }

    #[inline]
    fn envelope_mut(&mut self) -> &mut Self::Envelope {
        &mut self.envelope
    }

    #[doc(hidden)]
    #[inline]
    fn header(&self) -> &Self::Header {
        unsafe { self.header.as_ref() }
    }

    #[doc(hidden)]
    #[inline]
    fn header_mut(&mut self) -> &mut Self::Header {
        unsafe { self.header.as_mut() }
    }

    #[inline]
    fn offset(&self) -> usize {
        self.offset
    }

    #[doc(hidden)]
    #[inline]
    fn do_parse(envelope: Self::Envelope) -> Fallible<Self> {
        ensure!(
            envelope.ether_type() == EtherTypes::Ipv6,
            ParseError::new("not an IPv6 packet.")
        );

        let mbuf = envelope.mbuf();
        let offset = envelope.payload_offset();
        let header = mbuf.read_data(offset)?;

        Ok(Ipv6 {
            envelope,
            header,
            offset,
        })
    }

    #[doc(hidden)]
    #[inline]
    fn do_push(mut envelope: Self::Envelope) -> Fallible<Self> {
        let offset = envelope.payload_offset();
        let mbuf = envelope.mbuf_mut();

        mbuf.extend(offset, Self::Header::size_of())?;
        let header = mbuf.write_data(offset, &Self::Header::default())?;

        envelope.set_ether_type(EtherTypes::Ipv6);

        Ok(Ipv6 {
            envelope,
            header,
            offset,
        })
    }

    #[inline]
    fn remove(mut self) -> Fallible<Self::Envelope> {
        let offset = self.offset();
        let len = self.header_len();
        self.mbuf_mut().shrink(offset, len)?;
        Ok(self.envelope)
    }

    #[inline]
    fn cascade(&mut self) {
        let len = self.payload_len() as u16;
        self.set_payload_length(len);
        self.envelope_mut().cascade();
    }

    #[inline]
    fn deparse(self) -> Self::Envelope {
        self.envelope
    }
}

impl IpPacket for Ipv6 {
    #[inline]
    fn next_protocol(&self) -> ProtocolNumber {
        self.next_header()
    }

    #[inline]
    fn set_next_protocol(&mut self, proto: ProtocolNumber) {
        self.set_next_header(proto);
    }

    #[inline]
    fn src(&self) -> IpAddr {
        IpAddr::V6(self.src())
    }

    #[inline]
    fn set_src(&mut self, src: IpAddr) -> Fallible<()> {
        match src {
            IpAddr::V6(addr) => {
                self.set_src(addr);
                Ok(())
            }
            _ => Err(IpPacketError::IpAddrMismatch.into()),
        }
    }

    #[inline]
    fn dst(&self) -> IpAddr {
        IpAddr::V6(self.dst())
    }

    #[inline]
    fn set_dst(&mut self, dst: IpAddr) -> Fallible<()> {
        match dst {
            IpAddr::V6(addr) => {
                self.set_dst(addr);
                Ok(())
            }
            _ => Err(IpPacketError::IpAddrMismatch.into()),
        }
    }

    #[inline]
    fn pseudo_header(&self, packet_len: u16, protocol: ProtocolNumber) -> PseudoHeader {
        PseudoHeader::V6 {
            src: self.src(),
            dst: self.dst(),
            packet_len,
            protocol,
        }
    }

    #[inline]
    fn truncate(&mut self, mtu: usize) -> Fallible<()> {
        ensure!(
            mtu >= IPV6_MIN_MTU,
            IpPacketError::MtuTooSmall(mtu, IPV6_MIN_MTU)
        );

        // accounts for the Ethernet frame length.
        let to_len = mtu + self.offset();
        self.mbuf_mut().truncate(to_len)
    }
}

impl Ipv6Packet for Ipv6 {
    #[inline]
    fn next_header(&self) -> ProtocolNumber {
        ProtocolNumber::new(self.header().next_header)
    }

    #[inline]
    fn set_next_header(&mut self, next_header: ProtocolNumber) {
        self.header_mut().next_header = next_header.0;
    }
}

/// Common behaviors shared by IPv6 and extension packets.
pub trait Ipv6Packet: IpPacket {
    /// Returns the next header type.
    fn next_header(&self) -> ProtocolNumber;

    /// Sets the next header type.
    fn set_next_header(&mut self, next_header: ProtocolNumber);
}

/// IPv6 header accessible through [`Ipv6`].
///
/// [`Ipv6`]: Ipv6
#[derive(Clone, Copy, Debug, SizeOf)]
#[repr(C)]
pub struct Ipv6Header {
    version_to_flow_label: u32,
    payload_length: u16,
    next_header: u8,
    hop_limit: u8,
    src: Ipv6Addr,
    dst: Ipv6Addr,
}

impl Default for Ipv6Header {
    fn default() -> Ipv6Header {
        Ipv6Header {
            version_to_flow_label: u32::to_be(6 << 28),
            payload_length: 0,
            next_header: 0,
            hop_limit: DEFAULT_IP_TTL,
            src: Ipv6Addr::UNSPECIFIED,
            dst: Ipv6Addr::UNSPECIFIED,
        }
    }
}

impl Header for Ipv6Header {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packets::ip::ProtocolNumbers;
    use crate::testils::byte_arrays::{IPV4_UDP_PACKET, IPV6_TCP_PACKET};
    use crate::Mbuf;

    #[test]
    fn size_of_ipv6_header() {
        assert_eq!(40, Ipv6Header::size_of());
    }

    #[capsule::test]
    fn parse_ipv6_packet() {
        let packet = Mbuf::from_bytes(&IPV6_TCP_PACKET).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();
        let ipv6 = ethernet.parse::<Ipv6>().unwrap();

        assert_eq!(6, ipv6.version());
        assert_eq!(0, ipv6.dscp());
        assert_eq!(0, ipv6.ecn());
        assert_eq!(0, ipv6.flow_label());
        assert_eq!(24, ipv6.payload_len());
        assert_eq!(ProtocolNumbers::Tcp, ipv6.next_header());
        assert_eq!(2, ipv6.hop_limit());
        assert_eq!("2001:db8:85a3::1", ipv6.src().to_string());
        assert_eq!("2001:db8:85a3::8a2e:370:7334", ipv6.dst().to_string());
    }

    #[capsule::test]
    fn parse_non_ipv6_packet() {
        let packet = Mbuf::from_bytes(&IPV4_UDP_PACKET).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();

        assert!(ethernet.parse::<Ipv6>().is_err());
    }

    #[capsule::test]
    fn parse_ipv6_setter_checks() {
        let packet = Mbuf::from_bytes(&IPV6_TCP_PACKET).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();
        let mut ipv6 = ethernet.parse::<Ipv6>().unwrap();

        assert_eq!(6, ipv6.version());
        assert_eq!(0, ipv6.dscp());
        assert_eq!(0, ipv6.ecn());
        assert_eq!(0, ipv6.flow_label());
        ipv6.set_dscp(10);
        ipv6.set_ecn(3);
        assert_eq!(6, ipv6.version());
        assert_eq!(10, ipv6.dscp());
        assert_eq!(3, ipv6.ecn());
        assert_eq!(0, ipv6.flow_label());
    }

    #[capsule::test]
    fn push_ipv6_packet() {
        let packet = Mbuf::new().unwrap();
        let ethernet = packet.push::<Ethernet>().unwrap();
        let ipv6 = ethernet.push::<Ipv6>().unwrap();

        assert_eq!(6, ipv6.version());
        assert_eq!(Ipv6Header::size_of(), ipv6.len());

        // make sure ether type is fixed
        assert_eq!(EtherTypes::Ipv6, ipv6.envelope().ether_type());
    }

    #[capsule::test]
    fn truncate_ipv6_packet() {
        // prime the buffer with 1800 bytes of data
        let mut packet = Mbuf::new().unwrap();
        let _ = packet.extend(0, 1800);

        let ethernet = packet.push::<Ethernet>().unwrap();
        let mut ipv6 = ethernet.push::<Ipv6>().unwrap();

        // can't truncate to less than minimum MTU.
        assert!(ipv6.truncate(1200).is_err());

        assert!(ipv6.len() > 1500);
        let _ = ipv6.truncate(1500);
        assert_eq!(1500, ipv6.len());
    }
}

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

//! Internet Protocol v4.

use crate::packets::checksum::{self, PseudoHeader};
use crate::packets::ip::{IpPacket, IpPacketError, ProtocolNumber, DEFAULT_IP_TTL};
use crate::packets::types::u16be;
use crate::packets::{EtherTypes, Ethernet, Internal, Packet, ParseError};
use crate::{ensure, SizeOf};
use failure::Fallible;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr};
use std::ptr::NonNull;

/// The minimum IPv4 MTU defined in [IETF RFC 791].
///
/// Every internet module must be able to forward a datagram of 68 octets
/// without further fragmentation.  This is because an internet header may
/// be up to 60 octets, and the minimum fragment is 8 octets.
///
/// [IETF RFC 791]: https://tools.ietf.org/html/rfc791
pub const IPV4_MIN_MTU: usize = 68;

// Masks.
const DSCP: u8 = 0b1111_1100;
const ECN: u8 = !DSCP;
const FLAGS_DF: u16be = u16be(u16::to_be(0b0100_0000_0000_0000));
const FLAGS_MF: u16be = u16be(u16::to_be(0b0010_0000_0000_0000));

/// Internet Protocol v4 based on [IETF RFC 791].
///
/// ```
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |Version|  IHL  |    DSCP   |ECN|          Total Length         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |         Identification        |Flags|      Fragment Offset    |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |  Time to Live |    Protocol   |         Header Checksum       |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                       Source Address                          |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                    Destination Address                        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                    Options                    |    Padding    |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// - *Version*: (4 bits)
///      The Version field indicates the format of the internet header. This
///      document describes version 4.
///
/// - *IHL*: (4 bits)
///      Internet Header Length is the length of the internet header in 32
///      bit words, and thus points to the beginning of the data. Note that
///      the minimum value for a correct header is 5.
///
/// - *DSCP*: (6 bits)
///      Differentiated services codepoint defined in [IETF RFC 2474]. Used to
///      select the per hop behavior a packet experiences at each node.
///
/// - *ECN*: (2 bits)
///      Explicit congestion notification codepoint defined in [IETF RFC 3168].
///
/// - *Total Length*: (16 bits)
///      Total Length is the length of the datagram, measured in octets,
///      including internet header and data.
///
/// - *Identification*: (16 bits)
///      An identifying value assigned by the sender to aid in assembling the
///      fragments of a datagram.
///
/// - *Flags*: (3 bits)
///      Various Control Flags.
///
///      - Bit 0: reserved, must be zero
///      - Bit 1: (DF) 0 = May Fragment,  1 = Don't Fragment.
///      - Bit 2: (MF) 0 = Last Fragment, 1 = More Fragments.
///
///              0   1   2
///            +---+---+---+
///            |   | D | M |
///            | 0 | F | F |
///            +---+---+---+
///
/// - *Fragment Offset*: (13 bits)
///      This field indicates where in the datagram this fragment belongs.
///      The fragment offset is measured in units of 8 octets (64 bits). The
///      first fragment has offset zero.
///
/// - *Time to Live*: (8 bits)
///      This field indicates the maximum time the datagram is allowed to
///      remain in the internet system. If this field contains the value
///      zero, then the datagram must be destroyed. This field is modified
///      in internet header processing. The time is measured in units of
///      seconds, but since every module that processes a datagram must
///      decrease the TTL by at least one even if it process the datagram in
///      less than a second, the TTL must be thought of only as an upper
///      bound on the time a datagram may exist. The intention is to cause
///      undeliverable datagrams to be discarded, and to bound the maximum
///      datagram lifetime.
///
/// - *Protocol*: (8 bits)
///      This field indicates the next level protocol used in the data
///      portion of the internet datagram. The values for various protocols
///      are specified in "Assigned Numbers."
///
/// - *Header Checksum*: (16 bits)
///      A checksum on the header only. Since some header fields change
///      (e.g., time to live), this is recomputed and verified at each point
///      that the internet header is processed.
///
/// - *Source Address*: (32 bits)
///      The source address.
///
/// - *Destination Address*: (32 bits)
///      The destination address.
///
/// - *Options*:  (variable)
///      The options may appear or not in datagrams. They must be
///      implemented by all IP modules (host and gateways). What is optional
///      is their transmission in any particular datagram, not their
///      implementation.
///
/// [IETF RFC 791]: https://tools.ietf.org/html/rfc791#section-3.1
/// [IETF RFC 2474]: https://tools.ietf.org/html/rfc2474
/// [IETF RFC 3168]: https://tools.ietf.org/html/rfc3168
pub struct Ipv4 {
    envelope: Ethernet,
    header: NonNull<Ipv4Header>,
    offset: usize,
}

impl Ipv4 {
    #[inline]
    fn header(&self) -> &Ipv4Header {
        unsafe { self.header.as_ref() }
    }

    #[inline]
    fn header_mut(&mut self) -> &mut Ipv4Header {
        unsafe { self.header.as_mut() }
    }

    /// Returns the protocol version. Should always be `4`.
    #[inline]
    pub fn version(&self) -> u8 {
        (self.header().version_ihl & 0xf0) >> 4
    }

    /// Returns the length of the internet header measured in number of
    /// 32-bit words. This indicates where the data begins.
    #[inline]
    pub fn ihl(&self) -> u8 {
        self.header().version_ihl & 0x0f
    }

    #[allow(dead_code)]
    #[inline]
    fn set_ihl(&mut self, ihl: u8) {
        self.header_mut().version_ihl = (self.header().version_ihl & 0x0f) | (ihl & 0x0f);
    }

    /// Returns the differentiated services codepoint.
    #[inline]
    pub fn dscp(&self) -> u8 {
        self.header().dscp_ecn >> 2
    }

    /// Sets the differentiated services codepoint.
    #[inline]
    pub fn set_dscp(&mut self, dscp: u8) {
        self.header_mut().dscp_ecn = (self.header().dscp_ecn & ECN) | (dscp << 2);
    }

    /// Returns the explicit congestion notification codepoint.
    #[inline]
    pub fn ecn(&self) -> u8 {
        self.header().dscp_ecn & ECN
    }

    /// Sets the explicit congestion notification codepoint.
    #[inline]
    pub fn set_ecn(&mut self, ecn: u8) {
        self.header_mut().dscp_ecn = (self.header().dscp_ecn & DSCP) | (ecn & ECN);
    }

    /// Returns the length of the packet, measured in octets, including
    /// the header and data.
    #[inline]
    pub fn total_length(&self) -> u16 {
        self.header().total_length.into()
    }

    /// Sets the length of the packet.
    #[inline]
    fn set_total_length(&mut self, total_length: u16) {
        self.header_mut().total_length = total_length.into();
    }

    /// Returns the identifying value assigned by the sender to aid in
    /// assembling the fragments of a packet.
    #[inline]
    pub fn identification(&self) -> u16 {
        self.header().identification.into()
    }

    /// Sets the identifying value.
    #[inline]
    pub fn set_identification(&mut self, identification: u16) {
        self.header_mut().identification = identification.into();
    }

    /// Returns a flag indicating whether the packet can be fragmented.
    #[inline]
    pub fn dont_fragment(&self) -> bool {
        self.header().flags_to_frag_offset & FLAGS_DF != u16be::MIN
    }

    /// Sets the don't fragment flag to indicate that the packet must not
    /// be fragmented.
    #[inline]
    pub fn set_dont_fragment(&mut self) {
        self.header_mut().flags_to_frag_offset |= FLAGS_DF
    }

    /// Unsets the don't fragment flag to indicate that the packet may be
    /// fragmented.
    #[inline]
    pub fn unset_dont_fragment(&mut self) {
        self.header_mut().flags_to_frag_offset &= !FLAGS_DF
    }

    /// Returns a flag indicating whether there are more fragments.
    #[inline]
    pub fn more_fragments(&self) -> bool {
        self.header().flags_to_frag_offset & FLAGS_MF != u16be::MIN
    }

    /// Sets the more fragment flag indicating there are more fragments.
    #[inline]
    pub fn set_more_fragments(&mut self) {
        self.header_mut().flags_to_frag_offset |= FLAGS_MF
    }

    /// Unsets the more fragment flag indicating this is the last fragment.
    #[inline]
    pub fn unset_more_fragments(&mut self) {
        self.header_mut().flags_to_frag_offset &= !FLAGS_MF
    }

    /// Returns an offset indicating where in the datagram this fragment
    /// belongs. It is measured in units of 8 octets or 64 bits. The first
    /// fragment has offset zero.
    #[inline]
    pub fn fragment_offset(&self) -> u16 {
        (self.header().flags_to_frag_offset & u16be::from(0x1fff)).into()
    }

    /// Sets the fragment offset.
    #[inline]
    pub fn set_fragment_offset(&mut self, offset: u16) {
        self.header_mut().flags_to_frag_offset = (self.header().flags_to_frag_offset
            & u16be::from(0xe000))
            | u16be::from(offset & 0x1fff)
    }

    /// Returns the packet's time to live.
    #[inline]
    pub fn ttl(&self) -> u8 {
        self.header().ttl
    }

    /// Sets the time to live.
    #[inline]
    pub fn set_ttl(&mut self, ttl: u8) {
        self.header_mut().ttl = ttl;
    }

    /// Returns the next level protocol in the packet payload.
    #[inline]
    pub fn protocol(&self) -> ProtocolNumber {
        ProtocolNumber::new(self.header().protocol)
    }

    /// Sets the next level protocol.
    #[inline]
    pub fn set_protocol(&mut self, protocol: ProtocolNumber) {
        self.header_mut().protocol = protocol.0;
    }

    /// Returns the checksum.
    #[inline]
    pub fn checksum(&self) -> u16 {
        self.header().checksum.into()
    }

    /// Sets the checksum.
    #[inline]
    fn set_checksum(&mut self, checksum: u16) {
        self.header_mut().checksum = checksum.into();
    }

    #[inline]
    fn compute_checksum(&mut self) {
        self.set_checksum(0);

        if let Ok(data) = self.mbuf().read_data_slice(self.offset, self.header_len()) {
            let data = unsafe { data.as_ref() };
            let checksum = checksum::compute(0, data);
            self.set_checksum(checksum);
        } else {
            // we are reading the entire header, should never run out
            unreachable!()
        }
    }

    /// Returns the source address.
    #[inline]
    pub fn src(&self) -> Ipv4Addr {
        self.header().src
    }

    /// Sets the source address.
    #[inline]
    pub fn set_src(&mut self, src: Ipv4Addr) {
        self.header_mut().src = src;
    }

    /// Returns the destination address.
    #[inline]
    pub fn dst(&self) -> Ipv4Addr {
        self.header().dst
    }

    /// Sets the destination address.
    #[inline]
    pub fn set_dst(&mut self, dst: Ipv4Addr) {
        self.header_mut().dst = dst;
    }
}

impl fmt::Debug for Ipv4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ipv4")
            .field("src", &format!("{}", self.src()))
            .field("dst", &format!("{}", self.dst()))
            .field("version", &self.version())
            .field("ihl", &self.ihl())
            .field("dscp", &self.dscp())
            .field("ecn", &self.ecn())
            .field("total_length", &self.total_length())
            .field("dont_fragment", &self.dont_fragment())
            .field("more_fragments", &self.more_fragments())
            .field("fragment_offset", &self.fragment_offset())
            .field("ttl", &self.ttl())
            .field("protocol", &format!("{}", self.protocol()))
            .field("checksum", &format!("0x{:04x}", self.checksum()))
            .field("$offset", &self.offset())
            .field("$len", &self.len())
            .field("$header_len", &self.header_len())
            .finish()
    }
}

impl Packet for Ipv4 {
    /// The preceding type for an IPv4 packet must be Ethernet.
    type Envelope = Ethernet;

    #[inline]
    fn envelope(&self) -> &Self::Envelope {
        &self.envelope
    }

    #[inline]
    fn envelope_mut(&mut self) -> &mut Self::Envelope {
        &mut self.envelope
    }

    #[inline]
    fn offset(&self) -> usize {
        self.offset
    }

    #[inline]
    fn header_len(&self) -> usize {
        Ipv4Header::size_of()
    }

    #[inline]
    unsafe fn clone(&self, internal: Internal) -> Self {
        Ipv4 {
            envelope: self.envelope.clone(internal),
            header: self.header,
            offset: self.offset,
        }
    }

    /// Parses the Ethernet's payload as an IPv4 packet.
    ///
    /// [`ether_type`] must be set to [`EtherTypes::Ipv4`]. Otherwise a parsing
    /// error is returned.
    ///
    /// [`ether_type`]: Ethernet::ether_type
    /// [`EtherTypes::Ipv4`]: EtherTypes::Ipv4
    #[inline]
    fn try_parse(envelope: Self::Envelope, _internal: Internal) -> Fallible<Self> {
        ensure!(
            envelope.ether_type() == EtherTypes::Ipv4,
            ParseError::new("not an IPv4 packet.")
        );

        let mbuf = envelope.mbuf();
        let offset = envelope.payload_offset();
        let header = mbuf.read_data(offset)?;

        Ok(Ipv4 {
            envelope,
            header,
            offset,
        })
    }

    /// Prepends an IPv4 packet to the beginning of the Ethernet's payload.
    ///
    /// [`ether_type`] is set to [`EtherTypes::Ipv4`].
    ///
    /// [`ether_type`]: Ethernet::ether_type
    /// [`EtherTypes::Ipv4`]: EtherTypes::Ipv4
    #[inline]
    fn try_push(mut envelope: Self::Envelope, _internal: Internal) -> Fallible<Self> {
        let offset = envelope.payload_offset();
        let mbuf = envelope.mbuf_mut();

        mbuf.extend(offset, Ipv4Header::size_of())?;
        let header = mbuf.write_data(offset, &Ipv4Header::default())?;

        envelope.set_ether_type(EtherTypes::Ipv4);

        Ok(Ipv4 {
            envelope,
            header,
            offset,
        })
    }

    #[inline]
    fn deparse(self) -> Self::Envelope {
        self.envelope
    }

    /// Reconciles the derivable header fields against the changes made to
    /// the packet.
    ///
    /// * [`total_length`] is set to the total length of the header and the
    /// payload.
    /// * [`checksum`] is computed based on the IPv4 header.
    ///
    /// [`total_length`]: Ipv4::total_length
    /// [`checksum`]: Ipv4::checksum
    #[inline]
    fn reconcile(&mut self) {
        self.set_total_length(self.len() as u16);
        self.compute_checksum();
    }
}

impl IpPacket for Ipv4 {
    #[inline]
    fn next_protocol(&self) -> ProtocolNumber {
        self.protocol()
    }

    #[inline]
    fn set_next_protocol(&mut self, proto: ProtocolNumber) {
        self.set_protocol(proto);
    }

    #[inline]
    fn src(&self) -> IpAddr {
        IpAddr::V4(self.src())
    }

    #[inline]
    fn set_src(&mut self, src: IpAddr) -> Fallible<()> {
        match src {
            IpAddr::V4(addr) => {
                self.set_src(addr);
                Ok(())
            }
            _ => Err(IpPacketError::IpAddrMismatch.into()),
        }
    }

    #[inline]
    fn dst(&self) -> IpAddr {
        IpAddr::V4(self.dst())
    }

    #[inline]
    fn set_dst(&mut self, dst: IpAddr) -> Fallible<()> {
        match dst {
            IpAddr::V4(addr) => {
                self.set_dst(addr);
                Ok(())
            }
            _ => Err(IpPacketError::IpAddrMismatch.into()),
        }
    }

    #[inline]
    fn pseudo_header(&self, packet_len: u16, protocol: ProtocolNumber) -> PseudoHeader {
        PseudoHeader::V4 {
            src: self.src(),
            dst: self.dst(),
            packet_len,
            protocol,
        }
    }

    #[inline]
    fn truncate(&mut self, mtu: usize) -> Fallible<()> {
        ensure!(
            mtu >= IPV4_MIN_MTU,
            IpPacketError::MtuTooSmall(mtu, IPV4_MIN_MTU)
        );

        // accounts for the Ethernet frame length.
        let to_len = mtu + self.offset();
        self.mbuf_mut().truncate(to_len)
    }
}

/// IPv4 header.
///
/// The header only include the fixed portion of the IPv4 header.
/// Options are parsed separately.
#[derive(Clone, Copy, Debug, SizeOf)]
#[repr(C, packed)]
struct Ipv4Header {
    version_ihl: u8,
    dscp_ecn: u8,
    total_length: u16be,
    identification: u16be,
    flags_to_frag_offset: u16be,
    ttl: u8,
    protocol: u8,
    checksum: u16be,
    src: Ipv4Addr,
    dst: Ipv4Addr,
}

impl Default for Ipv4Header {
    fn default() -> Ipv4Header {
        Ipv4Header {
            version_ihl: 0x45,
            dscp_ecn: 0,
            total_length: u16be::default(),
            identification: u16be::default(),
            flags_to_frag_offset: u16be::default(),
            ttl: DEFAULT_IP_TTL,
            protocol: 0,
            checksum: u16be::default(),
            src: Ipv4Addr::UNSPECIFIED,
            dst: Ipv4Addr::UNSPECIFIED,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packets::ip::ProtocolNumbers;
    use crate::testils::byte_arrays::{IPV4_UDP_PACKET, IPV6_TCP_PACKET};
    use crate::Mbuf;

    #[test]
    fn size_of_ipv4_header() {
        assert_eq!(20, Ipv4Header::size_of());
    }

    #[capsule::test]
    fn parse_ipv4_packet() {
        let packet = Mbuf::from_bytes(&IPV4_UDP_PACKET).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();
        let ipv4 = ethernet.parse::<Ipv4>().unwrap();

        assert_eq!(4, ipv4.version());
        assert_eq!(5, ipv4.ihl());
        assert_eq!(38, ipv4.total_length());
        assert_eq!(43849, ipv4.identification());
        assert_eq!(true, ipv4.dont_fragment());
        assert_eq!(false, ipv4.more_fragments());
        assert_eq!(0, ipv4.fragment_offset());
        assert_eq!(0, ipv4.dscp());
        assert_eq!(0, ipv4.ecn());
        assert_eq!(255, ipv4.ttl());
        assert_eq!(ProtocolNumbers::Udp, ipv4.protocol());
        assert_eq!(0xf700, ipv4.checksum());
        assert_eq!("139.133.217.110", ipv4.src().to_string());
        assert_eq!("139.133.233.2", ipv4.dst().to_string());
    }

    #[capsule::test]
    fn parse_non_ipv4_packet() {
        let packet = Mbuf::from_bytes(&IPV6_TCP_PACKET).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();

        assert!(ethernet.parse::<Ipv4>().is_err());
    }

    #[capsule::test]
    fn parse_ipv4_setter_checks() {
        let packet = Mbuf::from_bytes(&IPV4_UDP_PACKET).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();
        let mut ipv4 = ethernet.parse::<Ipv4>().unwrap();

        // Fields
        ipv4.set_ihl(ipv4.ihl());

        // Flags
        assert_eq!(true, ipv4.dont_fragment());
        assert_eq!(false, ipv4.more_fragments());

        ipv4.unset_dont_fragment();
        assert_eq!(false, ipv4.dont_fragment());
        ipv4.set_dont_fragment();
        assert_eq!(true, ipv4.dont_fragment());

        ipv4.set_more_fragments();
        assert_eq!(true, ipv4.more_fragments());
        ipv4.unset_more_fragments();
        assert_eq!(false, ipv4.more_fragments());

        ipv4.set_fragment_offset(5);
        assert_eq!(5, ipv4.fragment_offset());

        // DSCP & ECN
        assert_eq!(0, ipv4.dscp());
        assert_eq!(0, ipv4.ecn());
        ipv4.set_dscp(10);
        ipv4.set_ecn(3);
        assert_eq!(10, ipv4.dscp());
        assert_eq!(3, ipv4.ecn());
    }

    #[capsule::test]
    fn push_ipv4_packet() {
        let packet = Mbuf::new().unwrap();
        let ethernet = packet.push::<Ethernet>().unwrap();
        let ipv4 = ethernet.push::<Ipv4>().unwrap();

        assert_eq!(4, ipv4.version());
        assert_eq!(Ipv4Header::size_of(), ipv4.len());

        // make sure ether type is fixed
        assert_eq!(EtherTypes::Ipv4, ipv4.envelope().ether_type());
    }

    #[capsule::test]
    fn truncate_ipv4_packet() {
        // prime the buffer with 2000 bytes of data
        let mut packet = Mbuf::new().unwrap();
        let _ = packet.extend(0, 2000);

        let ethernet = packet.push::<Ethernet>().unwrap();
        let mut ipv4 = ethernet.push::<Ipv4>().unwrap();

        // can't truncate to less than minimum MTU.
        assert!(ipv4.truncate(60).is_err());

        assert!(ipv4.len() > 1000);
        let _ = ipv4.truncate(1000);
        assert_eq!(1000, ipv4.len());
    }

    #[capsule::test]
    fn compute_checksum() {
        let packet = Mbuf::from_bytes(&IPV4_UDP_PACKET).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();
        let mut ipv4 = ethernet.parse::<Ipv4>().unwrap();

        let expected = ipv4.checksum();
        // no payload change but force a checksum recompute anyway
        ipv4.reconcile_all();
        assert_eq!(expected, ipv4.checksum());
    }
}

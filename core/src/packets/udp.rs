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

use crate::packets::ip::{Flow, IpPacket, ProtocolNumbers};
use crate::packets::types::u16be;
use crate::packets::{checksum, Internal, Packet, ParseError};
use crate::{ensure, SizeOf};
use failure::Fallible;
use std::fmt;
use std::net::IpAddr;
use std::ptr::NonNull;

/// User Datagram Protocol packet based on [IETF RFC 768].
///
/// ```
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |          Source Port          |       Destination Port        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |             Length            |            Checksum           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                             data                              |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// - *Source Port*: (16 bits)
///      An  optional field that, when meaningful, indicates the port
///      of the sending process, and may be assumed to be the port to which a
///      reply should be addressed in the absence of any other information. If
///      not used, a value of zero is inserted.
///
/// - *Destination Port*: (16 bits)
///      Has a meaning  within the context of a particular Internet
///      destination address.
///
/// - *Length*: (16 bits)
///      The length  in octets of this user datagram including its
///      header and the data. (This means the minimum value of the length is
///      eight.)
///
/// - *Checksum*: (16 bits)
///      The 16-bit one's complement of the one's complement sum of a
///      pseudo header of information from the IP header, the UDP header, and
///      the data, padded with zero octets at the end (if necessary) to make a
///      multiple of two octets.
///
///      The pseudo header conceptually prefixed to the UDP header contains the
///      source address, the destination address, the protocol, and the UDP
///      length. This information gives protection against misrouted datagrams.
///      This checksum procedure is the same as is used in TCP.
///
/// [IETF RFC 768]: https://tools.ietf.org/html/rfc768
pub struct Udp<E: IpPacket> {
    envelope: E,
    header: NonNull<UdpHeader>,
    offset: usize,
}

impl<E: IpPacket> Udp<E> {
    #[inline]
    fn header(&self) -> &UdpHeader {
        unsafe { self.header.as_ref() }
    }

    #[inline]
    fn header_mut(&mut self) -> &mut UdpHeader {
        unsafe { self.header.as_mut() }
    }

    /// Returns the source port.
    #[inline]
    pub fn src_port(&self) -> u16 {
        self.header().src_port.into()
    }

    /// Sets the source port.
    #[inline]
    pub fn set_src_port(&mut self, src_port: u16) {
        self.header_mut().src_port = src_port.into();
    }

    /// Returns the destination port.
    #[inline]
    pub fn dst_port(&self) -> u16 {
        self.header().dst_port.into()
    }

    /// Sets the destination port.
    #[inline]
    pub fn set_dst_port(&mut self, dst_port: u16) {
        self.header_mut().dst_port = dst_port.into();
    }

    /// Returns the length in octets of this user datagram including this
    /// header and the data.
    #[inline]
    pub fn length(&self) -> u16 {
        self.header().length.into()
    }

    #[inline]
    fn set_length(&mut self, length: u16) {
        self.header_mut().length = length.into()
    }

    /// Returns the checksum.
    #[inline]
    pub fn checksum(&self) -> u16 {
        self.header().checksum.into()
    }

    /// Sets the checksum.
    #[inline]
    fn set_checksum(&mut self, checksum: u16) {
        // For UDP, if the computed checksum is zero, it is transmitted as
        // all ones. An all zero transmitted checksum value means that the
        // transmitter generated no checksum. To set the checksum value to
        // `0`, use `no_checksum` instead of `set_checksum`.
        self.header_mut().checksum = match checksum {
            0 => u16be::from(0xFFFF),
            _ => checksum.into(),
        }
    }

    /// Sets checksum to 0 indicating no checksum generated.
    #[inline]
    pub fn no_checksum(&mut self) {
        self.header_mut().checksum = u16be::default();
    }

    /// Returns the 5-tuple that uniquely identifies a UDP connection.
    #[inline]
    pub fn flow(&self) -> Flow {
        Flow::new(
            self.envelope().src(),
            self.envelope().dst(),
            self.src_port(),
            self.dst_port(),
            ProtocolNumbers::Udp,
        )
    }

    /// Sets the layer-3 source address and recomputes the checksum.
    ///
    /// It recomputes the checksum using the incremental method. This is more
    /// efficient if the only change made is the address. Otherwise should use
    /// `cascade` to recompute the checksum over all the fields.
    #[inline]
    pub fn set_src_ip(&mut self, src_ip: IpAddr) -> Fallible<()> {
        let old_ip = self.envelope().src();
        let checksum = checksum::compute_with_ipaddr(self.checksum(), &old_ip, &src_ip)?;
        self.envelope_mut().set_src(src_ip)?;
        self.set_checksum(checksum);
        Ok(())
    }

    /// Sets the layer-3 destination address and recomputes the checksum.
    ///
    /// It recomputes the checksum using the incremental method. This is more
    /// efficient if the only change made is the address. Otherwise should use
    /// `cascade` to recompute the checksum over all the fields.
    #[inline]
    pub fn set_dst_ip(&mut self, dst_ip: IpAddr) -> Fallible<()> {
        let old_ip = self.envelope().dst();
        let checksum = checksum::compute_with_ipaddr(self.checksum(), &old_ip, &dst_ip)?;
        self.envelope_mut().set_dst(dst_ip)?;
        self.set_checksum(checksum);
        Ok(())
    }

    #[inline]
    fn compute_checksum(&mut self) {
        self.no_checksum();

        if let Ok(data) = self.mbuf().read_data_slice(self.offset, self.len()) {
            let data = unsafe { data.as_ref() };
            let pseudo_header_sum = self
                .envelope()
                .pseudo_header(data.len() as u16, ProtocolNumbers::Udp)
                .sum();
            let checksum = checksum::compute(pseudo_header_sum, data);
            self.set_checksum(checksum);
        } else {
            // we are reading till the end of buffer, should never run out
            unreachable!()
        }
    }
}

impl<E: IpPacket> fmt::Debug for Udp<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("udp")
            .field("src_port", &self.src_port())
            .field("dst_port", &self.dst_port())
            .field("length", &self.length())
            .field("checksum", &format!("0x{:04x}", self.checksum()))
            .field("$offset", &self.offset())
            .field("$len", &self.len())
            .field("$header_len", &self.header_len())
            .finish()
    }
}

impl<E: IpPacket> Packet for Udp<E> {
    /// The preceding packet type for an UDP packet can be either an [IPv4]
    /// packet, an [IPv6] packet, or any IPv6 extension packets.
    ///
    /// [IPv4]: crate::packets::ip::v4::Ipv4
    /// [IPv6]: crate::packets::ip::v6::Ipv6
    type Envelope = E;

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
        UdpHeader::size_of()
    }

    #[inline]
    unsafe fn clone(&self, internal: Internal) -> Self {
        Udp::<E> {
            envelope: self.envelope.clone(internal),
            header: self.header,
            offset: self.offset,
        }
    }

    /// Parses the envelope's payload as an UDP packet.
    ///
    /// If the envelope is IPv4, then [`Ipv4::protocol`] must be set to
    /// [`ProtocolNumbers::Udp`]. If the envelope is IPv6 or an extension
    /// header, then [`next_header`] must be set to `ProtocolNumbers::Udp`.
    /// Otherwise, a parsing error is returned.
    ///
    /// [`Ipv4::protocol`]: crate::packets::ip::v4::Ipv4::protocol
    /// [`ProtocolNumbers::Udp`]: crate::packets::ip::ProtocolNumbers::Udp
    /// [`next_header`]: crate::packets::ip::v6::Ipv6Packet::next_header
    #[inline]
    fn try_parse(envelope: Self::Envelope, _internal: Internal) -> Fallible<Self> {
        ensure!(
            envelope.next_protocol() == ProtocolNumbers::Udp,
            ParseError::new("not a UDP packet.")
        );

        let mbuf = envelope.mbuf();
        let offset = envelope.payload_offset();
        let header = mbuf.read_data(offset)?;

        Ok(Udp {
            envelope,
            header,
            offset,
        })
    }

    /// Prepends an UDP packet to the beginning of the envelope's payload.
    ///
    /// If the envelope is IPv4, then [`Ipv4::protocol`] is set to
    /// [`ProtocolNumbers::Udp`]. If the envelope is IPv6 or an extension
    /// header, then [`next_header`] is set to `ProtocolNumbers::Udp`.
    ///
    /// [`Ipv4::protocol`]: crate::packets::ip::v4::Ipv4::protocol
    /// [`ProtocolNumbers::Udp`]: crate::packets::ip::ProtocolNumbers::Udp
    /// [`next_header`]: crate::packets::ip::v6::Ipv6Packet::next_header
    #[inline]
    fn try_push(mut envelope: Self::Envelope, _internal: Internal) -> Fallible<Self> {
        let offset = envelope.payload_offset();
        let mbuf = envelope.mbuf_mut();

        mbuf.extend(offset, UdpHeader::size_of())?;
        let header = mbuf.write_data(offset, &UdpHeader::default())?;

        envelope.set_next_protocol(ProtocolNumbers::Udp);

        Ok(Udp {
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
    /// * [`length`] is set to the total length of the header and the payload.
    /// * [`checksum`] is computed based on the [`pseudo-header`] and the
    /// full packet.
    ///
    /// [`length`]: Udp::length
    /// [`checksum`]: Udp::checksum
    /// [`pseudo-header`]: crate::packets::checksum::PseudoHeader
    #[inline]
    fn reconcile(&mut self) {
        let len = self.len() as u16;
        self.set_length(len);
        self.compute_checksum();
    }
}

/// UDP header.
#[derive(Clone, Copy, Debug, Default, SizeOf)]
#[repr(C)]
struct UdpHeader {
    src_port: u16be,
    dst_port: u16be,
    length: u16be,
    checksum: u16be,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packets::ip::v4::Ipv4;
    use crate::packets::Ethernet;
    use crate::testils::byte_arrays::{IPV4_TCP_PACKET, IPV4_UDP_PACKET};
    use crate::Mbuf;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn size_of_udp_header() {
        assert_eq!(8, UdpHeader::size_of());
    }

    #[capsule::test]
    fn parse_udp_packet() {
        let packet = Mbuf::from_bytes(&IPV4_UDP_PACKET).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();
        let ipv4 = ethernet.parse::<Ipv4>().unwrap();
        let udp = ipv4.parse::<Udp<Ipv4>>().unwrap();

        assert_eq!(39376, udp.src_port());
        assert_eq!(1087, udp.dst_port());
        assert_eq!(18, udp.length());
        assert_eq!(0x7228, udp.checksum());
    }

    #[capsule::test]
    fn parse_non_udp_packet() {
        let packet = Mbuf::from_bytes(&IPV4_TCP_PACKET).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();
        let ipv4 = ethernet.parse::<Ipv4>().unwrap();

        assert!(ipv4.parse::<Udp<Ipv4>>().is_err());
    }

    #[capsule::test]
    fn udp_flow_v4() {
        let packet = Mbuf::from_bytes(&IPV4_UDP_PACKET).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();
        let ipv4 = ethernet.parse::<Ipv4>().unwrap();
        let udp = ipv4.parse::<Udp<Ipv4>>().unwrap();
        let flow = udp.flow();

        assert_eq!("139.133.217.110", flow.src_ip().to_string());
        assert_eq!("139.133.233.2", flow.dst_ip().to_string());
        assert_eq!(39376, flow.src_port());
        assert_eq!(1087, flow.dst_port());
        assert_eq!(ProtocolNumbers::Udp, flow.protocol());
    }

    #[capsule::test]
    fn set_src_dst_ip() {
        let packet = Mbuf::from_bytes(&IPV4_UDP_PACKET).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();
        let ipv4 = ethernet.parse::<Ipv4>().unwrap();
        let mut udp = ipv4.parse::<Udp<Ipv4>>().unwrap();

        let old_checksum = udp.checksum();
        let new_ip = Ipv4Addr::new(10, 0, 0, 0);
        assert!(udp.set_src_ip(new_ip.into()).is_ok());
        assert!(udp.checksum() != old_checksum);
        assert_eq!(new_ip.to_string(), udp.envelope().src().to_string());

        let old_checksum = udp.checksum();
        let new_ip = Ipv4Addr::new(20, 0, 0, 0);
        assert!(udp.set_dst_ip(new_ip.into()).is_ok());
        assert!(udp.checksum() != old_checksum);
        assert_eq!(new_ip.to_string(), udp.envelope().dst().to_string());

        // can't set v6 addr on a v4 packet
        assert!(udp.set_src_ip(Ipv6Addr::UNSPECIFIED.into()).is_err());
    }

    #[capsule::test]
    fn compute_checksum() {
        let packet = Mbuf::from_bytes(&IPV4_UDP_PACKET).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();
        let ipv4 = ethernet.parse::<Ipv4>().unwrap();
        let mut udp = ipv4.parse::<Udp<Ipv4>>().unwrap();

        let expected = udp.checksum();
        // no payload change but force a checksum recompute anyway
        udp.reconcile_all();
        assert_eq!(expected, udp.checksum());
    }

    #[capsule::test]
    fn push_udp_packet() {
        let packet = Mbuf::new().unwrap();
        let ethernet = packet.push::<Ethernet>().unwrap();
        let ipv4 = ethernet.push::<Ipv4>().unwrap();
        let udp = ipv4.push::<Udp<Ipv4>>().unwrap();

        assert_eq!(UdpHeader::size_of(), udp.len());

        // make sure the next protocol is fixed
        assert_eq!(ProtocolNumbers::Udp, udp.envelope().next_protocol());
    }
}

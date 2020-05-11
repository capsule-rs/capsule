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

use crate::packets::checksum::PseudoHeader;
use crate::packets::ip::v6::Ipv6Packet;
use crate::packets::ip::{IpPacket, ProtocolNumber, ProtocolNumbers};
use crate::packets::types::u16be;
use crate::packets::{Internal, Packet, ParseError};
use crate::{ensure, SizeOf};
use failure::{Fail, Fallible};
use std::fmt;
use std::net::{IpAddr, Ipv6Addr};
use std::ptr::NonNull;

/// IPv6 Segment Routing based on [IETF DRAFT].
///
/// Routing Headers are defined in [IETF RFC 8200]. The Segment Routing
/// Header has a new Routing Type (suggested value 4) to be assigned by
/// IANA.
///
/// ```
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | Next Header   |  Hdr Ext Len  | Routing Type  | Segments Left |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |  Last Entry   |     Flags     |              Tag              |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |            Segment List[0] (128 bits IPv6 address)            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
///                              ...
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |            Segment List[n] (128 bits IPv6 address)            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |         Optional Type Length Value objects (variable)         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// - *Next Header*:       8-bit selector. Identifies the type of header
///                        immediately following the SRH.
///
/// - *Hdr Ext Len*:       8-bit unsigned integer, is the length of the SRH
///                        header in 8-octet units, not including the first 8
///                        octets.
///
/// - *Routing Type*:      TBD, to be assigned by IANA (suggested value: 4).
///
/// - *Segments Left*:     8-bit unsigned integer Number of route segments
///                        remaining, i.e., number of explicitly listed
///                        intermediate nodes still to be visited before
///                        reaching the final destination.
///
/// - *Last Entry*:        Contains the index (zero based), in the Segment List,
///                        of the last element of the Segment List.
///
/// - *Flags*:             8 bits of flags. Following flags are defined:
///
///        0 1 2 3 4 5 6 7
///       +-+-+-+-+-+-+-+-+
///       |U U U U U U U U|
///       +-+-+-+-+-+-+-+-+
///
///   - *U*:               Unused and for future use. MUST be 0 on transmission
///                        and ignored on receipt.
///
/// - *Tag*:               Tag a packet as part of a class or group of packets,
///                        e.g., packets sharing the same set of properties.
///
/// - *Segment List\[n]*:  128 bit IPv6 addresses representing the nth
///                        segment in the Segment List.  The Segment List is
///                        encoded starting from the last segment of the SR
///                        Policy, i.e., the first element of the segment list
///                        (Segment List \[0]) contains the last segment of the
///                        SR Policy, the second element contains the
///                        penultimate segment of the SR Policy and so on.
///
/// - *Type Length Value*: A TLV provides meta-data for segment processing.  The
///                        TLVs defined in this spec are the HMAC and PAD TLVs.
///
/// # Remarks
///
/// TLVs are not supported yet.
///
/// [IETF Draft]: https://tools.ietf.org/html/draft-ietf-6man-segment-routing-header-26#section-2
/// [IETF RFC 8200]: https://tools.ietf.org/html/rfc8200#section-4.4
pub struct SegmentRouting<E: Ipv6Packet> {
    envelope: E,
    header: NonNull<SegmentRoutingHeader>,
    segments: NonNull<[Ipv6Addr]>,
    offset: usize,
}

impl<E: Ipv6Packet> SegmentRouting<E> {
    #[inline]
    fn header(&self) -> &SegmentRoutingHeader {
        unsafe { self.header.as_ref() }
    }

    #[inline]
    fn header_mut(&mut self) -> &mut SegmentRoutingHeader {
        unsafe { self.header.as_mut() }
    }

    /// Returns the length of the segment routing header in 8-octet units,
    /// not including the first 8 octets.
    #[inline]
    pub fn hdr_ext_len(&self) -> u8 {
        self.header().hdr_ext_len
    }

    /// Sets the length of the segment routing header.
    #[inline]
    fn set_hdr_ext_len(&mut self, hdr_ext_len: u8) {
        self.header_mut().hdr_ext_len = hdr_ext_len;
    }

    /// Returns the routing type. Suggested value is `4` to be assigned by
    /// IANA.
    #[inline]
    pub fn routing_type(&self) -> u8 {
        self.header().routing_type
    }

    /// Sets the routing type. Should not be used unless to explicitly
    /// override the IANA assigned value.
    #[doc(hidden)]
    #[inline]
    pub fn set_routing_type(&mut self, routing_type: u8) {
        self.header_mut().routing_type = routing_type;
    }

    /// Returns the number of route segments remaining.
    #[inline]
    pub fn segments_left(&self) -> u8 {
        self.header().segments_left
    }

    /// Sets the number of route segments remaining.
    ///
    /// # Remarks
    ///
    /// Should also call `Ipv6::set_dst` to keep the packet's destination
    /// in sync with the segment routing header.
    #[inline]
    pub fn set_segments_left(&mut self, segments_left: u8) {
        self.header_mut().segments_left = segments_left;
    }

    /// Returns the index of the last element of the segment list, 0 based.
    #[inline]
    pub fn last_entry(&self) -> u8 {
        self.header().last_entry
    }

    /// Sets the index of the last element of the segment list.
    #[inline]
    fn set_last_entry(&mut self, last_entry: u8) {
        self.header_mut().last_entry = last_entry;
    }

    /// Returns the tag that marks a packet as part of a class or group of
    /// packets.
    #[inline]
    pub fn tag(&self) -> u16 {
        self.header().tag.into()
    }

    /// Tags a packet as part of a class or group of packets.
    #[inline]
    pub fn set_tag(&mut self, tag: u16) {
        self.header_mut().tag = tag.into();
    }

    /// Returns the segment list.
    #[inline]
    pub fn segments(&self) -> &[Ipv6Addr] {
        unsafe { self.segments.as_ref() }
    }

    /// Sets the segment list.
    ///
    /// # Remarks
    ///
    /// Be aware that when invoking this function, it can affect Tcp and Udp
    /// checksum calculations, as the last segment is used as part of the
    /// pseudo header.
    #[inline]
    pub fn set_segments(&mut self, segments: &[Ipv6Addr]) -> Fallible<()> {
        if !segments.is_empty() {
            let old_len = self.last_entry() + 1;
            let new_len = segments.len() as u8;

            let segments_offset = self.offset + SegmentRoutingHeader::size_of();

            let mbuf = self.mbuf_mut();

            // if it's a true 1:1 segments replace, don't resize first
            if old_len != new_len {
                mbuf.resize(
                    segments_offset,
                    (new_len as isize - old_len as isize) * Ipv6Addr::size_of() as isize,
                )?;
            }
            self.segments = mbuf.write_data_slice(segments_offset, segments)?;
            self.set_hdr_ext_len(new_len * 2);
            self.set_last_entry(new_len - 1);
            Ok(())
        } else {
            Err(BadSegmentsError.into())
        }
    }
}

impl<E: Ipv6Packet> fmt::Debug for SegmentRouting<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("segment routing")
            .field("next_header", &format!("{}", self.next_header()))
            .field("hdr_ext_len", &self.hdr_ext_len())
            .field("routing_type", &self.routing_type())
            .field("segments_left", &self.segments_left())
            .field("last_entry", &self.last_entry())
            .field("tag", &self.tag())
            .field("segments", &self.segments())
            .field("$offset", &self.offset())
            .field("$len", &self.len())
            .field("$header_len", &self.header_len())
            .finish()
    }
}

impl<E: Ipv6Packet> Packet for SegmentRouting<E> {
    /// The preceding type for an IPv6 segment routing packet can be either
    /// an IPv6 packet or any possible IPv6 extension packets.
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
        SegmentRoutingHeader::size_of() + self.segments().len() * Ipv6Addr::size_of()
    }

    #[inline]
    unsafe fn clone(&self, internal: Internal) -> Self {
        SegmentRouting::<E> {
            envelope: self.envelope.clone(internal),
            header: self.header,
            segments: self.segments,
            offset: self.offset,
        }
    }

    /// Parses the envelope's payload as an IPv6 segment routing packet.
    ///
    /// [`next_header`] of the envelope must be set to [`ProtocolNumbers::Ipv6Route`].
    /// Otherwise a parsing error is returned.
    ///
    /// [`next_header`]: Ipv6Packet::next_header
    /// [`ProtocolNumbers::Ipv6Route`]: ProtocolNumbers::Ipv6Route
    #[inline]
    fn try_parse(envelope: Self::Envelope, _internal: Internal) -> Fallible<Self> {
        ensure!(
            envelope.next_header() == ProtocolNumbers::Ipv6Route,
            ParseError::new("not an IPv6 routing packet.")
        );

        let mbuf = envelope.mbuf();
        let offset = envelope.payload_offset();
        let header = mbuf.read_data::<SegmentRoutingHeader>(offset)?;

        let hdr_ext_len = unsafe { header.as_ref().hdr_ext_len };
        let segments_len = unsafe { header.as_ref().last_entry + 1 };

        if hdr_ext_len != 0 && (2 * segments_len == hdr_ext_len) {
            let segments = mbuf.read_data_slice::<Ipv6Addr>(
                offset + SegmentRoutingHeader::size_of(),
                segments_len as usize,
            )?;

            Ok(SegmentRouting {
                envelope,
                header,
                segments,
                offset,
            })
        } else {
            Err(ParseError::new("Packet has inconsistent segment list length.").into())
        }
    }

    /// Prepends an IPv6 segment routing packet with a segment list of one
    /// to the beginning of the envelope's payload.
    ///
    /// [`next_header`] is set to the value of the `next_header` field of the
    /// envelope, and the envelope is set to [`ProtocolNumbers::Ipv6Route`].
    ///
    /// [`next_header`]: Ipv6Packet::next_header
    /// [`ProtocolNumbers::Ipv6Route`]: ProtocolNumbers::Ipv6Route
    #[inline]
    fn try_push(mut envelope: Self::Envelope, _internal: Internal) -> Fallible<Self> {
        let offset = envelope.payload_offset();
        let mbuf = envelope.mbuf_mut();

        // adds a default segment list of one element.
        mbuf.extend(
            offset,
            SegmentRoutingHeader::size_of() + Ipv6Addr::size_of(),
        )?;
        let header = mbuf.write_data(offset, &SegmentRoutingHeader::default())?;
        let segments = mbuf.write_data_slice(
            offset + SegmentRoutingHeader::size_of(),
            &[Ipv6Addr::UNSPECIFIED],
        )?;

        let mut packet = SegmentRouting {
            envelope,
            header,
            segments,
            offset,
        };

        packet.set_next_header(packet.envelope().next_header());
        packet
            .envelope_mut()
            .set_next_header(ProtocolNumbers::Ipv6Route);

        Ok(packet)
    }

    /// Removes IPv6 segment routing packet from the message buffer.
    ///
    /// The envelope's [`next_header`] field is set to the value of the
    /// `next_header` field on the segment routing packet.
    ///
    /// [`next_header`]: Ipv6Packet::next_header
    #[inline]
    fn remove(mut self) -> Fallible<Self::Envelope> {
        let offset = self.offset();
        let len = self.header_len();
        let next_header = self.next_header();
        self.mbuf_mut().shrink(offset, len)?;
        self.envelope_mut().set_next_header(next_header);
        Ok(self.envelope)
    }

    #[inline]
    fn deparse(self) -> Self::Envelope {
        self.envelope
    }
}

impl<E: Ipv6Packet> IpPacket for SegmentRouting<E> {
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
        self.envelope().src()
    }

    #[inline]
    fn set_src(&mut self, src: IpAddr) -> Fallible<()> {
        self.envelope_mut().set_src(src)
    }

    #[inline]
    fn dst(&self) -> IpAddr {
        IpAddr::V6(self.segments()[0])
    }

    #[inline]
    fn set_dst(&mut self, dst: IpAddr) -> Fallible<()> {
        if let IpAddr::V6(v6_dst) = dst {
            let mut segments = vec![v6_dst];
            for segment in self.segments().iter().skip(1) {
                segments.push(*segment)
            }

            self.set_segments(&segments)?;

            if self.segments_left() == 0 {
                self.envelope_mut().set_dst(dst)
            } else {
                Ok(())
            }
        } else {
            unreachable!()
        }
    }

    /// Returns the pseudo header.
    ///
    /// Based on [IETF RFC 8200], if the IPv6 packet contains a Routing
    /// header, the Destination Address used in the pseudo-header is that
    /// of the final destination. At the originating node, that address will
    /// be in the last element of the Routing header; at the recipient(s),
    /// that address will be in the Destination Address field of the IPv6
    /// header.
    ///
    /// [IETF RFC 8200]: https://tools.ietf.org/html/rfc8200#section-8.1
    #[inline]
    fn pseudo_header(&self, packet_len: u16, protocol: ProtocolNumber) -> PseudoHeader {
        let dst = match self.dst() {
            IpAddr::V6(dst) => dst,
            _ => unreachable!(),
        };

        let src = match self.src() {
            IpAddr::V6(src) => src,
            _ => unreachable!(),
        };

        PseudoHeader::V6 {
            src,
            dst,
            packet_len,
            protocol,
        }
    }

    #[inline]
    fn truncate(&mut self, mtu: usize) -> Fallible<()> {
        self.envelope_mut().truncate(mtu)
    }
}

impl<E: Ipv6Packet> Ipv6Packet for SegmentRouting<E> {
    #[inline]
    fn next_header(&self) -> ProtocolNumber {
        ProtocolNumber::new(self.header().next_header)
    }

    #[inline]
    fn set_next_header(&mut self, next_header: ProtocolNumber) {
        self.header_mut().next_header = next_header.0;
    }
}

/// Error when the segment list length is 0.
#[derive(Debug, Fail)]
#[fail(display = "Segment list length must be greater than 0")]
pub struct BadSegmentsError;

/// IPv6 segment routing header.
///
/// The segment routing header contains only the fixed portion of the
/// header. `segment_list` and `tlv` are parsed separately.
#[derive(Clone, Copy, Debug, SizeOf)]
#[repr(C, packed)]
struct SegmentRoutingHeader {
    next_header: u8,
    hdr_ext_len: u8,
    routing_type: u8,
    segments_left: u8,
    last_entry: u8,
    flags: u8,
    tag: u16be,
}

impl Default for SegmentRoutingHeader {
    fn default() -> SegmentRoutingHeader {
        SegmentRoutingHeader {
            next_header: 0,
            hdr_ext_len: 2,
            routing_type: 4,
            segments_left: 0,
            last_entry: 0,
            flags: 0,
            tag: u16be::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packets::ip::v6::Ipv6;
    use crate::packets::ip::ProtocolNumbers;
    use crate::packets::{Ethernet, Tcp};
    use crate::testils::byte_arrays::{IPV6_TCP_PACKET, SR_TCP_PACKET};
    use crate::Mbuf;

    #[test]
    fn size_of_segment_routing_header() {
        assert_eq!(8, SegmentRoutingHeader::size_of());
    }

    #[capsule::test]
    fn parse_segment_routing_packet() {
        let packet = Mbuf::from_bytes(&SR_TCP_PACKET).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();
        let ipv6 = ethernet.parse::<Ipv6>().unwrap();
        let srh = ipv6.parse::<SegmentRouting<Ipv6>>().unwrap();

        assert_eq!(ProtocolNumbers::Tcp, srh.next_header());
        assert_eq!(6, srh.hdr_ext_len());
        assert_eq!(4, srh.routing_type());
        assert_eq!(0, srh.segments_left());
        assert_eq!(2, srh.last_entry());
        assert_eq!(0, srh.tag());

        let segments = srh.segments();
        assert_eq!(3, segments.len());
        assert_eq!("2001:db8:85a3::8a2e:370:7333", segments[0].to_string());
        assert_eq!("2001:db8:85a3::8a2e:370:7334", segments[1].to_string());
        assert_eq!("2001:db8:85a3::8a2e:370:7335", segments[2].to_string());
    }

    #[capsule::test]
    fn parse_non_segment_routing_packet() {
        let packet = Mbuf::from_bytes(&IPV6_TCP_PACKET).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();
        let ipv6 = ethernet.parse::<Ipv6>().unwrap();

        assert!(ipv6.parse::<SegmentRouting<Ipv6>>().is_err());
    }

    #[capsule::test]
    fn set_segments() {
        let packet = Mbuf::from_bytes(&SR_TCP_PACKET).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();
        let ipv6 = ethernet.parse::<Ipv6>().unwrap();
        let mut srh = ipv6.parse::<SegmentRouting<Ipv6>>().unwrap();

        let segment1: Ipv6Addr = "::1".parse().unwrap();

        assert!(srh.set_segments(&[segment1]).is_ok());
        assert_eq!(2, srh.hdr_ext_len());
        assert_eq!(0, srh.last_entry());
        assert_eq!(1, srh.segments().len());
        assert_eq!(segment1, srh.segments()[0]);

        let segment2: Ipv6Addr = "::2".parse().unwrap();
        let segment3: Ipv6Addr = "::3".parse().unwrap();
        let segment4: Ipv6Addr = "::4".parse().unwrap();

        assert!(srh
            .set_segments(&[segment1, segment2, segment3, segment4])
            .is_ok());
        assert_eq!(8, srh.hdr_ext_len());
        assert_eq!(3, srh.last_entry());
        assert_eq!(4, srh.segments().len());
        assert_eq!(segment1, srh.segments()[0]);
        assert_eq!(segment2, srh.segments()[1]);
        assert_eq!(segment3, srh.segments()[2]);
        assert_eq!(segment4, srh.segments()[3]);
        assert!(srh.set_segments(&[]).is_err());

        // make sure rest of the packet still valid
        let tcp = srh.parse::<Tcp<SegmentRouting<Ipv6>>>().unwrap();
        assert_eq!(3464, tcp.src_port())
    }

    #[capsule::test]
    fn compute_checksum() {
        let packet = Mbuf::from_bytes(&SR_TCP_PACKET).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();
        let ipv6 = ethernet.parse::<Ipv6>().unwrap();
        let mut srh = ipv6.parse::<SegmentRouting<Ipv6>>().unwrap();

        let segment1: Ipv6Addr = "::1".parse().unwrap();
        let segment2: Ipv6Addr = "::2".parse().unwrap();
        let segment3: Ipv6Addr = "::3".parse().unwrap();
        let segment4: Ipv6Addr = "::4".parse().unwrap();

        assert!(srh
            .set_segments(&[segment1, segment2, segment3, segment4])
            .is_ok());
        assert_eq!(4, srh.segments().len());
        srh.set_segments_left(3);

        let mut tcp = srh.parse::<Tcp<SegmentRouting<Ipv6>>>().unwrap();

        // Should pass as we're using the hard-coded (and wrong) initial
        // checksum, as it's 0 given above.
        assert_eq!(0, tcp.checksum());

        tcp.reconcile_all();
        let expected = tcp.checksum();

        // our checksum should now be calculated correctly & no longer be 0
        assert_ne!(expected, 0);

        // Let's update the segments list to make sure the last checksum
        // computed matches what happens when it's the last (and only)
        // segment in the list.
        let mut srh_ret = tcp.deparse();
        assert!(srh_ret.set_segments(&[segment1]).is_ok());
        assert_eq!(1, srh_ret.segments().len());
        srh_ret.set_segments_left(0);

        let mut tcp_ret = srh_ret.parse::<Tcp<SegmentRouting<Ipv6>>>().unwrap();
        tcp_ret.reconcile_all();
        assert_eq!(expected, tcp_ret.checksum());

        // Let's make sure that if segments left is 0, then our checksum
        // is still the same segment.
        let mut srh_fin = tcp_ret.deparse();
        srh_fin.set_segments_left(0);
        let mut tcp_fin = srh_fin.parse::<Tcp<SegmentRouting<Ipv6>>>().unwrap();
        tcp_fin.reconcile_all();
        assert_eq!(expected, tcp_fin.checksum());
    }

    #[capsule::test]
    fn insert_segment_routing_packet() {
        let packet = Mbuf::from_bytes(&IPV6_TCP_PACKET).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();
        let ipv6 = ethernet.parse::<Ipv6>().unwrap();
        let ipv6_payload_len = ipv6.payload_len();
        let srh = ipv6.push::<SegmentRouting<Ipv6>>().unwrap();

        assert_eq!(2, srh.hdr_ext_len());
        assert_eq!(1, srh.segments().len());
        assert_eq!(4, srh.routing_type());

        // make sure next header is fixed
        assert_eq!(ProtocolNumbers::Tcp, srh.next_header());
        assert_eq!(ProtocolNumbers::Ipv6Route, srh.envelope().next_header());

        // ipv6 payload is srh payload after push
        assert_eq!(ipv6_payload_len, srh.payload_len());
        // make sure rest of the packet still valid
        let tcp = srh.parse::<Tcp<SegmentRouting<Ipv6>>>().unwrap();
        assert_eq!(36869, tcp.src_port());

        let mut srh = tcp.deparse();
        let srh_packet_len = srh.len();
        srh.reconcile_all();
        let ipv6 = srh.deparse();
        assert_ne!(srh_packet_len, ipv6_payload_len as usize);
        assert_eq!(srh_packet_len, ipv6.payload_length() as usize)
    }

    #[capsule::test]
    fn remove_segment_routing_packet() {
        let packet = Mbuf::from_bytes(&SR_TCP_PACKET).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();
        let ipv6 = ethernet.parse::<Ipv6>().unwrap();
        let srh = ipv6.parse::<SegmentRouting<Ipv6>>().unwrap();
        let ipv6 = srh.remove().unwrap();

        // make sure next header is fixed
        assert_eq!(ProtocolNumbers::Tcp, ipv6.next_header());

        // make sure rest of the packet still valid
        let tcp = ipv6.parse::<Tcp<Ipv6>>().unwrap();
        assert_eq!(3464, tcp.src_port());
    }
}

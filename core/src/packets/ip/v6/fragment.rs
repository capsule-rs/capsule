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
use crate::packets::{CondRc, Header, Packet};
use crate::{Result, SizeOf};
use std::fmt;
use std::net::IpAddr;
use std::ptr::NonNull;

/// Masks
const FRAG_OS: u16 = !0b111;
const FLAG_MORE: u16 = 0b1;

/// IPv6 Fragment Extension packet based on [`IETF RFC 8200`].
///
/// ```
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |  Next Header  |   Reserved    |      Fragment Offset    |Res|M|
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                         Identification                        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// - *Next Header*:      8-bit selector.  Identifies the initial header
///                       type of the Fragmentable Part of the original
///                       packet. Uses the same values as the IPv4 Protocol
///                       field [IANA-PN].
///
/// - *Reserved*:         8-bit reserved field.  Initialized to zero for
///                       transmission; ignored on reception.
///
/// - *Fragment Offset*:  13-bit unsigned integer.  The offset, in
///                       8-octet units, of the data following this
///                       header, relative to the start of the
///                       Fragmentable Part of the original packet.
///
/// - *Res*:              2-bit reserved field.  Initialized to zero for
///                       transmission; ignored on reception.
///
/// - *M flag*:           1 = more fragments; 0 = last fragment.
///
/// - *Identification*:   32 bits.
///
/// # Remarks
///
/// Because the payload following the fragment header is incomplete data,
/// `push` and `remove` should be used with care. The result is likely not
/// a valid packet without additional fixes.
///
/// [`IETF RFC 8200`]: https://tools.ietf.org/html/rfc8200#section-4.5
#[derive(Clone)]
pub struct Fragment<E: Ipv6Packet> {
    envelope: CondRc<E>,
    header: NonNull<FragmentHeader>,
    offset: usize,
}

impl<E: Ipv6Packet> Fragment<E> {
    /// Returns the offset of the data following this header relative to the
    /// start of the fragmentable part of the original packet. It is measured
    /// in units of 8 octets or 64 bits.
    pub fn fragment_offset(&self) -> u16 {
        (u16::from_be(self.header().frag_res_m) & FRAG_OS) >> 3
    }

    /// Sets the fragment offset.
    pub fn set_fragment_offset(&mut self, offset: u16) {
        self.header_mut().frag_res_m =
            u16::to_be((u16::from_be(self.header().frag_res_m) & !FRAG_OS) | (offset << 3));
    }

    /// Returns a flag indicating whether there are more fragments.
    pub fn more_fragments(&self) -> bool {
        u16::from_be(self.header().frag_res_m) & FLAG_MORE > 0
    }

    /// Sets the more fragment flag indicating there are more fragments.
    pub fn set_more_fragments(&mut self) {
        self.header_mut().frag_res_m =
            u16::to_be((u16::from_be(self.header().frag_res_m)) | FLAG_MORE);
    }

    /// Unsets the more fragment flag indicating this is the last fragment.
    pub fn unset_more_fragments(&mut self) {
        self.header_mut().frag_res_m =
            u16::to_be((u16::from_be(self.header().frag_res_m)) & !FLAG_MORE);
    }

    /// Returns the identifying value assigned by the sender to aid in
    /// assembling the fragments of a packet.
    pub fn identification(&self) -> u32 {
        u32::from_be(self.header().identification)
    }

    /// Sets the identifying value.
    pub fn set_identification(&mut self, identification: u32) {
        self.header_mut().identification = u32::to_be(identification);
    }
}

impl<E: Ipv6Packet> fmt::Debug for Fragment<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("fragment")
            .field("next_header", &format!("{}", self.next_header()))
            .field("fragment_offset", &self.fragment_offset())
            .field("more_fragments", &self.more_fragments())
            .field("identification", &format!("{:x}", self.identification()))
            .finish()
    }
}

impl<E: Ipv6Packet> Packet for Fragment<E> {
    type Header = FragmentHeader;
    type Envelope = E;

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

    #[inline]
    fn header_len(&self) -> usize {
        Self::Header::size_of()
    }

    #[doc(hidden)]
    #[inline]
    fn do_parse(envelope: Self::Envelope) -> Result<Self> {
        let mbuf = envelope.mbuf();
        let offset = envelope.payload_offset();
        let header = mbuf.read_data(offset)?;

        Ok(Fragment {
            envelope: CondRc::new(envelope),
            header,
            offset,
        })
    }

    #[doc(hidden)]
    #[inline]
    fn do_push(mut envelope: Self::Envelope) -> Result<Self> {
        let offset = envelope.payload_offset();
        let mbuf = envelope.mbuf_mut();

        mbuf.extend(offset, Self::Header::size_of())?;
        let header = mbuf.write_data(offset, &Self::Header::default())?;

        let mut packet = Fragment {
            envelope: CondRc::new(envelope),
            header,
            offset,
        };

        packet.set_next_header(packet.envelope().next_header());
        packet
            .envelope_mut()
            .set_next_header(ProtocolNumbers::Ipv6Frag);

        Ok(packet)
    }

    #[inline]
    fn remove(mut self) -> Result<Self::Envelope> {
        let offset = self.offset();
        let len = self.header_len();
        let next_header = self.next_header();
        self.mbuf_mut().shrink(offset, len)?;
        self.envelope_mut().set_next_header(next_header);
        Ok(self.envelope.into_owned())
    }

    #[inline]
    fn deparse(self) -> Self::Envelope {
        self.envelope.into_owned()
    }
}

impl<E: Ipv6Packet> IpPacket for Fragment<E> {
    #[inline]
    fn next_proto(&self) -> ProtocolNumber {
        self.next_header()
    }

    #[inline]
    fn set_next_proto(&mut self, proto: ProtocolNumber) {
        self.set_next_header(proto);
    }

    #[inline]
    fn src(&self) -> IpAddr {
        self.envelope().src()
    }

    #[inline]
    fn set_src(&mut self, src: IpAddr) -> Result<()> {
        self.envelope_mut().set_src(src)
    }

    #[inline]
    fn dst(&self) -> IpAddr {
        self.envelope().dst()
    }

    #[inline]
    fn set_dst(&mut self, dst: IpAddr) -> Result<()> {
        self.envelope_mut().set_dst(dst)
    }

    #[inline]
    fn pseudo_header(&self, packet_len: u16, protocol: ProtocolNumber) -> PseudoHeader {
        self.envelope().pseudo_header(packet_len, protocol)
    }

    #[inline]
    fn truncate(&mut self, mtu: usize) -> Result<()> {
        self.envelope_mut().truncate(mtu)
    }
}

impl<E: Ipv6Packet> Ipv6Packet for Fragment<E> {
    #[inline]
    fn next_header(&self) -> ProtocolNumber {
        ProtocolNumber::new(self.header().next_header)
    }

    #[inline]
    fn set_next_header(&mut self, next_header: ProtocolNumber) {
        self.header_mut().next_header = next_header.0;
    }
}

/// IPv6 fragment extension header.
#[derive(Clone, Copy, Debug, Default, SizeOf)]
#[repr(C, packed)]
pub struct FragmentHeader {
    next_header: u8,
    reserved: u8,
    frag_res_m: u16,
    identification: u32,
}

impl Header for FragmentHeader {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packets::ip::v6::Ipv6;
    use crate::packets::Ethernet;
    use crate::testils::byte_arrays::{IPV6_FRAGMENT_PACKET, IPV6_TCP_PACKET};
    use crate::Mbuf;

    #[test]
    fn size_of_fragment_header() {
        assert_eq!(8, FragmentHeader::size_of());
    }

    #[capsule::test]
    fn parse_fragment_packet() {
        let packet = Mbuf::from_bytes(&IPV6_FRAGMENT_PACKET).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();
        let ipv6 = ethernet.parse::<Ipv6>().unwrap();
        let frag = ipv6.parse::<Fragment<Ipv6>>().unwrap();

        assert_eq!(ProtocolNumbers::Udp, frag.next_header());
        assert_eq!(543, frag.fragment_offset());
        assert!(!frag.more_fragments());
        assert_eq!(0xf88e_b466, frag.identification());
    }

    #[capsule::test]
    fn push_and_set_fragment_packet() {
        let packet = Mbuf::new().unwrap();
        let ethernet = packet.push::<Ethernet>().unwrap();
        let ipv6 = ethernet.push::<Ipv6>().unwrap();
        let mut frag = ipv6.push::<Fragment<Ipv6>>().unwrap();

        assert_eq!(FragmentHeader::size_of(), frag.len());
        assert_eq!(ProtocolNumbers::Ipv6Frag, frag.envelope().next_header());

        // offset and mf flag share one u16, so we check both.
        frag.set_fragment_offset(100);
        assert_eq!(100, frag.fragment_offset());
        assert!(!frag.more_fragments());

        // we check both again.
        frag.set_more_fragments();
        assert_eq!(100, frag.fragment_offset());
        assert!(frag.more_fragments());

        frag.set_identification(0xabcd_1234);
        assert_eq!(0xabcd_1234, frag.identification());
    }

    #[capsule::test]
    fn insert_fragment_packet() {
        let packet = Mbuf::from_bytes(&IPV6_TCP_PACKET).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();
        let ipv6 = ethernet.parse::<Ipv6>().unwrap();

        let next_header = ipv6.next_header();
        let payload_len = ipv6.payload_len();
        let frag = ipv6.push::<Fragment<Ipv6>>().unwrap();

        assert_eq!(ProtocolNumbers::Ipv6Frag, frag.envelope().next_header());
        assert_eq!(next_header, frag.next_header());
        assert_eq!(payload_len, frag.payload_len());
    }

    #[capsule::test]
    fn remove_fragment_packet() {
        let packet = Mbuf::from_bytes(&IPV6_FRAGMENT_PACKET).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();
        let ipv6 = ethernet.parse::<Ipv6>().unwrap();
        let frag = ipv6.parse::<Fragment<Ipv6>>().unwrap();

        let next_header = frag.next_header();
        let payload_len = frag.payload_len();
        let ipv6 = frag.remove().unwrap();

        assert_eq!(next_header, ipv6.next_header());
        assert_eq!(payload_len, ipv6.payload_len());
    }
}

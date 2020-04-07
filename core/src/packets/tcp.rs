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
use crate::packets::{checksum, Header, Internal, Packet, PacketBase, ParseError};
use crate::{ensure, SizeOf};
use failure::Fallible;
use std::fmt;
use std::net::IpAddr;
use std::ptr::NonNull;

// TCP control flag bitmasks.
const CWR: u8 = 0b1000_0000;
const ECE: u8 = 0b0100_0000;
const URG: u8 = 0b0010_0000;
const ACK: u8 = 0b0001_0000;
const PSH: u8 = 0b0000_1000;
const RST: u8 = 0b0000_0100;
const SYN: u8 = 0b0000_0010;
const FIN: u8 = 0b0000_0001;

/// Transmission Control Protocol packet based on [`IETF RFC 793`].
///
/// ```
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |          Source Port          |       Destination Port        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                        Sequence Number                        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                    Acknowledgment Number                      |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |  Data |     |N|C|E|U|A|P|R|S|F|                               |
/// | Offset| Res |S|W|C|R|C|S|S|Y|I|            Window             |
/// |       |     | |R|E|G|K|H|T|N|N|                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |           Checksum            |         Urgent Pointer        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                    Options                    |    Padding    |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                             data                              |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// - *Source Port*: (16 bits)
///      The source port number.
///
/// - *Destination Port*: (16 bits)
///      The destination port number.
///
/// - *Sequence Number*: (32 bits)
///      The sequence number of the first data octet in this segment (except
///      when SYN is present). If SYN is present the sequence number is the
///      initial sequence number (ISN) and the first data octet is ISN+1.
///
/// - *Acknowledgment Number*: (32 bits)
///      If the ACK control bit is set this field contains the value of the
///      next sequence number the sender of the segment is expecting to
///      receive.  Once a connection is established this is always sent.
///
/// - *Data Offset*: (4 bits)
///      The number of 32 bit words in the TCP Header.  This indicates where
///      the data begins.  The TCP header (even one including options) is an
///      integral number of 32 bits long.
///
/// - *Control Bits*: (9 bits) [from left to right]
///      - NS:   ECN-nonce nonce sum [`IETF RFC 3540`]
///      - CWR:  Congestion Window Reduced flag [`IETF RFC 3168`]
///      - ECE:  ECN-Echo flag [`IETF RFC 3168`]
///      - URG:  Urgent Pointer field significant
///      - ACK:  Acknowledgment field significant
///      - PSH:  Push Function
///      - RST:  Reset the connection
///      - SYN:  Synchronize sequence numbers
///      - FIN:  No more data from sender
///
/// - *Window*: (16 bits)
///      The number of data octets beginning with the one indicated in the
///      acknowledgment field which the sender of this segment is willing to
///      accept.
///
/// - *Checksum*: (16 bits)
///      The checksum field is the 16 bit one's complement of the one's
///      complement sum of all 16 bit words in the header and text.
///
/// - *Urgent Pointer*: (16 bits)
///      This field communicates the current value of the urgent pointer as a
///      positive offset from the sequence number in this segment.  The
///      urgent pointer points to the sequence number of the octet following
///      the urgent data.  This field is only be interpreted in segments with
///      the URG control bit set.
///
/// - *Options*: (variable)
///     Options may occupy space at the end of the TCP header and are a
///     multiple of 8 bits in length.  All options are included in the
///     checksum.
///
/// [`IETF RFC 793`]: https://tools.ietf.org/html/rfc793#section-3.1
/// [`IETF RFC 3540`]: https://tools.ietf.org/html/rfc3540
/// [`IETF RFC 3168`]: https://tools.ietf.org/html/rfc3168
pub struct Tcp<E: IpPacket> {
    envelope: E,
    header: NonNull<TcpHeader>,
    offset: usize,
}

impl<E: IpPacket> Tcp<E> {
    /// Returns the source port.
    #[inline]
    pub fn src_port(&self) -> u16 {
        u16::from_be(self.header().src_port)
    }

    /// Sets the source port.
    #[inline]
    pub fn set_src_port(&mut self, src_port: u16) {
        self.header_mut().src_port = u16::to_be(src_port);
    }

    /// Returns the destination port.
    #[inline]
    pub fn dst_port(&self) -> u16 {
        u16::from_be(self.header().dst_port)
    }

    /// Sets the destination port.
    #[inline]
    pub fn set_dst_port(&mut self, dst_port: u16) {
        self.header_mut().dst_port = u16::to_be(dst_port);
    }

    /// Returns the sequence number.
    #[inline]
    pub fn seq_no(&self) -> u32 {
        u32::from_be(self.header().seq_no)
    }

    /// Sets the sequence number.
    #[inline]
    pub fn set_seq_no(&mut self, seq_no: u32) {
        self.header_mut().seq_no = u32::to_be(seq_no);
    }

    /// Returns the acknowledgment number.
    #[inline]
    pub fn ack_no(&self) -> u32 {
        u32::from_be(self.header().ack_no)
    }

    /// Sets the acknowledgment number.
    #[inline]
    pub fn set_ack_no(&mut self, ack_no: u32) {
        self.header_mut().ack_no = u32::to_be(ack_no);
    }

    /// Returns the number of 32 bit words in the TCP Header. This indicates
    /// where the data begins.
    #[inline]
    pub fn data_offset(&self) -> u8 {
        (self.header().offset_to_ns & 0xf0) >> 4
    }

    // TODO: support tcp header options.
    #[allow(dead_code)]
    #[inline]
    fn set_data_offset(&mut self, data_offset: u8) {
        self.header_mut().offset_to_ns = (self.header().offset_to_ns & 0x0f) | (data_offset << 4);
    }

    /// Returns the nonce sum bit.
    #[inline]
    pub fn ns(&self) -> bool {
        (self.header().offset_to_ns & 0x01) != 0
    }

    /// Sets the nonce sum bit.
    #[inline]
    pub fn set_ns(&mut self) {
        self.header_mut().offset_to_ns |= 0x01;
    }

    /// Unsets the nonce sum bit.
    #[inline]
    pub fn unset_ns(&mut self) {
        self.header_mut().offset_to_ns &= !0x1;
    }

    /// Returns whether the congestion window has been reduced.
    #[inline]
    pub fn cwr(&self) -> bool {
        (self.header().flags & CWR) != 0
    }

    /// Sets the congestion window reduced flag.
    #[inline]
    pub fn set_cwr(&mut self) {
        self.header_mut().flags |= CWR;
    }

    /// Unsets the congestion window reduced flag.
    #[inline]
    pub fn unset_cwr(&mut self) {
        self.header_mut().flags &= !CWR;
    }

    /// Returns the ECN-echo flag.
    #[inline]
    pub fn ece(&self) -> bool {
        (self.header().flags & ECE) != 0
    }

    /// Sets the ECN-echo flag.
    #[inline]
    pub fn set_ece(&mut self) {
        self.header_mut().flags |= ECE;
    }

    /// Unsets the ECN-echo flag.
    #[inline]
    pub fn unset_ece(&mut self) {
        self.header_mut().flags &= !ECE;
    }

    /// Returns a flag indicating the packet contains urgent data and should
    /// be prioritized.
    #[inline]
    pub fn urg(&self) -> bool {
        (self.header().flags & URG) != 0
    }

    /// Sets the urgent flag.
    #[inline]
    pub fn set_urg(&mut self) {
        self.header_mut().flags |= URG;
    }

    /// Unsets the urgent flag.
    #[inline]
    pub fn unset_urg(&mut self) {
        self.header_mut().flags &= !URG;
    }

    /// Returns a flag acknowledging the successful receipt of a packet.
    #[inline]
    pub fn ack(&self) -> bool {
        (self.header().flags & ACK) != 0
    }

    /// Sets the acknowledgment flag.
    #[inline]
    pub fn set_ack(&mut self) {
        self.header_mut().flags |= ACK;
    }

    /// Unsets the acknowledgment flag.
    #[inline]
    pub fn unset_ack(&mut self) {
        self.header_mut().flags &= !ACK;
    }

    /// Returns a flag instructing the sender to push the packet immediately
    /// without waiting for more data.
    #[inline]
    pub fn psh(&self) -> bool {
        (self.header().flags & PSH) != 0
    }

    /// Sets the push function flag.
    #[inline]
    pub fn set_psh(&mut self) {
        self.header_mut().flags |= PSH;
    }

    /// Unsets the push function flag.
    #[inline]
    pub fn unset_psh(&mut self) {
        self.header_mut().flags &= !PSH;
    }

    /// Returns a flag indicating the connection should be reset.
    #[inline]
    pub fn rst(&self) -> bool {
        (self.header().flags & RST) != 0
    }

    /// Sets the reset flag.
    #[inline]
    pub fn set_rst(&mut self) {
        self.header_mut().flags |= RST;
    }

    /// Unsets the reset flag.
    #[inline]
    pub fn unset_rst(&mut self) {
        self.header_mut().flags &= !RST;
    }

    /// Returns a flag indicating to synchronize the sequence numbers to
    /// initiate a new TCP connection.
    #[inline]
    pub fn syn(&self) -> bool {
        (self.header().flags & SYN) != 0
    }

    /// Sets the synchronize sequence numbers flag.
    #[inline]
    pub fn set_syn(&mut self) {
        self.header_mut().flags |= SYN;
    }

    /// Unsets the synchronize sequence numbers flag.
    #[inline]
    pub fn unset_syn(&mut self) {
        self.header_mut().flags &= !SYN;
    }

    /// Returns whether `SYN` and `ACK` flags are both set. This check is
    /// part of the 3-way handshake when initializing a new TCP connection.
    #[inline]
    pub fn syn_ack(&self) -> bool {
        self.syn() && self.ack()
    }

    /// Returns a flag indicating no more data from sender.
    #[inline]
    pub fn fin(&self) -> bool {
        (self.header().flags & FIN) != 0
    }

    /// Sets the finished flag.
    #[inline]
    pub fn set_fin(&mut self) {
        self.header_mut().flags |= FIN;
    }

    /// Unsets the finished flag.
    #[inline]
    pub fn unset_fin(&mut self) {
        self.header_mut().flags &= !FIN;
    }

    /// Returns the TCP window.
    #[inline]
    pub fn window(&self) -> u16 {
        u16::from_be(self.header().window)
    }

    /// Sets the TCP window.
    #[inline]
    pub fn set_window(&mut self, window: u16) {
        self.header_mut().window = u16::to_be(window);
    }

    /// Returns the checksum.
    #[inline]
    pub fn checksum(&self) -> u16 {
        u16::from_be(self.header().checksum)
    }

    /// Sets the checksum.
    #[inline]
    fn set_checksum(&mut self, checksum: u16) {
        self.header_mut().checksum = u16::to_be(checksum);
    }

    /// Returns the urgent pointer.
    #[inline]
    pub fn urgent_pointer(&self) -> u16 {
        u16::from_be(self.header().urgent_pointer)
    }

    /// Sets the urgent pointer.
    #[inline]
    pub fn set_urgent_pointer(&mut self, urgent_pointer: u16) {
        self.header_mut().urgent_pointer = u16::to_be(urgent_pointer);
    }

    /// Returns the 5-tuple that uniquely identifies a TCP connection.
    #[inline]
    pub fn flow(&self) -> Flow {
        Flow::new(
            self.envelope().src(),
            self.envelope().dst(),
            self.src_port(),
            self.dst_port(),
            ProtocolNumbers::Tcp,
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
        self.set_checksum(0);

        if let Ok(data) = self.mbuf().read_data_slice(self.offset, self.len()) {
            let data = unsafe { data.as_ref() };
            let pseudo_header_sum = self
                .envelope()
                .pseudo_header(data.len() as u16, ProtocolNumbers::Tcp)
                .sum();
            let checksum = checksum::compute(pseudo_header_sum, data);
            self.set_checksum(checksum);
        } else {
            // we are reading till the end of buffer, should never run out
            unreachable!()
        }
    }
}

impl<E: IpPacket> fmt::Debug for Tcp<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("tcp")
            .field("src_port", &self.src_port())
            .field("dst_port", &self.dst_port())
            .field("seq_no", &self.seq_no())
            .field("ack_no", &self.ack_no())
            .field("data_offset", &self.data_offset())
            .field("window", &self.window())
            .field("checksum", &format!("0x{:04x}", self.checksum()))
            .field("urgent pointer", &self.urgent_pointer())
            .field("ns", &self.ns())
            .field("cwr", &self.cwr())
            .field("ece", &self.ece())
            .field("urg", &self.urg())
            .field("ack", &self.ack())
            .field("psh", &self.psh())
            .field("rst", &self.rst())
            .field("syn", &self.syn())
            .field("fin", &self.fin())
            .field("$offset", &self.offset())
            .field("$len", &self.len())
            .field("$header_len", &self.header_len())
            .finish()
    }
}

impl<E: IpPacket> PacketBase for Tcp<E> {
    fn clone(&self, internal: Internal) -> Self {
        Tcp::<E> {
            envelope: self.envelope.clone(internal),
            header: self.header,
            offset: self.offset,
        }
    }
}

impl<E: IpPacket> Packet for Tcp<E> {
    type Envelope = E;
    type Header = TcpHeader;

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
            envelope.next_protocol() == ProtocolNumbers::Tcp,
            ParseError::new("not a TCP packet.")
        );

        let mbuf = envelope.mbuf();
        let offset = envelope.payload_offset();
        let header = mbuf.read_data(offset)?;

        Ok(Tcp {
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

        envelope.set_next_protocol(ProtocolNumbers::Tcp);

        Ok(Tcp {
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
        self.compute_checksum();
        self.envelope_mut().cascade();
    }

    #[inline]
    fn deparse(self) -> Self::Envelope {
        self.envelope
    }
}

/// TCP header accessible through [`Tcp`].
///
/// The header only include the fixed portion of the TCP header. Variable
/// sized options are parsed separately.
///
/// [`Tcp`]: Tcp
#[derive(Clone, Copy, Debug, SizeOf)]
#[repr(C, packed)]
pub struct TcpHeader {
    src_port: u16,
    dst_port: u16,
    seq_no: u32,
    ack_no: u32,
    offset_to_ns: u8,
    flags: u8,
    window: u16,
    checksum: u16,
    urgent_pointer: u16,
}

impl Default for TcpHeader {
    fn default() -> TcpHeader {
        TcpHeader {
            src_port: 0,
            dst_port: 0,
            seq_no: 0,
            ack_no: 0,
            offset_to_ns: 5 << 4,
            flags: 0,
            window: 0,
            checksum: 0,
            urgent_pointer: 0,
        }
    }
}

impl Header for TcpHeader {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packets::ip::v4::Ipv4;
    use crate::packets::ip::v6::{Ipv6, SegmentRouting};
    use crate::packets::Ethernet;
    use crate::testils::byte_arrays::{IPV4_TCP_PACKET, IPV4_UDP_PACKET, SR_TCP_PACKET};
    use crate::Mbuf;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn size_of_tcp_header() {
        assert_eq!(20, TcpHeader::size_of());
    }

    #[capsule::test]
    fn parse_tcp_packet() {
        let packet = Mbuf::from_bytes(&IPV4_TCP_PACKET).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();
        let ipv4 = ethernet.parse::<Ipv4>().unwrap();
        let tcp = ipv4.parse::<Tcp<Ipv4>>().unwrap();

        assert_eq!(36869, tcp.src_port());
        assert_eq!(23, tcp.dst_port());
        assert_eq!(1_913_975_060, tcp.seq_no());
        assert_eq!(0, tcp.ack_no());
        assert_eq!(6, tcp.data_offset());
        assert_eq!(8760, tcp.window());
        assert_eq!(0xa92c, tcp.checksum());
        assert_eq!(0, tcp.urgent_pointer());
        assert!(!tcp.ns());
        assert!(!tcp.cwr());
        assert!(!tcp.ece());
        assert!(!tcp.urg());
        assert!(!tcp.ack());
        assert!(!tcp.psh());
        assert!(!tcp.rst());
        assert!(tcp.syn());
        assert!(!tcp.fin());
    }

    #[capsule::test]
    fn parse_non_tcp_packet() {
        let packet = Mbuf::from_bytes(&IPV4_UDP_PACKET).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();
        let ipv4 = ethernet.parse::<Ipv4>().unwrap();

        assert!(ipv4.parse::<Tcp<Ipv4>>().is_err());
    }

    #[capsule::test]
    fn tcp_flow_v4() {
        let packet = Mbuf::from_bytes(&IPV4_TCP_PACKET).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();
        let ipv4 = ethernet.parse::<Ipv4>().unwrap();
        let tcp = ipv4.parse::<Tcp<Ipv4>>().unwrap();
        let flow = tcp.flow();

        assert_eq!("139.133.217.110", flow.src_ip().to_string());
        assert_eq!("139.133.233.2", flow.dst_ip().to_string());
        assert_eq!(36869, flow.src_port());
        assert_eq!(23, flow.dst_port());
        assert_eq!(ProtocolNumbers::Tcp, flow.protocol());
    }

    #[capsule::test]
    fn tcp_flow_v6() {
        let packet = Mbuf::from_bytes(&SR_TCP_PACKET).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();
        let ipv6 = ethernet.parse::<Ipv6>().unwrap();
        let srh = ipv6.parse::<SegmentRouting<Ipv6>>().unwrap();
        let tcp = srh.parse::<Tcp<SegmentRouting<Ipv6>>>().unwrap();
        let flow = tcp.flow();

        assert_eq!("2001:db8:85a3::1", flow.src_ip().to_string());
        assert_eq!("2001:db8:85a3::8a2e:370:7333", flow.dst_ip().to_string());
        assert_eq!(3464, flow.src_port());
        assert_eq!(1024, flow.dst_port());
        assert_eq!(ProtocolNumbers::Tcp, flow.protocol());
    }

    #[capsule::test]
    fn set_src_dst_ip() {
        let packet = Mbuf::from_bytes(&IPV4_TCP_PACKET).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();
        let ipv4 = ethernet.parse::<Ipv4>().unwrap();
        let mut tcp = ipv4.parse::<Tcp<Ipv4>>().unwrap();

        let old_checksum = tcp.checksum();
        let new_ip = Ipv4Addr::new(10, 0, 0, 0);
        assert!(tcp.set_src_ip(new_ip.into()).is_ok());
        assert!(tcp.checksum() != old_checksum);
        assert_eq!(new_ip.to_string(), tcp.envelope().src().to_string());

        let old_checksum = tcp.checksum();
        let new_ip = Ipv4Addr::new(20, 0, 0, 0);
        assert!(tcp.set_dst_ip(new_ip.into()).is_ok());
        assert!(tcp.checksum() != old_checksum);
        assert_eq!(new_ip.to_string(), tcp.envelope().dst().to_string());

        // can't set v6 addr on a v4 packet
        assert!(tcp.set_src_ip(Ipv6Addr::UNSPECIFIED.into()).is_err());
    }

    #[capsule::test]
    fn compute_checksum() {
        let packet = Mbuf::from_bytes(&IPV4_TCP_PACKET).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();
        let ipv4 = ethernet.parse::<Ipv4>().unwrap();
        let mut tcp = ipv4.parse::<Tcp<Ipv4>>().unwrap();

        let expected = tcp.checksum();
        // no payload change but force a checksum recompute anyway
        tcp.cascade();
        assert_eq!(expected, tcp.checksum());
    }

    #[capsule::test]
    fn push_tcp_packet() {
        let packet = Mbuf::new().unwrap();
        let ethernet = packet.push::<Ethernet>().unwrap();
        let ipv4 = ethernet.push::<Ipv4>().unwrap();
        let tcp = ipv4.push::<Tcp<Ipv4>>().unwrap();

        assert_eq!(TcpHeader::size_of(), tcp.len());
        assert_eq!(5, tcp.data_offset());

        // make sure the next protocol is fixed
        assert_eq!(ProtocolNumbers::Tcp, tcp.envelope().next_protocol());
    }
}

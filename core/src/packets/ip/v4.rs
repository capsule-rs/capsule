use crate::packets::checksum::PseudoHeader;
use crate::packets::ip::{IpAddrMismatchError, IpPacket, ProtocolNumber};
use crate::packets::{CondRc, EtherTypes, Ethernet, Header, Packet};
use crate::{Result, SizeOf};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr};
use std::ptr::NonNull;

// Masks.
const DSCP: u8 = 0b1111_1100;
const ECN: u8 = !DSCP;
const FLAGS_DF: u16 = 0b0100_0000_0000_0000;
const FLAGS_MF: u16 = 0b0010_0000_0000_0000;

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
/// Version:  4 bits
///     The Version field indicates the format of the internet header.  This
///     document describes version 4.
///
/// IHL:  4 bits
///     Internet Header Length is the length of the internet header in 32
///     bit words, and thus points to the beginning of the data.  Note that
///     the minimum value for a correct header is 5.
///
/// DSCP:  6 bits
///     Differentiated services codepoint defined in [IETF RFC 2474]. Used to
///     select the per hop behavior a packet experiences at each node.
///
/// ECN:   2 bits
///     Explicit congestion notification codepoint defined in [IETF RFC 3168].
///
/// Total Length:  16 bits
///     Total Length is the length of the datagram, measured in octets,
///     including internet header and data.
///
/// Identification:  16 bits
///     An identifying value assigned by the sender to aid in assembling the
///     fragments of a datagram.
///
/// Flags:  3 bits
///     Various Control Flags.
///
///     Bit 0: reserved, must be zero
///     Bit 1: (DF) 0 = May Fragment,  1 = Don't Fragment.
///     Bit 2: (MF) 0 = Last Fragment, 1 = More Fragments.
///
///       0   1   2
///     +---+---+---+
///     |   | D | M |
///     | 0 | F | F |
///     +---+---+---+
///
/// Fragment Offset:  13 bits
///     This field indicates where in the datagram this fragment belongs.
///     The fragment offset is measured in units of 8 octets (64 bits).  The
///     first fragment has offset zero.
///
/// Time to Live:  8 bits
///     This field indicates the maximum time the datagram is allowed to
///     remain in the internet system.  If this field contains the value
///     zero, then the datagram must be destroyed.  This field is modified
///     in internet header processing.  The time is measured in units of
///     seconds, but since every module that processes a datagram must
///     decrease the TTL by at least one even if it process the datagram in
///     less than a second, the TTL must be thought of only as an upper
///     bound on the time a datagram may exist.  The intention is to cause
///     undeliverable datagrams to be discarded, and to bound the maximum
///     datagram lifetime.
///
/// Protocol:  8 bits
///     This field indicates the next level protocol used in the data
///     portion of the internet datagram.  The values for various protocols
///     are specified in "Assigned Numbers".
///
/// Header Checksum:  16 bits
///     A checksum on the header only.  Since some header fields change
///     (e.g., time to live), this is recomputed and verified at each point
///     that the internet header is processed.
///
/// Source Address:  32 bits
///     The source address.
///
/// Destination Address:  32 bits
///     The destination address.
///
/// Options:  variable
///     The options may appear or not in datagrams.  They must be
///     implemented by all IP modules (host and gateways).  What is optional
///     is their transmission in any particular datagram, not their
///     implementation.
///
/// [IETF RFC 791]: https://tools.ietf.org/html/rfc791#section-3.1
/// [IETF RFC 2474]: https://tools.ietf.org/html/rfc2474
/// [IETF RFC 3168]: https://tools.ietf.org/html/rfc3168
#[derive(Clone)]
pub struct Ipv4 {
    envelope: CondRc<Ethernet>,
    header: NonNull<Ipv4Header>,
    offset: usize,
}

impl Ipv4 {
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
        u16::from_be(self.header().total_length)
    }

    /// Sets the length of the packet.
    #[inline]
    fn set_total_length(&mut self, total_length: u16) {
        self.header_mut().total_length = u16::to_be(total_length);
    }

    /// Returns the identifying value assigned by the sender to aid in
    /// assembling the fragments of a packet.
    #[inline]
    pub fn identification(&self) -> u16 {
        u16::from_be(self.header().identification)
    }

    /// Sets the identifying value.
    #[inline]
    pub fn set_identification(&mut self, identification: u16) {
        self.header_mut().identification = u16::to_be(identification);
    }

    /// Returns a flag indicating whether the packet can be fragmented.
    #[inline]
    pub fn dont_fragment(&self) -> bool {
        u16::from_be(self.header().flags_to_frag_offset) & FLAGS_DF != 0
    }

    /// Sets the don't fragment flag to indicate that the packet must not
    /// be fragmented.
    #[inline]
    pub fn set_dont_fragment(&mut self) {
        self.header_mut().flags_to_frag_offset =
            u16::to_be(u16::from_be(self.header().flags_to_frag_offset) | FLAGS_DF);
    }

    /// Unsets the don't fragment flag to indicate that the packet may be
    /// fragmented.
    #[inline]
    pub fn unset_dont_fragment(&mut self) {
        self.header_mut().flags_to_frag_offset =
            u16::to_be(u16::from_be(self.header().flags_to_frag_offset) & !FLAGS_DF);
    }

    /// Returns a flag indicating whether there are more fragments.
    #[inline]
    pub fn more_fragments(&self) -> bool {
        u16::from_be(self.header().flags_to_frag_offset) & FLAGS_MF != 0
    }

    /// Sets the more fragment flag indicating there are more fragments.
    #[inline]
    pub fn set_more_fragments(&mut self) {
        self.header_mut().flags_to_frag_offset =
            u16::to_be(u16::from_be(self.header().flags_to_frag_offset) | FLAGS_MF);
    }

    /// Unsets the more fragment flag indicating this is the last fragment.
    #[inline]
    pub fn unset_more_fragments(&mut self) {
        self.header_mut().flags_to_frag_offset =
            u16::to_be(u16::from_be(self.header().flags_to_frag_offset) & !FLAGS_MF);
    }

    /// Clears the don't fragment and more fragments flags.
    #[inline]
    pub fn clear_flags(&mut self) {
        self.header_mut().flags_to_frag_offset =
            u16::to_be(u16::from_be(self.header().flags_to_frag_offset) & !0xe000);
    }

    /// Returns an offset indicating where in the datagram this fragment
    /// belongs. It is measured in units of 8 octets or 64 bits. The first
    /// fragment has offset zero.
    #[inline]
    pub fn fragment_offset(&self) -> u16 {
        u16::from_be(self.header().flags_to_frag_offset) & 0x1fff
    }

    /// Sets the fragment offset.
    #[inline]
    pub fn set_fragment_offset(&mut self, offset: u16) {
        self.header_mut().flags_to_frag_offset = u16::to_be(
            (u16::from_be(self.header().flags_to_frag_offset) & 0xe000) | (offset & 0x1fff),
        );
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
        u16::from_be(self.header().checksum)
    }

    /// Sets the checksum.
    #[allow(dead_code)]
    #[inline]
    fn set_checksum(&mut self, checksum: u16) {
        self.header_mut().checksum = u16::to_be(checksum);
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
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
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
    type Header = Ipv4Header;
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
    fn do_parse(envelope: Self::Envelope) -> Result<Self> {
        let mbuf = envelope.mbuf();
        let offset = envelope.payload_offset();
        let header = mbuf.read_data(offset)?;

        Ok(Ipv4 {
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

        envelope.set_ether_type(EtherTypes::Ipv4);

        Ok(Ipv4 {
            envelope: CondRc::new(envelope),
            header,
            offset,
        })
    }

    #[inline]
    fn remove(mut self) -> Result<Self::Envelope> {
        let offset = self.offset();
        let len = self.header_len();
        self.mbuf_mut().shrink(offset, len)?;
        Ok(self.envelope.into_owned())
    }

    #[inline]
    fn cascade(&mut self) {
        // TODO: fix header checksum
        let len = self.len() as u16;
        self.set_total_length(len);
        self.envelope_mut().cascade();
    }

    #[inline]
    fn deparse(self) -> Self::Envelope {
        self.envelope.into_owned()
    }
}

impl IpPacket for Ipv4 {
    #[inline]
    fn next_proto(&self) -> ProtocolNumber {
        self.protocol()
    }

    #[inline]
    fn set_next_proto(&mut self, proto: ProtocolNumber) {
        self.set_protocol(proto);
    }

    #[inline]
    fn src(&self) -> IpAddr {
        IpAddr::V4(self.src())
    }

    #[inline]
    fn set_src(&mut self, src: IpAddr) -> Result<()> {
        match src {
            IpAddr::V4(addr) => {
                self.set_src(addr);
                Ok(())
            }
            _ => Err(IpAddrMismatchError.into()),
        }
    }

    #[inline]
    fn dst(&self) -> IpAddr {
        IpAddr::V4(self.dst())
    }

    #[inline]
    fn set_dst(&mut self, dst: IpAddr) -> Result<()> {
        match dst {
            IpAddr::V4(addr) => {
                self.set_dst(addr);
                Ok(())
            }
            _ => Err(IpAddrMismatchError.into()),
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
}

/// IPv4 header.
///
/// The header only include the fixed portion of the IPv4 header.
/// Options are parsed separately.
#[derive(Clone, Copy, Debug)]
#[repr(C, packed)]
pub struct Ipv4Header {
    version_ihl: u8,
    dscp_ecn: u8,
    total_length: u16,
    identification: u16,
    flags_to_frag_offset: u16,
    ttl: u8,
    protocol: u8,
    checksum: u16,
    src: Ipv4Addr,
    dst: Ipv4Addr,
}

impl Default for Ipv4Header {
    fn default() -> Ipv4Header {
        Ipv4Header {
            version_ihl: 0x45,
            dscp_ecn: 0,
            total_length: 0,
            identification: 0,
            flags_to_frag_offset: 0,
            ttl: 0,
            protocol: 0,
            checksum: 0,
            src: Ipv4Addr::UNSPECIFIED,
            dst: Ipv4Addr::UNSPECIFIED,
        }
    }
}

impl Header for Ipv4Header {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packets::ip::ProtocolNumbers;
    use crate::packets::UDP_PACKET;
    use crate::Mbuf;

    #[test]
    fn size_of_ipv4_header() {
        assert_eq!(20, Ipv4Header::size_of());
    }

    #[nb2::test]
    fn parse_ipv4_packet() {
        let packet = Mbuf::from_bytes(&UDP_PACKET).unwrap();
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

    #[nb2::test]
    fn parse_ipv4_setter_checks() {
        let packet = Mbuf::from_bytes(&UDP_PACKET).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();
        let mut ipv4 = ethernet.parse::<Ipv4>().unwrap();

        // Flags
        assert_eq!(true, ipv4.dont_fragment());
        assert_eq!(false, ipv4.more_fragments());
        ipv4.unset_dont_fragment();
        assert_eq!(false, ipv4.dont_fragment());
        ipv4.set_more_fragments();
        assert_eq!(true, ipv4.more_fragments());
        ipv4.set_fragment_offset(5);
        assert_eq!(5, ipv4.fragment_offset());
        ipv4.clear_flags();
        assert_eq!(false, ipv4.dont_fragment());
        assert_eq!(false, ipv4.more_fragments());

        // DSCP & ECN
        assert_eq!(0, ipv4.dscp());
        assert_eq!(0, ipv4.ecn());
        ipv4.set_dscp(10);
        ipv4.set_ecn(3);
        assert_eq!(10, ipv4.dscp());
        assert_eq!(3, ipv4.ecn());
    }

    #[nb2::test]
    fn push_ipv4_packet() {
        let packet = Mbuf::new().unwrap();
        let ethernet = packet.push::<Ethernet>().unwrap();
        let ipv4 = ethernet.push::<Ipv4>().unwrap();

        assert_eq!(4, ipv4.version());
        assert_eq!(Ipv4Header::size_of(), ipv4.len());

        // make sure ether type is fixed
        assert_eq!(EtherTypes::Ipv4, ipv4.envelope().ether_type());
    }
}

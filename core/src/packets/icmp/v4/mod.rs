mod echo_reply;
mod echo_request;

pub use self::echo_reply::*;
pub use self::echo_request::*;

use crate::packets::ip::IpPacket;
use crate::packets::ip::ProtocolNumbers;
use crate::packets::{checksum, CondRc, Header, Packet, ParseError};
use crate::{ensure, Result, SizeOf};
use std::fmt;
use std::ptr::NonNull;

/// Base Internet Control Message Protocol (for v4 packet) based on [IETF RFC 792].
///
/// ```
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Type      |     Code      |          Checksum             |
/// |                                                               |
/// +                         Message Body                          +
/// |                                                               |
/// ```
/// The type field indicates the type of the message.  Its value
/// determines the format of the remaining data.
///
/// The code field depends on the message type.  It is used to create an
/// additional level of message granularity.
///
/// The checksum field is used to detect data corruption in the ICMPv4
/// message and parts of the IPv4 header.
///
/// The message body varies based on the type field. The packet needs to
/// be first parsed with the unit `()` payload before the type field can
/// be read.
///
/// # Example
///
/// ```
/// if ipv4.protocol() == ProtocolNumbers::Icmpv4 {
///     let icmpv4 = ipv4.parse::<Icmpv4<()>>().unwrap();
///     println!("{}", icmpv4.msg_type());
/// }
/// ```
///
/// [IETF RFC 792]: https://tools.ietf.org/html/rfc792

#[derive(Clone)]
pub struct Icmpv4<E: IpPacket, P: Icmpv4Payload> {
    envelope: CondRc<E>,
    header: NonNull<Icmpv4Header>,
    payload: NonNull<P>,
    offset: usize,
}

impl<E: IpPacket> Icmpv4<E, ()> {
    pub fn downcast<P: Icmpv4Payload>(self) -> Result<Icmpv4<E, P>> {
        Icmpv4::<E, P>::do_parse(self.envelope.into_owned())
    }
}

impl<E: IpPacket> fmt::Debug for Icmpv4<E, ()> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("icmpv4")
            .field("type", &self.msg_type())
            .field("code", &self.code())
            .field("checksum", &format!("0x{:04x}", self.checksum()))
            .field("$offset", &self.offset())
            .field("$len", &self.len())
            .field("$header_len", &self.header_len())
            .finish()
    }
}

impl<E: IpPacket, P: Icmpv4Payload> Icmpv4Packet<E, P> for Icmpv4<E, P> {
    fn payload(&self) -> &P {
        unsafe { self.payload.as_ref() }
    }

    fn payload_mut(&mut self) -> &mut P {
        unsafe { self.payload.as_mut() }
    }
}

impl<E: IpPacket, P: Icmpv4Payload> Packet for Icmpv4<E, P> {
    type Header = Icmpv4Header;
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

    #[doc(hidden)]
    #[inline]
    fn do_parse(envelope: Self::Envelope) -> Result<Self> {
        ensure!(
            envelope.next_proto() == ProtocolNumbers::Icmpv4,
            ParseError::new("not an ICMPv4 packet.")
        );

        let mbuf = envelope.mbuf();
        let offset = envelope.payload_offset();
        let header = mbuf.read_data(offset)?;
        let payload = mbuf.read_data(offset + Self::Header::size_of())?;

        Ok(Icmpv4 {
            envelope: CondRc::new(envelope),
            header,
            payload,
            offset,
        })
    }

    #[doc(hidden)]
    #[inline]
    fn do_push(mut envelope: Self::Envelope) -> Result<Self> {
        let offset = envelope.payload_offset();
        let mbuf = envelope.mbuf_mut();

        mbuf.extend(offset, Self::Header::size_of() + P::size_of())?;
        let header = mbuf.write_data(offset, &Self::Header::default())?;
        let payload = mbuf.write_data(offset + Self::Header::size_of(), &P::default())?;

        let mut packet = Icmpv4 {
            envelope: CondRc::new(envelope),
            header,
            payload,
            offset,
        };

        packet.header_mut().msg_type = P::msg_type().0;
        packet
            .envelope_mut()
            .set_next_proto(ProtocolNumbers::Icmpv4);

        Ok(packet)
    }

    #[inline]
    fn remove(mut self) -> Result<Self::Envelope> {
        let offset = self.offset();
        let len = self.header_len();
        self.mbuf_mut().shrink(offset, len)?;
        Ok(self.envelope.into_owned())
    }

    #[inline]
    default fn cascade(&mut self) {
        self.compute_checksum();
        self.envelope_mut().cascade();
    }

    #[inline]
    fn deparse(self) -> Self::Envelope {
        self.envelope.into_owned()
    }
}

/// Type of ICMPv4 message.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(C, packed)]
pub struct Icmpv4Type(pub u8);

impl Icmpv4Type {
    pub fn new(value: u8) -> Self {
        Icmpv4Type(value)
    }
}

impl fmt::Display for Icmpv4Type {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match *self {
                Icmpv4Types::EchoRequest => "Echo Request".to_string(),
                Icmpv4Types::EchoReply => "Echo Reply".to_string(),
                _ => format!("{}", self.0),
            }
        )
    }
}

/// Icmpv4 packet header.
#[derive(Clone, Copy, Debug, Default)]
#[repr(C, packed)]
pub struct Icmpv4Header {
    msg_type: u8,
    code: u8,
    checksum: u16,
}

/// Supported Icmpv4 message types.
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
pub mod Icmpv4Types {
    use super::Icmpv4Type;

    pub const EchoRequest: Icmpv4Type = Icmpv4Type(8);
    pub const EchoReply: Icmpv4Type = Icmpv4Type(0);
}

impl Header for Icmpv4Header {}

pub trait Icmpv4Payload: Clone + Default + SizeOf {
    /// Returns the ICMPv4 message type that corresponds to the payload.
    fn msg_type() -> Icmpv4Type;
}

/// ICMPv4 unit payload `()`.
impl Icmpv4Payload for () {
    fn msg_type() -> Icmpv4Type {
        // Unit payload does not have a type
        unreachable!();
    }
}

/// Common behaviors shared by ICMPv4 packets.
pub trait Icmpv4Packet<E: IpPacket, P: Icmpv4Payload>:
    Packet<Header = Icmpv4Header, Envelope = E>
{
    /// Returns a reference to the fixed payload.
    fn payload(&self) -> &P;

    /// Returns a mutable reference to the fixed payload.
    fn payload_mut(&mut self) -> &mut P;

    /// Returns the message type.
    #[inline]
    fn msg_type(&self) -> Icmpv4Type {
        Icmpv4Type::new(self.header().msg_type)
    }

    /// Returns the code.
    #[inline]
    fn code(&self) -> u8 {
        self.header().code
    }

    /// Sets the code.
    #[inline]
    fn set_code(&mut self, code: u8) {
        self.header_mut().code = code
    }

    /// Returns the checksum.
    #[inline]
    fn checksum(&self) -> u16 {
        u16::from_be(self.header().checksum)
    }

    #[inline]
    fn compute_checksum(&mut self) {
        self.header_mut().checksum = 0;

        if let Ok(data) = self.mbuf().read_data_slice(self.offset(), self.len()) {
            let data = unsafe { data.as_ref() };
            let checksum = checksum::compute(0, data);
            self.header_mut().checksum = u16::to_be(checksum);
        } else {
            // we are reading till the end of buffer, should never run out
            unreachable!()
        }
    }
}

/// An ICMPv4 message with parsed payload.
pub enum Icmpv4Message<E: IpPacket> {
    EchoRequest(Icmpv4<E, EchoRequest>),
    EchoReply(Icmpv4<E, EchoReply>),
    /// an ICMPv4 message with undefined payload
    Undefined(Icmpv4<E, ()>),
}

/// ICMPv4 helper functions for IPv6 packets.
pub trait Icmpv4Parse {
    type Envelope: IpPacket;

    fn parse_icmpv4(self) -> Result<Icmpv4Message<Self::Envelope>>;
}

impl<T: IpPacket> Icmpv4Parse for T {
    type Envelope = T;

    fn parse_icmpv4(self) -> Result<Icmpv4Message<Self::Envelope>> {
        if self.next_proto() == ProtocolNumbers::Icmpv4 {
            let icmpv4 = self.parse::<Icmpv4<Self::Envelope, ()>>()?;
            match icmpv4.msg_type() {
                Icmpv4Types::EchoRequest => {
                    let packet = icmpv4.downcast::<EchoRequest>()?;
                    Ok(Icmpv4Message::EchoRequest(packet))
                }
                Icmpv4Types::EchoReply => {
                    let packet = icmpv4.downcast::<EchoReply>()?;
                    Ok(Icmpv4Message::EchoReply(packet))
                }
                _ => Ok(Icmpv4Message::Undefined(icmpv4)),
            }
        } else {
            Err(ParseError::new("Packet is not Icmpv4").into())
        }
    }
}

#[cfg(any(test, feature = "testils"))]
#[rustfmt::skip]
pub const ICMPV4_PACKET: [u8; 74] = [
// ethernet header
    0x00, 0x50, 0x56, 0xe0, 0x14, 0x49,
    0x00, 0x0c, 0x29, 0x34, 0x0B, 0xde,
    0x08, 0x00,
// IPv4 header
    0x45, 0x00, 0x00, 0x3c,
    0xd7, 0x43, 0x00, 0x00,
    0x80, 0x01, 0x2b, 0x73,
    0xc0, 0xa8, 0x9e, 0x8b,
    0xae, 0x89, 0x2a, 0x4d,
// ICMPv4 header
    0x08, 0x00, 0x2a, 0x5c, 0x02, 0x00,
    0x21, 0x00, 0x61, 0x62, 0x63, 0x64,
    0x65, 0x66, 0x67, 0x68, 0x69, 0x6a,
    0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70,
    0x71, 0x72, 0x73, 0x74, 0x75, 0x76,
    0x77, 0x61, 0x62, 0x63, 0x64, 0x65,
    0x66, 0x67, 0x68, 0x69,
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packets::icmp::v4::EchoRequest;
    use crate::packets::ip::v4::Ipv4;
    use crate::packets::Ethernet;
    use crate::testils::byte_arrays::UDP_PACKET;
    use crate::Mbuf;

    #[test]
    fn size_of_icmpv4_header() {
        assert_eq!(4, Icmpv4Header::size_of());
    }

    #[nb2::test]
    fn parse_icmpv4_packet() {
        let packet = Mbuf::from_bytes(&ICMPV4_PACKET).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();
        let ipv4 = ethernet.parse::<Ipv4>().unwrap();
        let icmpv4 = ipv4.parse::<Icmpv4<Ipv4, ()>>().unwrap();

        assert_eq!(Icmpv4Type::new(0x8), icmpv4.msg_type());
        assert_eq!(0, icmpv4.code());
        assert_eq!(0x2a5c, icmpv4.checksum());
    }

    #[nb2::test]
    fn parse_non_icmpv6_packet() {
        let packet = Mbuf::from_bytes(&UDP_PACKET).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();
        let ipv4 = ethernet.parse::<Ipv4>().unwrap();

        assert!(ipv4.parse::<Icmpv4<Ipv4, ()>>().is_err());
    }

    #[nb2::test]
    fn downcast_icmpv4() {
        let packet = Mbuf::from_bytes(&ICMPV4_PACKET).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();
        let ipv4 = ethernet.parse::<Ipv4>().unwrap();
        let icmpv4 = ipv4.parse::<Icmpv4<Ipv4, ()>>().unwrap();
        let request = icmpv4.downcast::<EchoRequest>().unwrap();

        // check one accessor that belongs to `EchoRequest`
        assert_eq!(8448, request.seq_no());
    }

    #[nb2::test]
    fn compute_checksum() {
        let packet = Mbuf::from_bytes(&ICMPV4_PACKET).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();
        let ipv4 = ethernet.parse::<Ipv4>().unwrap();
        let mut icmpv4 = ipv4.parse::<Icmpv4<Ipv4, ()>>().unwrap();

        let expected = icmpv4.checksum();
        // no payload change but force a checksum recompute anyway
        icmpv4.cascade();
        assert_eq!(expected, icmpv4.checksum());
    }

    #[nb2::test]
    fn matchable_icmpv4_packets() {
        let packet = Mbuf::from_bytes(&ICMPV4_PACKET).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();
        let ipv4 = ethernet.parse::<Ipv4>().unwrap();
        if let Ok(Icmpv4Message::EchoRequest(icmpv4)) = ipv4.parse_icmpv4() {
            assert_eq!(Icmpv4Type::new(0x8), icmpv4.msg_type());
        } else {
            panic!("bad packet");
        }
    }
}

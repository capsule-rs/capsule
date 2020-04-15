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

//! Internet Control Message Protocol for IPv4.

mod echo_reply;
mod echo_request;

pub use self::echo_reply::*;
pub use self::echo_request::*;

use crate::packets::ip::v4::Ipv4;
use crate::packets::ip::{IpPacket, ProtocolNumbers};
use crate::packets::{checksum, Internal, Packet, PacketBase, ParseError};
use crate::{ensure, SizeOf};
use failure::Fallible;
use std::fmt;
use std::ptr::NonNull;

/// Internet Control Message Protocol v4 packet based on [`IETF RFC 792`].
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
/// - *Type*:          Indicates the type of the message. Its value
///                    determines the format of the remaining data.
///
/// - *Code*:          This field depends on the message type. It is used to
///                    create an additional level of message granularity.
///
/// - *Checksum*:      This field is used to detect data corruption in the
///                    ICMPv4 message and parts of the IPv4 header.
///
/// - *Message Body*:  Varies based on the type field and implemented with
///                    trait [`Icmpv4Payload`]. The packet needs to be first
///                    parsed with the unit `()` payload before the type field
///                    can be read.
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
/// [`IETF RFC 792`]: https://tools.ietf.org/html/rfc792
/// [`Icmpv4Payload`]: Icmpv4Payload
pub struct Icmpv4<P: Icmpv4Payload> {
    envelope: Ipv4,
    header: NonNull<Icmpv4Header>,
    payload: NonNull<P>,
    offset: usize,
}

impl fmt::Debug for Icmpv4<()> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("icmpv4")
            .field("type", &format!("{}", self.msg_type()))
            .field("code", &self.code())
            .field("checksum", &format!("0x{:04x}", self.checksum()))
            .field("$offset", &self.offset())
            .field("$len", &self.len())
            .field("$header_len", &self.header_len())
            .finish()
    }
}

impl Icmpv4Packet<()> for Icmpv4<()> {
    #[inline]
    fn header(&self) -> &Icmpv4Header {
        unsafe { self.header.as_ref() }
    }

    #[inline]
    fn header_mut(&mut self) -> &mut Icmpv4Header {
        unsafe { self.header.as_mut() }
    }

    #[inline]
    fn payload(&self) -> &() {
        unsafe { self.payload.as_ref() }
    }

    #[inline]
    fn payload_mut(&mut self) -> &mut () {
        unsafe { self.payload.as_mut() }
    }
}

impl PacketBase for Icmpv4<()> {
    type Envelope = Ipv4;

    #[inline]
    fn envelope0(&self) -> &Self::Envelope {
        &self.envelope
    }

    #[inline]
    fn envelope_mut0(&mut self) -> &mut Self::Envelope {
        &mut self.envelope
    }

    #[inline]
    fn into_envelope(self) -> Self::Envelope {
        self.envelope
    }

    #[inline]
    fn offset(&self) -> usize {
        self.offset
    }

    #[inline]
    fn header_len(&self) -> usize {
        Icmpv4Header::size_of()
    }

    #[inline]
    unsafe fn clone(&self, internal: Internal) -> Self {
        Icmpv4::<()> {
            envelope: self.envelope.clone(internal),
            header: self.header,
            payload: self.payload,
            offset: self.offset,
        }
    }

    #[inline]
    fn try_parse(envelope: Self::Envelope) -> Fallible<Self> {
        ensure!(
            envelope.next_protocol() == ProtocolNumbers::Icmpv4,
            ParseError::new("not an ICMPv4 packet.")
        );

        let mbuf = envelope.mbuf();
        let offset = envelope.payload_offset();
        let header = mbuf.read_data(offset)?;
        let payload = mbuf.read_data(offset + Icmpv4Header::size_of())?;

        Ok(Icmpv4 {
            envelope,
            header,
            payload,
            offset,
        })
    }

    #[inline]
    fn try_push(mut envelope: Self::Envelope, _internal: Internal) -> Fallible<Self> {
        let offset = envelope.payload_offset();
        let mbuf = envelope.mbuf_mut();

        mbuf.extend(offset, Icmpv4Header::size_of() + <()>::size_of())?;
        let header = mbuf.write_data(offset, &Icmpv4Header::default())?;
        let payload = mbuf.write_data(offset + Icmpv4Header::size_of(), &<()>::default())?;

        let mut packet = Icmpv4 {
            envelope,
            header,
            payload,
            offset,
        };

        packet.header_mut().msg_type = <()>::msg_type().0;
        packet
            .envelope_mut0()
            .set_next_protocol(ProtocolNumbers::Icmpv4);

        Ok(packet)
    }

    #[inline]
    fn fix_invariants(&mut self, _internal: Internal) {
        self.compute_checksum();
    }
}

/// Type of ICMPv4 message.
///
/// A list of supported types is under [`Icmpv4Types`].
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(C, packed)]
pub struct Icmpv4Type(pub u8);

impl Icmpv4Type {
    /// Creates a new ICMPv4 message type.
    pub fn new(value: u8) -> Self {
        Icmpv4Type(value)
    }
}

/// Supported ICMPv4 message types.
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
pub mod Icmpv4Types {
    use super::Icmpv4Type;

    /// Message type for [`Echo Request`].
    ///
    /// [`Echo Request`]: crate::packets::icmp::v4::EchoRequest
    pub const EchoRequest: Icmpv4Type = Icmpv4Type(8);
    /// Message type for [`Echo Reply`].
    ///
    /// [`Echo Reply`]: crate::packets::icmp::v4::EchoReply
    pub const EchoReply: Icmpv4Type = Icmpv4Type(0);
}

impl fmt::Display for Icmpv4Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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

/// ICMPv4 header.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Default, SizeOf)]
#[repr(C, packed)]
pub struct Icmpv4Header {
    msg_type: u8,
    code: u8,
    checksum: u16,
}

/// Common behaviors for ICMPv4 payloads.
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

/// A trait for common behaviors shared by ICMPv4 packets.
///
/// ## Derivable
///
/// The `Icmpv4Packet` trait can be used with `#[derive]` on Icmpv4 payloads,
/// which also derives the implementation for the [`Packet`] trait.
///
/// ```
/// #[derive(Icmpv4Packet)]
/// pub struct EchoReply {
///     ...
/// }
/// ```
///
/// ## Remarks
///
/// When using the associated derive macro, the payload struct implementation
/// must provide an private implementation of the `fix_invariants` function.
///
/// [`Packet`]: crate::packets::Packet
pub trait Icmpv4Packet<P: Icmpv4Payload>: Packet<Envelope = Ipv4> {
    /// Returns a reference to the header.
    fn header(&self) -> &Icmpv4Header;

    /// Returns a mutable reference to the header.
    fn header_mut(&mut self) -> &mut Icmpv4Header;

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

    /// Computes the checksum.
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

/// An [`ICMPv4`] message with parsed payload.
///
/// [`ICMPv4`]: `Icmpv4`
#[derive(Debug)]
pub enum Icmpv4Message {
    /// Echo Request message.
    EchoRequest(Icmpv4<EchoRequest>),

    /// Echo Reply message.
    EchoReply(Icmpv4<EchoReply>),

    /// An ICMPv4 message with undefined payload.
    Undefined(Icmpv4<()>),
}

/// Trait for parsing IPv4 packet payload as an ICMPv4 message.
pub trait Icmpv4Parse {
    /// Parses the IPv4 packet payload as an ICMPv4 message.
    fn parse_icmpv4(self) -> Fallible<Icmpv4Message>;
}

impl Icmpv4Parse for Ipv4 {
    fn parse_icmpv4(self) -> Fallible<Icmpv4Message> {
        if self.next_protocol() == ProtocolNumbers::Icmpv4 {
            let icmpv4 = self.parse::<Icmpv4<()>>()?;
            match icmpv4.msg_type() {
                Icmpv4Types::EchoRequest => {
                    let packet = icmpv4.deparse().parse::<Icmpv4<EchoRequest>>()?;
                    Ok(Icmpv4Message::EchoRequest(packet))
                }
                Icmpv4Types::EchoReply => {
                    let packet = icmpv4.deparse().parse::<Icmpv4<EchoReply>>()?;
                    Ok(Icmpv4Message::EchoReply(packet))
                }
                _ => Ok(Icmpv4Message::Undefined(icmpv4)),
            }
        } else {
            Err(ParseError::new("Packet is not Icmpv4").into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packets::ip::v4::Ipv4;
    use crate::packets::Ethernet;
    use crate::testils::byte_arrays::{ICMPV4_PACKET, IPV4_UDP_PACKET};
    use crate::Mbuf;

    #[test]
    fn size_of_icmpv4_header() {
        assert_eq!(4, Icmpv4Header::size_of());
    }

    #[capsule::test]
    fn parse_icmpv4_packet() {
        let packet = Mbuf::from_bytes(&ICMPV4_PACKET).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();
        let ipv4 = ethernet.parse::<Ipv4>().unwrap();
        let icmpv4 = ipv4.parse::<Icmpv4<()>>().unwrap();

        assert_eq!(Icmpv4Type::new(0x8), icmpv4.msg_type());
        assert_eq!(0, icmpv4.code());
        assert_eq!(0x2a5c, icmpv4.checksum());
    }

    #[capsule::test]
    fn parse_non_icmpv4_packet() {
        let packet = Mbuf::from_bytes(&IPV4_UDP_PACKET).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();
        let ipv4 = ethernet.parse::<Ipv4>().unwrap();

        assert!(ipv4.parse::<Icmpv4<()>>().is_err());
    }

    #[capsule::test]
    fn compute_checksum() {
        let packet = Mbuf::from_bytes(&ICMPV4_PACKET).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();
        let ipv4 = ethernet.parse::<Ipv4>().unwrap();
        let mut icmpv4 = ipv4.parse::<Icmpv4<()>>().unwrap();

        let expected = icmpv4.checksum();
        // no payload change but force a checksum recompute anyway
        icmpv4.cascade();
        assert_eq!(expected, icmpv4.checksum());
    }

    #[capsule::test]
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

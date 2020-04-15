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

//! Internet Control Message Protocol for IPv6.

mod echo_reply;
mod echo_request;
pub mod ndp;
mod time_exceeded;
mod too_big;

pub use self::echo_reply::*;
pub use self::echo_request::*;
pub use self::time_exceeded::*;
pub use self::too_big::*;

use self::ndp::*;
use crate::packets::ip::v6::Ipv6Packet;
use crate::packets::ip::ProtocolNumbers;
use crate::packets::{checksum, Internal, Packet, PacketBase, ParseError};
use crate::{ensure, SizeOf};
use failure::Fallible;
use std::fmt;
use std::ptr::NonNull;

/// Internet Control Message Protocol v6 packet based on [`IETF RFC 4443`].
///
/// ```
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Type      |     Code      |          Checksum             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// +                         Message Body                          +
/// |                                                               |
/// ```
///
/// - *Type*:          Indicates the type of the message. Its value determines
///                    the format of the remaining data.
///
/// - *Code*:          This field depends on the message type. It is used to
///                    create an additional level of message granularity.
///
/// - *Checksum*:      This field is used to detect data corruption in the
///                    ICMPv6 message and parts of the IPv6 header.
///
/// - *Message Body*:  Varies based on the type field and implemented with
///                    trait [`Icmpv6Payload`]. The packet needs to be first
///                    parsed with the unit `()` payload before the type field
///                    can be read.
///
/// # Example
///
/// ```
/// if ipv6.next_header() == NextHeaders::Icmpv6 {
///     let icmpv6 = ipv6.parse::<Icmpv6<Ipv6, ()>>().unwrap();
///     println!("{}", icmpv6.msg_type());
/// }
/// ```
///
/// [`IETF RFC 4443`]: https://tools.ietf.org/html/rfc4443
/// [`Icmpv6Payload`]: Icmpv6Payload
pub struct Icmpv6<E: Ipv6Packet, P: Icmpv6Payload> {
    envelope: E,
    header: NonNull<Icmpv6Header>,
    payload: NonNull<P>,
    offset: usize,
}

impl<E: Ipv6Packet> fmt::Debug for Icmpv6<E, ()> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("icmpv6")
            .field("type", &format!("{}", self.msg_type()))
            .field("code", &self.code())
            .field("checksum", &format!("0x{:04x}", self.checksum()))
            .field("$offset", &self.offset())
            .field("$len", &self.len())
            .field("$header_len", &self.header_len())
            .finish()
    }
}

impl<E: Ipv6Packet> Icmpv6Packet<E, ()> for Icmpv6<E, ()> {
    #[inline]
    fn header(&self) -> &Icmpv6Header {
        unsafe { self.header.as_ref() }
    }

    #[inline]
    fn header_mut(&mut self) -> &mut Icmpv6Header {
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

impl<E: Ipv6Packet> PacketBase for Icmpv6<E, ()> {
    type Envelope = E;

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
        Icmpv6Header::size_of()
    }

    #[inline]
    unsafe fn clone(&self, internal: Internal) -> Self {
        Icmpv6::<E, ()> {
            envelope: self.envelope.clone(internal),
            header: self.header,
            payload: self.payload,
            offset: self.offset,
        }
    }

    #[inline]
    fn try_parse(envelope: Self::Envelope) -> Fallible<Self> {
        ensure!(
            envelope.next_protocol() == ProtocolNumbers::Icmpv6,
            ParseError::new("not an ICMPv6 packet.")
        );

        let mbuf = envelope.mbuf();
        let offset = envelope.payload_offset();
        let header = mbuf.read_data(offset)?;
        let payload = mbuf.read_data(offset + Icmpv6Header::size_of())?;

        Ok(Icmpv6 {
            envelope,
            header,
            payload,
            offset,
        })
    }

    #[inline]
    fn try_push(
        mut envelope: Self::Envelope,
        _internal: crate::packets::Internal,
    ) -> Fallible<Self> {
        let offset = envelope.payload_offset();
        let mbuf = envelope.mbuf_mut();

        mbuf.extend(offset, Icmpv6Header::size_of() + <()>::size_of())?;
        let header = mbuf.write_data(offset, &Icmpv6Header::default())?;
        let payload = mbuf.write_data(offset + Icmpv6Header::size_of(), &<()>::default())?;

        let mut packet = Icmpv6 {
            envelope,
            header,
            payload,
            offset,
        };

        packet.header_mut().msg_type = <()>::msg_type().0;
        packet
            .envelope_mut0()
            .set_next_header(ProtocolNumbers::Icmpv6);

        Ok(packet)
    }

    #[inline]
    fn fix_invariants(&mut self, _internal: Internal) {
        self.compute_checksum();
    }
}

/// Type of ICMPv6 message.
///
/// A list of supported types is under [`Icmpv6Types`].
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(C, packed)]
pub struct Icmpv6Type(pub u8);

impl Icmpv6Type {
    /// Creates a new ICMPv6 message type.
    pub fn new(value: u8) -> Self {
        Icmpv6Type(value)
    }
}

/// Supported ICMPv6 message types.
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
pub mod Icmpv6Types {
    use super::Icmpv6Type;

    /// Message type for [`Packet Too Big`].
    ///
    /// [`Packet Too Big`]: crate::packets::icmp::v6::PacketTooBig
    pub const PacketTooBig: Icmpv6Type = Icmpv6Type(2);

    /// Message type for [`Time Exceeded`].
    ///
    /// [`Time Exceeded`]: crate::packets::icmp::v6::TimeExceeded
    pub const TimeExceeded: Icmpv6Type = Icmpv6Type(3);

    /// Message type for [`Echo Request`].
    ///
    /// [`Echo Request`]: crate::packets::icmp::v6::EchoRequest
    pub const EchoRequest: Icmpv6Type = Icmpv6Type(128);

    /// Message type for [`Echo Reply`].
    ///
    /// [`Echo Reply`]: crate::packets::icmp::v6::EchoReply
    pub const EchoReply: Icmpv6Type = Icmpv6Type(129);

    // NDP types
    /// Message type for [`Router Solicitation`].
    ///
    /// [`Router Solicitation`]: crate::packets::icmp::v6::RouterSolicitation
    pub const RouterSolicitation: Icmpv6Type = Icmpv6Type(133);

    /// Message type for [`Router Advertisement`].
    ///
    /// [`Router Advertisement`]: crate::packets::icmp::v6::RouterAdvertisement
    pub const RouterAdvertisement: Icmpv6Type = Icmpv6Type(134);

    /// Message type for [`Neighbor Solicitation`].
    ///
    /// [`Neighbor Solicitation`]: crate::packets::icmp::v6::NeighborSolicitation
    pub const NeighborSolicitation: Icmpv6Type = Icmpv6Type(135);

    /// Message type for [`Neighbor Advertisement`].
    ///
    /// [`Neighbor Advertisement`]: crate::packets::icmp::v6::NeighborAdvertisement
    pub const NeighborAdvertisement: Icmpv6Type = Icmpv6Type(136);

    /// Message type for `Redirect`.
    pub const Redirect: Icmpv6Type = Icmpv6Type(137);
}

impl fmt::Display for Icmpv6Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match *self {
                Icmpv6Types::PacketTooBig => "Packet Too Big".to_string(),
                Icmpv6Types::TimeExceeded => "Time Exceeded".to_string(),
                Icmpv6Types::EchoRequest => "Echo Request".to_string(),
                Icmpv6Types::EchoReply => "Echo Reply".to_string(),
                Icmpv6Types::RouterSolicitation => "Router Solicitation".to_string(),
                Icmpv6Types::RouterAdvertisement => "Router Advertisement".to_string(),
                Icmpv6Types::NeighborSolicitation => "Neighbor Solicitation".to_string(),
                Icmpv6Types::NeighborAdvertisement => "Neighbor Advertisement".to_string(),
                Icmpv6Types::Redirect => "Redirect".to_string(),
                _ => format!("{}", self.0),
            }
        )
    }
}

/// ICMPv6 header.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Default, SizeOf)]
#[repr(C, packed)]
pub struct Icmpv6Header {
    msg_type: u8,
    code: u8,
    checksum: u16,
}

/// ICMPv6 packet payload.
///
/// The ICMPv6 packet may contain a variable length payload. This
/// is only the fixed portion. The variable length portion has to
/// be parsed separately.
pub trait Icmpv6Payload: Clone + Default + SizeOf {
    /// Returns the ICMPv6 message type that corresponds to the payload.
    fn msg_type() -> Icmpv6Type;
}

/// ICMPv6 unit payload `()`.
impl Icmpv6Payload for () {
    fn msg_type() -> Icmpv6Type {
        // Unit payload does not have a type
        unreachable!();
    }
}

/// A trait for common behaviors shared by ICMPv6 packets.
///
/// ## Derivable
///
/// The `Icmpv6Packet` trait can be used with `#[derive]` on Icmpv6 payloads,
/// which also derives the implementation for the [`Packet`] trait.
///
/// ```
/// #[derive(Icmpv6Packet)]
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
pub trait Icmpv6Packet<E: Ipv6Packet, P: Icmpv6Payload>: Packet<Envelope = E> {
    /// Returns a reference to the header.
    fn header(&self) -> &Icmpv6Header;

    /// Returns a mutable reference to the header.
    fn header_mut(&mut self) -> &mut Icmpv6Header;

    /// Returns a reference to the fixed payload.
    fn payload(&self) -> &P;

    /// Returns a mutable reference to the fixed payload.
    fn payload_mut(&mut self) -> &mut P;

    /// Returns the message type.
    #[inline]
    fn msg_type(&self) -> Icmpv6Type {
        Icmpv6Type::new(self.header().msg_type)
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
            let pseudo_header_sum = self
                .envelope()
                .pseudo_header(data.len() as u16, ProtocolNumbers::Icmpv6)
                .sum();
            let checksum = checksum::compute(pseudo_header_sum, data);
            self.header_mut().checksum = u16::to_be(checksum);
        } else {
            // we are reading till the end of buffer, should never run out
            unreachable!()
        }
    }
}

/// An [`ICMPv6`] message with parsed payload.
///
/// A list of supported types is under [`Icmpv6Types`].
///
/// [`ICMPv6`]: Icmpv6
#[derive(Debug)]
pub enum Icmpv6Message<E: Ipv6Packet> {
    /// EchoRequest message.
    EchoRequest(Icmpv6<E, EchoRequest>),
    /// EchoReply message.
    EchoReply(Icmpv6<E, EchoReply>),
    /// TimeExceeded message.
    TimeExceeded(Icmpv6<E, TimeExceeded>),
    /// PacketTooBig message.
    PacketTooBig(Icmpv6<E, PacketTooBig>),
    /// NDP Neighbor Advertisement message.
    NeighborAdvertisement(Icmpv6<E, NeighborAdvertisement>),
    /// NDP Neighbor Solicitation message.
    NeighborSolicitation(Icmpv6<E, NeighborSolicitation>),
    /// NDP Router Advertisement message.
    RouterAdvertisement(Icmpv6<E, RouterAdvertisement>),
    /// NDP Router Solicitation message.
    RouterSolicitation(Icmpv6<E, RouterSolicitation>),
    /// An ICMPv6 message with undefined payload.
    Undefined(Icmpv6<E, ()>),
}

/// Trait for parsing IPv6 packet payload as an ICMPv6 message.
pub trait Icmpv6Parse {
    /// The outer packet type that encapsulates the ICMPv6 packet. It can be
    /// either [`IPv6`] or an extension header.
    ///
    /// [`IPv6`]: crate::packets::ip::v6::Ipv6
    type Envelope: Ipv6Packet;

    /// Parses the IPv6 packet payload as an ICMPv6 message. Automatically
    /// detects the ICMP message type and parses the payload as that type. If
    /// the message type is not supported, then `Undefined` is returned.
    ///
    /// # Example
    ///
    /// ```
    /// match ipv6.parse_icmpv6()? {
    ///     Icmpv6Message::RouterAdvertisement(advert) => {
    ///         advert.set_router_lifetime(0);
    ///     },
    ///     Icmpv6Message::Undefined(icmpv6) => {
    ///         println!("undefined");
    ///     }
    /// }
    /// ```
    fn parse_icmpv6(self) -> Fallible<Icmpv6Message<Self::Envelope>>;
}

impl<T: Ipv6Packet> Icmpv6Parse for T {
    type Envelope = T;

    fn parse_icmpv6(self) -> Fallible<Icmpv6Message<Self::Envelope>> {
        if self.next_protocol() == ProtocolNumbers::Icmpv6 {
            let icmpv6 = self.parse::<Icmpv6<Self::Envelope, ()>>()?;
            match icmpv6.msg_type() {
                Icmpv6Types::EchoRequest => {
                    let packet = icmpv6
                        .deparse()
                        .parse::<Icmpv6<Self::Envelope, EchoRequest>>()?;
                    Ok(Icmpv6Message::EchoRequest(packet))
                }
                Icmpv6Types::EchoReply => {
                    let packet = icmpv6
                        .deparse()
                        .parse::<Icmpv6<Self::Envelope, EchoReply>>()?;
                    Ok(Icmpv6Message::EchoReply(packet))
                }
                Icmpv6Types::TimeExceeded => {
                    let packet = icmpv6
                        .deparse()
                        .parse::<Icmpv6<Self::Envelope, TimeExceeded>>()?;
                    Ok(Icmpv6Message::TimeExceeded(packet))
                }
                Icmpv6Types::PacketTooBig => {
                    let packet = icmpv6
                        .deparse()
                        .parse::<Icmpv6<Self::Envelope, PacketTooBig>>()?;
                    Ok(Icmpv6Message::PacketTooBig(packet))
                }
                Icmpv6Types::NeighborAdvertisement => {
                    let packet = icmpv6
                        .deparse()
                        .parse::<Icmpv6<Self::Envelope, NeighborAdvertisement>>()?;
                    Ok(Icmpv6Message::NeighborAdvertisement(packet))
                }
                Icmpv6Types::NeighborSolicitation => {
                    let packet = icmpv6
                        .deparse()
                        .parse::<Icmpv6<Self::Envelope, NeighborSolicitation>>()?;
                    Ok(Icmpv6Message::NeighborSolicitation(packet))
                }
                Icmpv6Types::RouterAdvertisement => {
                    let packet = icmpv6
                        .deparse()
                        .parse::<Icmpv6<Self::Envelope, RouterAdvertisement>>()?;
                    Ok(Icmpv6Message::RouterAdvertisement(packet))
                }
                Icmpv6Types::RouterSolicitation => {
                    let packet = icmpv6
                        .deparse()
                        .parse::<Icmpv6<Self::Envelope, RouterSolicitation>>()?;
                    Ok(Icmpv6Message::RouterSolicitation(packet))
                }
                _ => Ok(Icmpv6Message::Undefined(icmpv6)),
            }
        } else {
            Err(ParseError::new("Packet is not ICMPv6").into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packets::ip::v6::Ipv6;
    use crate::packets::Ethernet;
    use crate::testils::byte_arrays::{ICMPV6_PACKET, IPV6_TCP_PACKET, ROUTER_ADVERT_PACKET};
    use crate::Mbuf;

    #[test]
    fn size_of_icmpv6_header() {
        assert_eq!(4, Icmpv6Header::size_of());
    }

    #[capsule::test]
    fn parse_icmpv6_packet() {
        let packet = Mbuf::from_bytes(&ICMPV6_PACKET).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();
        let ipv6 = ethernet.parse::<Ipv6>().unwrap();
        let icmpv6 = ipv6.parse::<Icmpv6<Ipv6, ()>>().unwrap();

        assert_eq!(Icmpv6Type::new(0xFF), icmpv6.msg_type());
        assert_eq!(0, icmpv6.code());
        assert_eq!(0x01f0, icmpv6.checksum());
    }

    #[capsule::test]
    fn parse_non_icmpv6_packet() {
        let packet = Mbuf::from_bytes(&IPV6_TCP_PACKET).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();
        let ipv6 = ethernet.parse::<Ipv6>().unwrap();

        assert!(ipv6.parse::<Icmpv6<Ipv6, ()>>().is_err());
    }

    #[capsule::test]
    fn compute_checksum() {
        let packet = Mbuf::from_bytes(&ROUTER_ADVERT_PACKET).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();
        let ipv6 = ethernet.parse::<Ipv6>().unwrap();
        let mut icmpv6 = ipv6.parse::<Icmpv6<Ipv6, ()>>().unwrap();

        let expected = icmpv6.checksum();
        // no payload change but force a checksum recompute anyway
        icmpv6.cascade();
        assert_eq!(expected, icmpv6.checksum());
    }

    #[capsule::test]
    fn matchable_icmpv6_packets() {
        let packet = Mbuf::from_bytes(&ICMPV6_PACKET).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();
        let ipv6 = ethernet.parse::<Ipv6>().unwrap();
        if let Ok(Icmpv6Message::Undefined(icmpv6)) = ipv6.parse_icmpv6() {
            assert_eq!(Icmpv6Type::new(0xFF), icmpv6.msg_type());
        } else {
            panic!("bad packet");
        }
    }
}

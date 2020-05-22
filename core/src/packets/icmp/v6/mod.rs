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
pub use capsule_macros::Icmpv6Packet;

use crate::packets::ip::v6::Ipv6Packet;
use crate::packets::ip::ProtocolNumbers;
use crate::packets::types::u16be;
use crate::packets::{checksum, Internal, Packet, ParseError};
use crate::{ensure, SizeOf};
use failure::{Fail, Fallible};
use std::fmt;
use std::ptr::NonNull;

/// Internet Control Message Protocol v6 packet based on [IETF RFC 4443].
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
/// - *Message Body*:  Varies based on the type field. Each specific type
///                    is implemented with trait [`Icmpv6Message`].
///
/// # Example
///
/// ```
/// if ipv6.next_header() == NextHeaders::Icmpv6 {
///     let icmpv6 = ipv6.parse::<Icmpv6<Ipv6>>().unwrap();
///     println!("{}", icmpv6.msg_type());
/// }
/// ```
///
/// [IETF RFC 4443]: https://tools.ietf.org/html/rfc4443
/// [`Icmpv6Message`]: Icmpv6Message
pub struct Icmpv6<E: Ipv6Packet> {
    envelope: E,
    header: NonNull<Icmpv6Header>,
    offset: usize,
}

impl<E: Ipv6Packet> Icmpv6<E> {
    #[inline]
    fn header(&self) -> &Icmpv6Header {
        unsafe { self.header.as_ref() }
    }

    #[inline]
    fn header_mut(&mut self) -> &mut Icmpv6Header {
        unsafe { self.header.as_mut() }
    }

    /// Returns the message type.
    #[inline]
    pub fn msg_type(&self) -> Icmpv6Type {
        Icmpv6Type::new(self.header().msg_type)
    }

    /// Returns the code.
    #[inline]
    pub fn code(&self) -> u8 {
        self.header().code
    }

    /// Sets the code.
    #[inline]
    pub fn set_code(&mut self, code: u8) {
        self.header_mut().code = code
    }

    /// Returns the checksum.
    #[inline]
    pub fn checksum(&self) -> u16 {
        self.header().checksum.into()
    }

    /// Computes the checksum.
    #[inline]
    pub fn compute_checksum(&mut self) {
        self.header_mut().checksum = u16be::default();

        if let Ok(data) = self.mbuf().read_data_slice(self.offset(), self.len()) {
            let data = unsafe { data.as_ref() };
            let pseudo_header_sum = self
                .envelope()
                .pseudo_header(data.len() as u16, ProtocolNumbers::Icmpv6)
                .sum();
            let checksum = checksum::compute(pseudo_header_sum, data);
            self.header_mut().checksum = checksum.into();
        } else {
            // we are reading till the end of buffer, should never run out
            unreachable!()
        }
    }

    /// Casts the ICMPv6 packet to a message of type `T`.
    ///
    /// Returns an error if the message type in the packet header does not
    /// match the assigned message type for `T`.
    #[inline]
    pub fn downcast<T: Icmpv6Message<Envelope = E>>(self) -> Fallible<T> {
        ensure!(
            self.msg_type() == T::msg_type(),
            ParseError::new(&format!("The ICMPv6 packet is not {}.", T::msg_type()))
        );

        T::try_parse(self, Internal(()))
    }
}

impl<E: Ipv6Packet> fmt::Debug for Icmpv6<E> {
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

/// Error when trying to push a generic ICMPv6 header without a message body.
#[derive(Debug, Fail)]
#[fail(display = "Cannot push a generic ICMPv6 header without a message body.")]
pub struct NoIcmpv6MessageBody;

impl<E: Ipv6Packet> Packet for Icmpv6<E> {
    /// The preceding type for an ICMPv6 packet must be either an [IPv6]
    /// packet or any IPv6 extension packets.
    ///
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
        Icmpv6Header::size_of()
    }

    #[inline]
    unsafe fn clone(&self, internal: Internal) -> Self {
        Icmpv6 {
            envelope: self.envelope.clone(internal),
            header: self.header,
            offset: self.offset,
        }
    }

    /// Parses the envelope's payload as an ICMPv6 packet.
    ///
    /// [`next_header`] must be set to [`ProtocolNumbers::Icmpv6`].
    /// Otherwise, a parsing error is returned.
    ///
    /// [`next_header`]: crate::packets::ip::v6::Ipv6Packet::next_header
    /// [`ProtocolNumbers::Icmpv6`]: crate::packets::ip::ProtocolNumbers::Icmpv6
    #[inline]
    fn try_parse(envelope: Self::Envelope, _internal: Internal) -> Fallible<Self> {
        ensure!(
            envelope.next_protocol() == ProtocolNumbers::Icmpv6,
            ParseError::new("not an ICMPv6 packet.")
        );

        let mbuf = envelope.mbuf();
        let offset = envelope.payload_offset();
        let header = mbuf.read_data(offset)?;

        Ok(Icmpv6 {
            envelope,
            header,
            offset,
        })
    }

    /// Cannot push a generic ICMPv6 header without a message body. This
    /// will always return [`NoIcmpv6MessageBody`]. Instead, push a specific
    /// message type like [`EchoRequest`], which includes the header and the
    /// message body.
    ///
    /// [`NoIcmpv6MessageBody`]: NoIcmpv6MessageBody
    /// [`EchoRequest`]: EchoRequest
    #[inline]
    fn try_push(_envelope: Self::Envelope, _internal: crate::packets::Internal) -> Fallible<Self> {
        Err(NoIcmpv6MessageBody.into())
    }

    #[inline]
    fn deparse(self) -> Self::Envelope {
        self.envelope
    }

    /// Reconciles the derivable header fields against the changes made to
    /// the packet.
    ///
    /// * [`checksum`] is computed based on the [`pseudo-header`] and the
    /// full packet.
    ///
    /// [`checksum`]: Icmpv6::checksum
    /// [`pseudo-header`]: crate::packets::checksum::PseudoHeader
    #[inline]
    fn reconcile(&mut self) {
        self.compute_checksum();
    }
}

/// [IANA] assigned ICMPv6 message types.
///
/// A list of supported types is under [`Icmpv6Types`].
///
/// [IANA]: https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml#icmpv6-parameters-2
/// [`Icmpv6Types`]: Icmpv6Types
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

    /// Message type for [Packet Too Big].
    ///
    /// [Packet Too Big]: crate::packets::icmp::v6::PacketTooBig
    pub const PacketTooBig: Icmpv6Type = Icmpv6Type(2);

    /// Message type for [Time Exceeded].
    ///
    /// [Time Exceeded]: crate::packets::icmp::v6::TimeExceeded
    pub const TimeExceeded: Icmpv6Type = Icmpv6Type(3);

    /// Message type for [Echo Request].
    ///
    /// [Echo Request]: crate::packets::icmp::v6::EchoRequest
    pub const EchoRequest: Icmpv6Type = Icmpv6Type(128);

    /// Message type for [Echo Reply].
    ///
    /// [Echo Reply]: crate::packets::icmp::v6::EchoReply
    pub const EchoReply: Icmpv6Type = Icmpv6Type(129);

    /// Message type for [Router Solicitation].
    ///
    /// [Router Solicitation]: crate::packets::icmp::v6::ndp::RouterSolicitation
    pub const RouterSolicitation: Icmpv6Type = Icmpv6Type(133);

    /// Message type for [Router Advertisement].
    ///
    /// [Router Advertisement]: crate::packets::icmp::v6::ndp::RouterAdvertisement
    pub const RouterAdvertisement: Icmpv6Type = Icmpv6Type(134);

    /// Message type for [Neighbor Solicitation].
    ///
    /// [Neighbor Solicitation]: crate::packets::icmp::v6::ndp::NeighborSolicitation
    pub const NeighborSolicitation: Icmpv6Type = Icmpv6Type(135);

    /// Message type for [Neighbor Advertisement].
    ///
    /// [Neighbor Advertisement]: crate::packets::icmp::v6::ndp::NeighborAdvertisement
    pub const NeighborAdvertisement: Icmpv6Type = Icmpv6Type(136);

    /// Message type for [Redirect].
    ///
    /// [Redirect]: crate::packets::icmp::v6::ndp::Redirect
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
    checksum: u16be,
}

/// A trait all ICMPv6 messages must implement.
///
/// The trait is used for conversion between the generic [ICMPv6] packet
/// and the more specific messages. Implementors can use this trait to
/// add custom message types. This trait should not be imported and used
/// directly. Use either [`Packet`] or [`Icmpv6Packet`] instead.
///
/// # Example
///
/// ```
/// let icmpv6 = ipv6.parse::<Icmpv6<Ipv6>>()?;
/// let reply = icmpv6.downcast::<EchoReply<Ipv6>>()?;
/// ```
///
/// [ICMPv6]: Icmpv6
/// [`Packet`]: Packet
/// [`Icmpv6Packet`]: Icmpv6Packet
pub trait Icmpv6Message {
    /// The preceding packet type that encapsulates this message.
    type Envelope: Ipv6Packet;

    /// Returns the assigned message type.
    fn msg_type() -> Icmpv6Type;

    /// Returns a reference to the generic ICMPv6 packet.
    fn icmp(&self) -> &Icmpv6<Self::Envelope>;

    /// Returns a mutable reference to the generic ICMPv6 packet.
    fn icmp_mut(&mut self) -> &mut Icmpv6<Self::Envelope>;

    /// Converts the message back to the generic ICMPv6 packet.
    fn into_icmp(self) -> Icmpv6<Self::Envelope>;

    /// Returns a copy of the message.
    ///
    /// # Safety
    ///
    /// This function cannot be invoked directly. It is internally used by
    /// [`Packet::clone`].
    ///
    /// [`Packet::clone`]: Packet::clone
    unsafe fn clone(&self, internal: Internal) -> Self;

    /// Parses the ICMPv6 packet's payload as this message type.
    ///
    /// # Remarks
    ///
    /// This function cannot be invoked directly. It is internally used by
    /// [`Icmpv6::downcast`]. `downcast` verifies that the [`msg_type`] in
    /// the packet matches the assigned number before invoking this function.
    ///
    /// [`Icmpv6::downcast`]: Icmpv6::downcast
    /// [`msg_type`]: Icmpv6::msg_type
    fn try_parse(icmp: Icmpv6<Self::Envelope>, internal: Internal) -> Fallible<Self>
    where
        Self: Sized;

    /// Prepends a new ICMPv6 message to the beginning of the envelope's
    /// payload.
    ///
    /// [`msg_type`] is preset to the fixed type number of the message. When
    /// the packet is inserted into an envelope with an existing payload, the
    /// original payload becomes part of the ICMPv6 message.
    ///
    /// # Remarks
    ///
    /// This function cannot be invoked directly. It is internally used by
    /// [`Packet::push`].
    ///
    /// [`msg_type`]: Icmpv6::msg_type
    /// [`Packet::push`]: Packet::push
    fn try_push(icmp: Icmpv6<Self::Envelope>, internal: Internal) -> Fallible<Self>
    where
        Self: Sized;

    /// Reconciles the derivable header fields against the changes made to
    /// the packet. The default implementation computes the [`checksum`]
    /// based on the pseudo-header and the ICMPv6 message.
    ///
    /// [`checksum`]: Icmpv6::checksum
    #[inline]
    fn reconcile(&mut self) {
        self.icmp_mut().compute_checksum()
    }
}

/// A trait for common ICMPv6 accessors.
///
/// # Derivable
///
/// This trait should be used with `#[derive]`. `#[derive]` provides
/// implementations for both `Icmpv6Packet` trait and [`Packet`] trait.
/// Those implementations depend on functions defined in [`Icmpv6Message`]
/// trait, therefore the struct must manually implement `Icmpv6Message`.
///
/// ```
/// #[derive(Icmpv6Packet)]
/// pub struct EchoReply {
///     ...
/// }
///
/// impl<E: Ipv6Packet> Icmpv6Message for EchoReply<E> {
///     ...
/// }
/// ```
///
/// [`Icmpv6Message`]: Icmpv6Message
/// [`Packet`]: Packet
pub trait Icmpv6Packet {
    /// Returns the message type.
    fn msg_type(&self) -> Icmpv6Type;

    /// Returns the code.
    fn code(&self) -> u8;

    /// Sets the code.
    ///
    /// # Remarks
    ///
    /// Not all code values are applicable to all message types. This setter
    /// does not perform any validation. It's the caller's responsibility to
    /// ensure that the value provided follows the spec.
    fn set_code(&mut self, code: u8);

    /// Returns the checksum.
    fn checksum(&self) -> u16;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packets::icmp::v6::ndp::RouterAdvertisement;
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
        let packet = Mbuf::from_bytes(&ROUTER_ADVERT_PACKET).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();
        let ipv6 = ethernet.parse::<Ipv6>().unwrap();
        let icmpv6 = ipv6.parse::<Icmpv6<Ipv6>>().unwrap();

        // parses the generic header
        assert_eq!(Icmpv6Types::RouterAdvertisement, icmpv6.msg_type());
        assert_eq!(0, icmpv6.code());
        assert_eq!(0xf50c, icmpv6.checksum());

        // downcasts to specific message
        let advert = icmpv6.downcast::<RouterAdvertisement<Ipv6>>().unwrap();
        assert_eq!(Icmpv6Types::RouterAdvertisement, advert.msg_type());
        assert_eq!(0, advert.code());
        assert_eq!(0xf50c, advert.checksum());
        assert_eq!(64, advert.current_hop_limit());
        assert!(!advert.managed_addr_cfg());
        assert!(advert.other_cfg());
        assert_eq!(3600, advert.router_lifetime());
        assert_eq!(0, advert.reachable_time());
        assert_eq!(0, advert.retrans_timer());

        // also can one-step parse
        let ipv6 = advert.deparse();
        assert!(ipv6.parse::<RouterAdvertisement<Ipv6>>().is_ok());
    }

    #[capsule::test]
    fn parse_wrong_icmpv6_type() {
        let packet = Mbuf::from_bytes(&ICMPV6_PACKET).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();
        let ipv6 = ethernet.parse::<Ipv6>().unwrap();
        let icmpv6 = ipv6.parse::<Icmpv6<Ipv6>>().unwrap();

        assert!(icmpv6.downcast::<EchoReply<Ipv6>>().is_err());
    }

    #[capsule::test]
    fn parse_non_icmpv6_packet() {
        let packet = Mbuf::from_bytes(&IPV6_TCP_PACKET).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();
        let ipv6 = ethernet.parse::<Ipv6>().unwrap();

        assert!(ipv6.parse::<Icmpv6<Ipv6>>().is_err());
    }

    #[capsule::test]
    fn compute_checksum() {
        let packet = Mbuf::from_bytes(&ROUTER_ADVERT_PACKET).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();
        let ipv6 = ethernet.parse::<Ipv6>().unwrap();
        let mut icmpv6 = ipv6.parse::<Icmpv6<Ipv6>>().unwrap();

        let expected = icmpv6.checksum();
        // no payload change but force a checksum recompute anyway
        icmpv6.reconcile_all();
        assert_eq!(expected, icmpv6.checksum());
    }

    #[capsule::test]
    fn push_icmpv6_header_without_body() {
        let packet = Mbuf::new().unwrap();
        let ethernet = packet.push::<Ethernet>().unwrap();
        let ipv6 = ethernet.push::<Ipv6>().unwrap();

        assert!(ipv6.push::<Icmpv6<Ipv6>>().is_err());
    }
}

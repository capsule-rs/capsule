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
mod redirect;
mod time_exceeded;

pub use self::echo_reply::*;
pub use self::echo_request::*;
pub use self::redirect::*;
pub use self::time_exceeded::*;
pub use capsule_macros::Icmpv4Packet;

use crate::packets::ip::v4::Ipv4;
use crate::packets::ip::ProtocolNumbers;
use crate::packets::types::u16be;
use crate::packets::{checksum, Internal, Packet, ParseError};
use crate::{ensure, SizeOf};
use failure::{Fail, Fallible};
use std::fmt;
use std::ptr::NonNull;

/// Internet Control Message Protocol v4 packet based on [IETF RFC 792].
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
/// - *Message Body*:  Varies based on the type field. Each specific type
///                    is implemented with trait [`Icmpv4Message`].
///
/// # Example
///
/// ```
/// if ipv4.protocol() == ProtocolNumbers::Icmpv4 {
///     let icmpv4 = ipv4.parse::<Icmpv4>()?;
///     println!("{}", icmpv4.msg_type());
/// }
/// ```
///
/// [IETF RFC 792]: https://tools.ietf.org/html/rfc792
/// [`Icmpv4Message`]: Icmpv4Message
pub struct Icmpv4 {
    envelope: Ipv4,
    header: NonNull<Icmpv4Header>,
    offset: usize,
}

impl Icmpv4 {
    #[inline]
    fn header(&self) -> &Icmpv4Header {
        unsafe { self.header.as_ref() }
    }

    #[inline]
    fn header_mut(&mut self) -> &mut Icmpv4Header {
        unsafe { self.header.as_mut() }
    }

    /// Returns the message type.
    #[inline]
    pub fn msg_type(&self) -> Icmpv4Type {
        Icmpv4Type::new(self.header().msg_type)
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
            let checksum = checksum::compute(0, data);
            self.header_mut().checksum = checksum.into();
        } else {
            // we are reading till the end of buffer, should never run out
            unreachable!()
        }
    }

    /// Casts the ICMPv4 packet to a message of type `T`.
    ///
    /// Returns an error if the message type in the packet header does not
    /// match the assigned message type for `T`.
    #[inline]
    pub fn downcast<T: Icmpv4Message>(self) -> Fallible<T> {
        ensure!(
            self.msg_type() == T::msg_type(),
            ParseError::new(&format!("The ICMPv4 packet is not {}.", T::msg_type()))
        );

        T::try_parse(self, Internal(()))
    }
}

impl fmt::Debug for Icmpv4 {
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

/// Error when trying to push a generic ICMPv4 header without a message body.
#[derive(Debug, Fail)]
#[fail(display = "Cannot push a generic ICMPv4 header without a message body.")]
pub struct NoIcmpv4MessageBody;

impl Packet for Icmpv4 {
    /// The preceding type for ICMPv4 packet must be IPv4.
    type Envelope = Ipv4;

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
        Icmpv4Header::size_of()
    }

    #[inline]
    unsafe fn clone(&self, internal: Internal) -> Self {
        Icmpv4 {
            envelope: self.envelope.clone(internal),
            header: self.header,
            offset: self.offset,
        }
    }

    /// Parses the envelope's payload as an ICMPv4 packet.
    ///
    /// [`Ipv4::protocol`] must be set to [`ProtocolNumbers::Icmpv4`].
    /// Otherwise, a parsing error is returned.
    ///
    /// [`Ipv4::protocol`]: crate::packets::ip::v4::Ipv4::protocol
    /// [`ProtocolNumbers::Icmpv4`]: crate::packets::ip::ProtocolNumbers::Icmpv4
    #[inline]
    fn try_parse(envelope: Self::Envelope, _internal: Internal) -> Fallible<Self> {
        ensure!(
            envelope.protocol() == ProtocolNumbers::Icmpv4,
            ParseError::new("not an ICMPv4 packet.")
        );

        let mbuf = envelope.mbuf();
        let offset = envelope.payload_offset();
        let header = mbuf.read_data(offset)?;

        Ok(Icmpv4 {
            envelope,
            header,
            offset,
        })
    }

    /// Cannot push a generic ICMPv4 header without a message body. This
    /// will always return [`NoIcmpv4MessageBody`]. Instead, push a specific
    /// message type like [`EchoRequest`], which includes the header and
    /// the message body.
    ///
    /// [`NoIcmpv4MessageBody`]: NoIcmpv4MessageBody
    /// [`EchoRequest`]: EchoRequest
    #[inline]
    fn try_push(_envelope: Self::Envelope, _internal: Internal) -> Fallible<Self> {
        Err(NoIcmpv4MessageBody.into())
    }

    #[inline]
    fn deparse(self) -> Self::Envelope {
        self.envelope
    }

    /// Reconciles the derivable header fields against the changes made to
    /// the packet.
    ///
    /// * [`checksum`] is computed based on the header and the message body.
    ///
    /// [`checksum`]: Icmpv4::checksum
    #[inline]
    fn reconcile(&mut self) {
        self.compute_checksum();
    }
}

/// [IANA] assigned ICMPv4 message types.
///
/// A list of supported types is under [`Icmpv4Types`].
///
/// [IANA]: https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml
/// [`Icmpv4Types`]: Icmpv4Types
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

    /// Message type for [Echo Request].
    ///
    /// [Echo Request]: crate::packets::icmp::v4::EchoRequest
    pub const EchoRequest: Icmpv4Type = Icmpv4Type(8);

    /// Message type for [Echo Reply].
    ///
    /// [Echo Reply]: crate::packets::icmp::v4::EchoReply
    pub const EchoReply: Icmpv4Type = Icmpv4Type(0);

    /// Message type for [Time Exceeded].
    ///
    /// [Time Exceeded]: crate::packets::icmp::v4::TimeExceeded
    pub const TimeExceeded: Icmpv4Type = Icmpv4Type(11);

    /// Message type for [Redirect].
    ///
    /// [Redirect]: crate::packets::icmp::v4::Redirect
    pub const Redirect: Icmpv4Type = Icmpv4Type(5);
}

impl fmt::Display for Icmpv4Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match *self {
                Icmpv4Types::EchoRequest => "Echo Request".to_string(),
                Icmpv4Types::EchoReply => "Echo Reply".to_string(),
                Icmpv4Types::TimeExceeded => "Time Exceeded".to_string(),
                Icmpv4Types::Redirect => "Redirect".to_string(),
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
    checksum: u16be,
}

/// A trait all ICMPv4 messages must implement.
///
/// The trait is used for conversion between the generic [ICMPv4] packet
/// and the more specific messages. Implementors can use this trait to
/// add custom message types. This trait should not be imported and used
/// directly. Use either [`Packet`] or [`Icmpv4Packet`] instead.
///
/// # Example
///
/// ```
/// let icmpv4 = ipv4.parse::<Icmpv4>()?;
/// let reply = icmpv4.downcast::<EchoReply>()?;
/// ```
///
/// [ICMPv4]: Icmpv4
/// [`Packet`]: Packet
/// [`Icmpv4Packet`]: Icmpv4Packet
pub trait Icmpv4Message {
    /// Returns the assigned message type.
    fn msg_type() -> Icmpv4Type;

    /// Returns a reference to the generic ICMPv4 packet.
    fn icmp(&self) -> &Icmpv4;

    /// Returns a mutable reference to the generic ICMPv4 packet.
    fn icmp_mut(&mut self) -> &mut Icmpv4;

    /// Converts the message back to the generic ICMPv4 packet.
    fn into_icmp(self) -> Icmpv4;

    /// Returns a copy of the message.
    ///
    /// # Safety
    ///
    /// This function cannot be invoked directly. It is internally used by
    /// [`Packet::clone`].
    ///
    /// [`Packet::clone`]: Packet::clone
    unsafe fn clone(&self, internal: Internal) -> Self;

    /// Parses the ICMPv4 packet's payload as this message type.
    ///
    /// # Remarks
    ///
    /// This function cannot be invoked directly. It is internally used by
    /// [`Icmpv4::downcast`]. `downcast` verifies that the [`msg_type`] in
    /// the packet matches the assigned number before invoking this function.
    ///
    /// [`Icmpv4::downcast`]: Icmpv4::downcast
    /// [`msg_type`]: Icmpv4::msg_type
    fn try_parse(icmp: Icmpv4, internal: Internal) -> Fallible<Self>
    where
        Self: Sized;

    /// Prepends a new ICMPv4 message to the beginning of the envelope's
    /// payload.
    ///
    /// [`msg_type`] is preset to the fixed type number of the message. When
    /// the packet is inserted into an envelope with an existing payload, the
    /// original payload becomes part of the ICMPv4 message.
    ///
    /// # Remarks
    ///
    /// This function cannot be invoked directly. It is internally used by
    /// [`Packet::push`].
    ///
    /// [`msg_type`]: Icmpv4::msg_type
    /// [`Packet::push`]: Packet::push
    fn try_push(icmp: Icmpv4, internal: Internal) -> Fallible<Self>
    where
        Self: Sized;

    /// Reconciles the derivable header fields against the changes made to
    /// the packet. The default implementation computes the [`checksum`]
    /// based on the ICMPv4 header and message body.
    ///
    /// [`checksum`]: Icmpv4::checksum
    #[inline]
    fn reconcile(&mut self) {
        self.icmp_mut().compute_checksum()
    }
}

/// A trait for common ICMPv4 accessors.
///
/// # Derivable
///
/// This trait should be used with `#[derive]`. `#[derive]` provides
/// implementations for both `Icmpv4Packet` trait and [`Packet`] trait.
/// Those implementations depend on functions defined in [`Icmpv4Message`]
/// trait, therefore the struct must manually implement `Icmpv4Message`.
///
/// ```
/// #[derive(Icmpv4Packet)]
/// pub struct EchoReply {
///     ...
/// }
///
/// impl Icmpv4Message for EchoReply {
///     ...
/// }
/// ```
///
/// [`Icmpv4Message`]: Icmpv4Message
/// [`Packet`]: Packet
pub trait Icmpv4Packet {
    /// Returns the message type.
    fn msg_type(&self) -> Icmpv4Type;

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
        let icmpv4 = ipv4.parse::<Icmpv4>().unwrap();

        // parses the generic header
        assert_eq!(Icmpv4Types::EchoRequest, icmpv4.msg_type());
        assert_eq!(0, icmpv4.code());
        assert_eq!(0x2a5c, icmpv4.checksum());

        // downcasts to specific message
        let echo = icmpv4.downcast::<EchoRequest>().unwrap();
        assert_eq!(Icmpv4Types::EchoRequest, echo.msg_type());
        assert_eq!(0, echo.code());
        assert_eq!(0x2a5c, echo.checksum());
        assert_eq!(0x0200, echo.identifier());
        assert_eq!(0x2100, echo.seq_no());

        // also can one-step parse
        let ipv4 = echo.deparse();
        assert!(ipv4.parse::<EchoRequest>().is_ok());
    }

    #[capsule::test]
    fn parse_wrong_icmpv4_type() {
        let packet = Mbuf::from_bytes(&ICMPV4_PACKET).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();
        let ipv4 = ethernet.parse::<Ipv4>().unwrap();
        let icmpv4 = ipv4.parse::<Icmpv4>().unwrap();

        assert!(icmpv4.downcast::<EchoReply>().is_err());
    }

    #[capsule::test]
    fn parse_non_icmpv4_packet() {
        let packet = Mbuf::from_bytes(&IPV4_UDP_PACKET).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();
        let ipv4 = ethernet.parse::<Ipv4>().unwrap();

        assert!(ipv4.parse::<Icmpv4>().is_err());
    }

    #[capsule::test]
    fn compute_checksum() {
        let packet = Mbuf::from_bytes(&ICMPV4_PACKET).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();
        let ipv4 = ethernet.parse::<Ipv4>().unwrap();
        let mut icmpv4 = ipv4.parse::<Icmpv4>().unwrap();

        let expected = icmpv4.checksum();
        // no payload change but force a checksum recompute anyway
        icmpv4.reconcile_all();
        assert_eq!(expected, icmpv4.checksum());
    }

    #[capsule::test]
    fn push_icmpv4_header_without_body() {
        let packet = Mbuf::new().unwrap();
        let ethernet = packet.push::<Ethernet>().unwrap();
        let ipv4 = ethernet.push::<Ipv4>().unwrap();

        assert!(ipv4.push::<Icmpv4>().is_err());
    }
}

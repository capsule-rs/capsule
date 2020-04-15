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

//! Packet types for reading and writing various network protocols.

pub mod checksum;
mod ethernet;
pub mod icmp;
pub mod ip;
mod tcp;
mod udp;

pub use self::ethernet::*;
pub use self::tcp::*;
pub use self::udp::*;

use crate::Mbuf;
use failure::{Fail, Fallible};
use std::fmt;
use std::marker::PhantomData;
use std::ops::Deref;

/// An argument to restrict users from calling functions on the [`PacketBase`]
/// trait.
///
/// While `Internal` is a publicly exported type, it can only be created
/// inside the crate. Hence any function using it as an argument can only
/// be called from within the crate. For example, users cannot invoke
/// [`PacketBase::clone`] directly from their code.
///
/// [`PacketBase`]: PacketBase
/// [`PacketBase::clone`]: PacketBase::clone
#[derive(Clone, Debug)]
pub struct Internal(());

/// A trait network protocols implement to integrate with other protocols.
///
/// Only use this trait to implement a new network protocol. The trait is
/// not intended to be used directly. Many functions are restricted and are
/// only callable from within the crate. Most applications should use the
/// [`Packet`] trait instead.
///
/// [`Packet`]: Packet
#[allow(clippy::len_without_is_empty)]
pub trait PacketBase {
    /// The proceeding packet type that encapsulates this packet.
    ///
    /// The envelope behaves as a constraint to enforce strict ordering
    /// between packet types. For example, an [`IPv4`] packet must be
    /// encapsulated by an [`Ethernet`] packet.
    ///
    /// [`Ethernet`]: Ethernet
    /// [`IPv4`]: Ipv4
    type Envelope: Packet;

    /// Returns a reference to the envelope.
    fn envelope0(&self) -> &Self::Envelope;

    /// Returns a mutable reference to the envelope.
    fn envelope_mut0(&mut self) -> &mut Self::Envelope;

    /// Returns the envelope.
    fn into_envelope(self) -> Self::Envelope
    where
        Self: Sized;

    /// Returns a reference to the raw message buffer.
    #[inline]
    fn mbuf(&self) -> &Mbuf {
        self.envelope0().mbuf()
    }

    /// Returns a mutable reference to the raw message buffer.
    #[inline]
    fn mbuf_mut(&mut self) -> &mut Mbuf {
        self.envelope_mut0().mbuf_mut()
    }

    /// Returns the buffer offset where the packet begins.
    fn offset(&self) -> usize;

    /// Returns the length of the packet header.
    fn header_len(&self) -> usize;

    /// Returns the length of the packet with the payload.
    #[inline]
    fn len(&self) -> usize {
        self.mbuf().data_len() - self.offset()
    }

    /// Returns the buffer offset where the packet payload begins.
    #[inline]
    fn payload_offset(&self) -> usize {
        self.offset() + self.header_len()
    }

    /// Returns the length of the packet payload.
    #[inline]
    fn payload_len(&self) -> usize {
        self.len() - self.header_len()
    }

    /// Returns a copy of the packet.
    ///
    /// # Safety
    ///
    /// The underlying byte buffer is not cloned. The original and the clone
    /// will share the same buffer. Both copies are independently mutable.
    /// Changes made through one copy could completely invalidate the other.
    ///
    /// [`Packet::peek`] addresses this safety issue by wrapping the clone in
    /// a [`Immutable`] and making the clone behave as an immutable borrow
    /// of the original.
    ///
    /// [`Packet::peek`]: Packet::peek
    /// [`Immutable`] Immutable
    unsafe fn clone(&self, internal: Internal) -> Self;

    /// Parses the envelope's payload as this packet type.
    ///
    /// The implementation should perform the necessary buffer boundary
    /// checks and validate the invariants if any. For example, before parsing
    /// the [`Ethernet`]'s payload as a [`IPv4`] packet, there should be a
    /// check to assert that [`ether_type`] matches the expectation.
    ///
    /// [`Ethernet`]: Ethernet
    /// [`IPv4`]: Ipv4
    /// [`ether_type`]: Ethernet::ether_type
    fn try_parse(envelope: Self::Envelope) -> Fallible<Self>
    where
        Self: Sized;

    /// Prepends packet at the start of the envelope's payload.
    ///
    /// When the packet is inserted into an envelope with an existing payload,
    /// the original payload becomes the payload of the new packet.
    fn try_push(envelope: Self::Envelope, internal: Internal) -> Fallible<Self>
    where
        Self: Sized;

    /// Removes the packet from the message buffer.
    ///
    /// The current payload of the packet becomes the payload of the envelope.
    #[inline]
    fn try_remove(mut self, _internal: Internal) -> Fallible<Self::Envelope>
    where
        Self: Sized,
    {
        let offset = self.offset();
        let len = self.header_len();
        self.mbuf_mut().shrink(offset, len)?;
        Ok(self.into_envelope())
    }

    /// Resets the parsed packet back to raw packet.
    #[inline]
    fn reset0(self) -> Mbuf
    where
        Self: Sized,
    {
        self.into_envelope().reset0()
    }

    /// Maintains the packet invariants after parts of it have been modified.
    fn fix_invariants(&mut self, internal: Internal);

    /// Cascades the changes recursively through the layers.
    #[inline]
    fn cascade0(&mut self) {
        self.fix_invariants(Internal(()));
        self.envelope_mut0().cascade0();
    }
}

/// Common behaviors shared by all typed packets.
pub trait Packet: PacketBase {
    /// Returns a reference to the envelope.
    fn envelope(&self) -> &Self::Envelope {
        self.envelope0()
    }

    /// Returns a mutable reference to the envelope.
    fn envelope_mut(&mut self) -> &mut Self::Envelope {
        self.envelope_mut0()
    }

    /// Parses the payload as packet of `T`.
    ///
    /// The ownership of the packet is moved after invocation. To retain
    /// ownership, use `Packet::peek` instead to gain immutable access
    /// to the packet payload.
    #[inline]
    fn parse<T: Packet<Envelope = Self>>(self) -> Fallible<T>
    where
        Self: Sized,
    {
        T::try_parse(self)
    }

    /// Peeks into the payload as packet of `T`.
    ///
    /// `Packet::peek` returns an immutable reference to the payload. Use
    /// `Packet::parse` instead to gain mutable access to the packet payload.
    #[inline]
    fn peek<'a, T: Packet<Envelope = Self>>(&'a self) -> Fallible<Immutable<'a, T>>
    where
        Self: Sized,
    {
        let clone = unsafe { self.clone(Internal(())) };
        clone.parse::<T>().map(Immutable::new)
    }

    /// Pushes a new packet `T` as the payload.
    #[inline]
    fn push<T: Packet<Envelope = Self>>(self) -> Fallible<T>
    where
        Self: Sized,
    {
        T::try_push(self, Internal(()))
    }

    /// Removes this packet's header from the message buffer.
    ///
    /// The packet's payload becomes the payload of its envelope. The
    /// result of the removal is not guaranteed to be a valid packet.
    #[inline]
    fn remove(self) -> Fallible<Self::Envelope>
    where
        Self: Sized,
    {
        self.try_remove(Internal(()))
    }

    /// Deparses the packet and returns its envelope.
    #[inline]
    fn deparse(self) -> Self::Envelope
    where
        Self: Sized,
    {
        self.into_envelope()
    }

    /// Resets the parsed packet back to raw packet.
    #[inline]
    fn reset(self) -> Mbuf
    where
        Self: Sized,
    {
        self.reset0()
    }

    /// Cascades the changes recursively through the layers.
    ///
    /// An upper layer change to message buffer size can have cascading
    /// effects on a lower layer packet header. This call recursively ensures
    /// such changes are propogated through all the layers.
    #[inline]
    fn cascade(&mut self) {
        self.cascade0();
    }
}

impl<T: PacketBase> Packet for T {}

/// Immutable smart pointer to a packet.
///
/// A smart pointer that prevents the packet from being modified. The main
/// use is allow safe lookahead of packet payload while retaining ownership
/// of the original packet. The lifetime of the smart pointer is constrained
/// by the original packet.
pub struct Immutable<'a, T: Packet> {
    value: T,
    phantom: PhantomData<&'a T>,
}

impl<T: Packet + fmt::Debug> fmt::Debug for Immutable<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.value.fmt(f)
    }
}

impl<T: Packet> Immutable<'_, T> {
    /// Creates a new immutable smart pointer to a packet.
    pub fn new(value: T) -> Self {
        Immutable {
            value,
            phantom: PhantomData,
        }
    }
}

impl<T: Packet> Deref for Immutable<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

/// Error when packet failed to parse.
#[derive(Debug, Fail)]
#[fail(display = "{}", _0)]
pub struct ParseError(String);

impl ParseError {
    /// Creates a new `ParseError` with a message.
    pub fn new(msg: &str) -> ParseError {
        ParseError(msg.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::MacAddr;
    use crate::packets::ip::v4::Ipv4;
    use crate::packets::Udp;
    use crate::testils::byte_arrays::IPV4_UDP_PACKET;

    #[capsule::test]
    fn parse_and_reset_packet() {
        let packet = Mbuf::from_bytes(&IPV4_UDP_PACKET).unwrap();
        let len = packet.data_len();

        let ethernet = packet.parse::<Ethernet>().unwrap();
        let ipv4 = ethernet.parse::<Ipv4>().unwrap();
        let udp = ipv4.parse::<Udp<Ipv4>>().unwrap();
        let reset = udp.reset();

        assert_eq!(len, reset.data_len());
    }

    #[capsule::test]
    fn peek_packet() {
        let packet = Mbuf::from_bytes(&IPV4_UDP_PACKET).unwrap();

        let ethernet = packet.peek::<Ethernet>().unwrap();
        assert_eq!(MacAddr::new(0, 0, 0, 0, 0, 2), ethernet.src());
        let v4 = ethernet.peek::<Ipv4>().unwrap();
        assert_eq!(255, v4.ttl());
        let udp = v4.peek::<Udp<Ipv4>>().unwrap();
        assert_eq!(39376, udp.src_port());
    }

    #[capsule::test]
    fn peek_back_via_envelope() {
        let packet = Mbuf::from_bytes(&IPV4_UDP_PACKET).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();
        let v4 = ethernet.parse::<Ipv4>().unwrap();
        let udp = v4.parse::<Udp<Ipv4>>().unwrap();
        let mut v4_2 = udp.deparse();
        v4_2.set_ttl(25);
        let udp_2 = v4_2.parse::<Udp<Ipv4>>().unwrap();
        let v4_4 = udp_2.envelope();
        assert_eq!(v4_4.ttl(), 25);
    }
}

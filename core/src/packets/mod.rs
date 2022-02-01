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

pub mod arp;
pub mod checksum;
pub mod ethernet;
pub mod gre;
pub mod gtpu;
pub mod icmp;
pub mod ip;
mod mbuf;
mod size_of;
pub mod tcp;
pub mod types;
pub mod udp;

pub use self::mbuf::*;
pub use self::size_of::*;
pub use capsule_macros::SizeOf;

use crate::packets::ethernet::EtherType;
use anyhow::{Context, Result};
use std::fmt;
use std::marker::PhantomData;
use std::ops::Deref;

/// An argument to restrict users from calling functions on the [`Packet`]
/// trait.
///
/// While `Internal` is a publicly exported type, it can only be created
/// inside the crate. Hence any function using it as an argument can only
/// be called from within the crate. For example, users cannot invoke
/// [`Packet::clone`] directly from their code.
///
/// [`PacketBase`]: PacketBase
/// [`PacketBase::clone`]: PacketBase::clone
#[derive(Clone, Debug)]
pub struct Internal(());

/// A trait all network protocols must implement.
///
/// This is the main trait for interacting with the message buffer as
/// statically-typed packets.
///
/// # Example
///
/// ```
/// let packet = Mbuf::new()?;
/// let ethernet = packet.push::<Ethernet>()?;
/// let ipv4 = ethernet.push::<Ipv4>()?;
///
/// let mut tcp = ipv4.push::<Tcp4>()?;
/// tcp.set_dst_ip(remote_ip);
/// tcp.set_dst_port(22);
/// tcp.reconcile_all();
/// ```
#[allow(clippy::len_without_is_empty)]
pub trait Packet {
    /// The preceding packet type that encapsulates this packet.
    ///
    /// The envelope behaves as a constraint to enforce strict ordering
    /// between packet types. For example, an [IPv4] packet must be
    /// encapsulated by an [Ethernet] packet.
    ///
    /// [Ethernet]: Ethernet
    /// [IPv4]: ip::v4::Ipv4
    type Envelope: Packet;

    /// Returns a reference to the envelope.
    fn envelope(&self) -> &Self::Envelope;

    /// Returns a mutable reference to the envelope.
    fn envelope_mut(&mut self) -> &mut Self::Envelope;

    /// Returns a reference to the raw message buffer.
    ///
    /// Directly reading from the buffer is error-prone and discouraged except
    /// when implementing a new protocol.
    #[inline]
    fn mbuf(&self) -> &Mbuf {
        self.envelope().mbuf()
    }

    /// Returns a mutable reference to the raw message buffer.
    ///
    /// Directly writing to the buffer is error-prone and discouraged except
    /// when implementing a new protocol.
    #[inline]
    fn mbuf_mut(&mut self) -> &mut Mbuf {
        self.envelope_mut().mbuf_mut()
    }

    /// Returns the buffer offset where the current packet begins.
    fn offset(&self) -> usize;

    /// Returns the length of the packet header.
    fn header_len(&self) -> usize;

    /// Returns the buffer offset where the packet payload begins.
    #[inline]
    fn payload_offset(&self) -> usize {
        self.offset() + self.header_len()
    }

    /// Returns the length of the packet with the payload.
    #[inline]
    fn len(&self) -> usize {
        self.mbuf().data_len() - self.offset()
    }

    /// Returns the length of the packet payload.
    #[inline]
    fn payload_len(&self) -> usize {
        self.len() - self.header_len()
    }

    /// Returns a copy of the packet.
    ///
    /// # Remarks
    ///
    /// This function cannot be invoked directly. It is internally used by
    /// [`peek`].
    ///
    /// # Safety
    ///
    /// The underlying byte buffer is not cloned. The original and the clone
    /// will share the same buffer. Both copies are independently mutable.
    /// Changes made through one copy could completely invalidate the other.
    ///
    /// [`peek`] addresses this safety issue by wrapping the clone in an
    /// [`Immutable`] and making the clone behave as an immutable borrow of
    /// the original.
    ///
    /// [`peek`]: Packet::peek
    /// [`Immutable`]: Immutable
    unsafe fn clone(&self, internal: Internal) -> Self;

    /// Parses the envelope's payload as this packet type.
    ///
    /// The implementation should perform the necessary buffer boundary
    /// checks and validate the invariants if any. For example, before parsing
    /// the [Ethernet]'s payload as an [IPv4] packet, there should be a
    /// check to assert that [`ether_type`] matches the expectation.
    ///
    /// # Remarks
    ///
    /// This function cannot be invoked directly. It is internally used by
    /// [`parse`].
    ///
    /// [Ethernet]: Ethernet
    /// [IPv4]: ip::v4::Ipv4
    /// [`ether_type`]: Ethernet::ether_type
    /// [`parse`]: Packet::parse
    fn try_parse(envelope: Self::Envelope, internal: Internal) -> Result<Self>
    where
        Self: Sized;

    /// Parses the packet's payload as a packet of type `T`.
    ///
    /// The ownership of the packet is moved after invocation. To retain
    /// ownership, use [`peek`] instead.
    ///
    /// [`peek`]: Packet::peek
    #[inline]
    fn parse<T: Packet<Envelope = Self>>(self) -> Result<T>
    where
        Self: Sized,
    {
        T::try_parse(self, Internal(()))
    }

    /// Peeks into the packet's payload as a packet of type `T`.
    ///
    /// `peek` returns an immutable reference to the payload. The caller
    /// retains full ownership of the packet.
    #[inline]
    fn peek<T: Packet<Envelope = Self>>(&self) -> Result<Immutable<'_, T>>
    where
        Self: Sized,
    {
        let clone = unsafe { self.clone(Internal(())) };
        clone.parse::<T>().map(Immutable::new)
    }

    /// Prepends a new packet to the beginning of the envelope's payload.
    ///
    /// When the packet is inserted into an envelope with an existing payload,
    /// the original payload becomes the payload of the new packet. The
    /// implementation should validate the invariants accordingly if there's
    /// an existing payload.
    ///
    /// # Remarks
    ///
    /// This function cannot be invoked directly. It is internally used by
    /// [`push`].
    ///
    /// [`push`]: Packet::push
    fn try_push(envelope: Self::Envelope, internal: Internal) -> Result<Self>
    where
        Self: Sized;

    /// Prepends a new packet of type `T` to the beginning of the envelope's
    /// payload.
    #[inline]
    fn push<T: Packet<Envelope = Self>>(self) -> Result<T>
    where
        Self: Sized,
    {
        T::try_push(self, Internal(()))
    }

    /// Deparses the packet back to the envelope's packet type.
    fn deparse(self) -> Self::Envelope
    where
        Self: Sized;

    /// Removes this packet's header from the message buffer.
    ///
    /// After the removal, the packet's payload becomes the payload of its
    /// envelope. The result of the removal is not guaranteed to be a valid
    /// packet. The protocol should provide a custom implementation if
    /// additional fixes are necessary.
    ///
    /// # Errors
    ///
    /// Returns an error if the buffer does not have sufficient data to
    /// remove.
    #[inline]
    fn remove(mut self) -> Result<Self::Envelope>
    where
        Self: Sized,
    {
        let offset = self.offset();
        let len = self.header_len();
        self.mbuf_mut()
            .shrink(offset, len)
            .context("failed to remove packet header.")?;
        Ok(self.deparse())
    }

    /// Removes the packet's payload from the message buffer.
    ///
    /// # Errors
    ///
    /// Returns an error if the size of the payload to remove exceeds data
    /// stored in the buffer. The packet in the mbuf is invalid.
    #[inline]
    fn remove_payload(&mut self) -> Result<()> {
        let offset = self.payload_offset();
        let len = self.payload_len();
        self.mbuf_mut()
            .shrink(offset, len)
            .context("failed to remove packet payload.")?;
        Ok(())
    }

    /// Resets the parsed packet back to `Mbuf`.
    ///
    /// [`Mbuf`]: Mbuf
    #[inline]
    fn reset(self) -> Mbuf
    where
        Self: Sized,
    {
        self.deparse().reset()
    }

    /// Reconciles the derivable header fields against the changes made to
    /// the packet.
    ///
    /// Protocols that have derivable header fields, like a checksum, should
    /// implement this to recompute those fields after changes were made
    /// to the packet.
    #[inline]
    fn reconcile(&mut self) {}

    /// Reconciles against the changes recursively through all layers.
    ///
    /// A change made to a packet can have cascading effects through the
    /// envelope chain. The call will recursively reconcile those changes
    /// starting at the current packet type. The recursion does not include
    /// the payload if the payload contains other packet types.
    #[inline]
    fn reconcile_all(&mut self) {
        self.reconcile();
        self.envelope_mut().reconcile_all();
    }

    /// Encapsulates the packet in a tunnel.
    ///
    /// Returns the delivery packet added by the tunnel. Once encapsulated,
    /// the current packet and the current payload must not be modified.
    /// The delivery packet treats the current packet as its opaque payload.
    #[inline]
    fn encap<T: Tunnel<Payload = Self>>(self) -> Result<T::Delivery>
    where
        Self: Sized,
    {
        T::encap(self)
    }

    /// Decapsulates the tunnel by removing the delivery packet.
    ///
    /// Returns the payload packet encapsulated in the tunnel.
    #[inline]
    fn decap<T: Tunnel<Delivery = Self>>(self) -> Result<T::Payload>
    where
        Self: Sized,
    {
        T::decap(self)
    }
}

/// A trait datalink layer protocol can implement.
///
/// A datalink protocol must implement this trait if it needs to encapsulate
/// network protocols like IP or ARP. Otherwise, it should not implement this
/// trait.
pub trait Datalink: Packet {
    /// Gets the encapsulated packet type.
    ///
    /// Returns the ethernet protocol type codes because ethernet is the most
    /// ubiquitous datalink protocol. Other datalink like InfiniBand adopted
    /// the ethernet type codes. When implementing a datalink with its own
    /// type codes, a translation from ether type is needed.
    fn protocol_type(&self) -> EtherType;

    /// Sets the protocol type of the encapsulated packet.
    ///
    /// Uses the ethernet protocol type codes because ethernet is the most
    /// ubiquitous datalink protocol. Other datalink like InfiniBand adopted
    /// the ethernet type codes. When implementing a datalink with its own
    /// type codes, a translation from ether type is needed.
    fn set_protocol_type(&mut self, ether_type: EtherType);
}

/// A trait all tunnel protocols must implement.
///
/// This trait defines how the entry point should encapsulate the payload
/// packet, and how the exit point should decapsulate the delivery packet.
pub trait Tunnel {
    /// The original packet type before entering the tunnel.
    type Payload: Packet;

    /// The packet type tunnel uses to deliver the datagram to the tunnel
    /// exit point.
    type Delivery: Packet;

    /// Encapsulates the original packet and returns the new delivery packet.
    ///  
    /// Once encapsulated, the original packet and its payload becomes the
    /// opaque payload of the newly prepended delivery packet. The original
    /// packet cannot be parsed and manipulated until it's decapsulated. The
    /// encapsulator must construct the payload packet in its entirety before
    /// invoking this.
    ///  
    /// A tunnel protocol, for example GRE, may add multiple delivery packet
    /// headers to the datagram. The return type should be the first
    /// prepended packet type in the protocol stack.
    fn encap(payload: Self::Payload) -> Result<Self::Delivery>;

    /// Decapsulates the delivery packet and returns the original packet.
    ///
    /// Once decapsulated, the content of the delivery packet(s) are lost.
    /// The decapsulator is responsible for caching the information before
    /// invoking this.
    fn decap(delivery: Self::Delivery) -> Result<Self::Payload>;
}

/// Immutable smart pointer to a struct.
///
/// A smart pointer that prevents the struct from being modified. The main
/// use is allow safe lookahead of packet payload while retaining ownership
/// of the original packet. The lifetime of the smart pointer is constrained
/// by the original packet. The pointer can be generally used on all structs
/// other than packets as well.
pub struct Immutable<'a, T> {
    value: T,
    phantom: PhantomData<&'a T>,
}

impl<T: fmt::Debug> fmt::Debug for Immutable<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.value.fmt(f)
    }
}

impl<T> Immutable<'_, T> {
    /// Creates a new immutable smart pointer to a struct `T`.
    pub fn new(value: T) -> Self {
        Immutable {
            value,
            phantom: PhantomData,
        }
    }
}

impl<T> Deref for Immutable<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

/// Mark of the packet as either `Emit` or `Drop`.
///
/// Together, a `Result<Postmark>` represents all three possible outcome
/// of packet processing. A packet can either be emitted through port TX,
/// intentionally dropped, or aborted due to an error.
#[derive(Debug)]
pub enum Postmark {
    /// Packet emitted through a port TX.
    Emit,

    /// Packet intentionally dropped.
    Drop(Mbuf),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::MacAddr;
    use crate::packets::ethernet::Ethernet;
    use crate::packets::ip::v4::Ipv4;
    use crate::packets::udp::Udp4;
    use crate::testils::byte_arrays::UDP4_PACKET;

    #[capsule::test]
    fn parse_and_reset_packet() {
        let packet = Mbuf::from_bytes(&UDP4_PACKET).unwrap();
        let len = packet.data_len();

        let ethernet = packet.parse::<Ethernet>().unwrap();
        let ip4 = ethernet.parse::<Ipv4>().unwrap();
        let udp = ip4.parse::<Udp4>().unwrap();
        let reset = udp.reset();

        assert_eq!(len, reset.data_len());
    }

    #[capsule::test]
    fn peek_packet() {
        let packet = Mbuf::from_bytes(&UDP4_PACKET).unwrap();

        let ethernet = packet.peek::<Ethernet>().unwrap();
        assert_eq!(MacAddr::new(0, 0, 0, 0, 0, 2), ethernet.src());
        let ip4 = ethernet.peek::<Ipv4>().unwrap();
        assert_eq!(255, ip4.ttl());
        let udp = ip4.peek::<Udp4>().unwrap();
        assert_eq!(39376, udp.src_port());
    }

    #[capsule::test]
    fn parse_and_deparse_packet() {
        let packet = Mbuf::from_bytes(&UDP4_PACKET).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();
        let mut ip4 = ethernet.parse::<Ipv4>().unwrap();
        ip4.set_ttl(25);

        let udp = ip4.parse::<Udp4>().unwrap();
        assert_eq!(udp.envelope().ttl(), 25);

        let ip4_2 = udp.deparse();
        assert_eq!(ip4_2.ttl(), 25);
    }

    #[capsule::test]
    fn remove_header_and_payload() {
        let packet = Mbuf::from_bytes(&UDP4_PACKET).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();
        let ip4 = ethernet.parse::<Ipv4>().unwrap();

        let mut udp = ip4.parse::<Udp4>().unwrap();
        assert!(udp.payload_len() > 0);

        let _ = udp.remove_payload();
        assert_eq!(0, udp.payload_len());

        let ip4 = udp.remove().unwrap();
        assert_eq!(0, ip4.payload_len());
    }

    /// Demonstrates that `Packet::peek` behaves as an immutable borrow on
    /// the envelope. Compilation will fail because it tries to have a
    /// mutable borrow on `Ethernet` while there's already an immutable
    /// borrow through peek.
    ///
    /// ```
    /// |         let ip4 = ethernet.peek::<Ipv4>().unwrap();
    /// |                    -------- immutable borrow occurs here
    /// |         ethernet.set_src(MacAddr::UNSPECIFIED);
    /// |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ mutable borrow occurs here
    /// |         assert!(ip4.payload_len() > 0);
    /// |                 ---- immutable borrow later used here
    /// ```
    #[test]
    #[cfg(feature = "compile_failure")]
    fn cannot_mutate_packet_while_peeking_into_payload() {
        let packet = Mbuf::from_bytes(&UDP4_PACKET).unwrap();
        let mut ethernet = packet.parse::<Ethernet>().unwrap();
        let ip4 = ethernet.peek::<Ipv4>().unwrap();
        ethernet.set_src(MacAddr::UNSPECIFIED);
        assert!(ip4.payload_len() > 0);
    }

    /// Demonstrates that `Packet::peek` returns an immutable packet wrapper.
    /// Compilation will fail because it tries to mutate the ethernet packet.
    ///
    /// ```
    /// |         ethernet.set_src(MacAddr::UNSPECIFIED);
    /// |         ^^^^^^^^ cannot borrow as mutable
    /// ```
    #[test]
    #[cfg(feature = "compile_failure")]
    fn cannot_mutate_immutable_packet() {
        let packet = Mbuf::from_bytes(&UDP4_PACKET).unwrap();
        let ethernet = packet.peek::<Ethernet>().unwrap();
        ethernet.set_src(MacAddr::UNSPECIFIED);
    }
}

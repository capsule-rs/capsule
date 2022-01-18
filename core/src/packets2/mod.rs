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

//pub mod arp;
pub mod checksum;
pub mod ethernet;
//pub mod gre;
//pub mod icmp;
pub mod ip;
mod mbuf;
mod size_of;
//pub mod tcp;
//pub mod types;
pub mod udp;

pub use self::mbuf::*;
pub use self::size_of::*;
pub use capsule_macros::SizeOf;

use crate::packets2::ethernet::EtherType;
use anyhow::Result;

/// A trait all network protocols must implement.
///
/// This is the main trait for interacting with the message buffer as
/// statically-typed packets.
///
/// # Example
///
/// ```
/// let mut packet = Mbuf::new()?;
/// let mut ethernet = packet.push::<Ethernet>()?;
/// let mut ipv4 = ethernet.push::<Ipv4>()?;
///
/// let mut tcp = ipv4.push::<Tcp4>()?;
/// tcp.set_dst_ip(remote_ip);
/// tcp.set_dst_port(22);
/// tcp.reconcile_all();
/// ```
#[allow(clippy::len_without_is_empty)]
pub trait Packet<'env> {
    /// The preceding packet type that encapsulates this packet.
    ///
    /// The envelope behaves as a constraint to enforce strict ordering
    /// between packet types. For example, an [IPv4] packet must be
    /// encapsulated by an [Ethernet] packet.
    ///
    /// [Ethernet]: Ethernet
    /// [IPv4]: ip::v4::Ipv4
    type Envelope: Packet<'env>;

    /// Returns a reference to the envelope.
    fn envelope<'local>(&'local self) -> &'local Self::Envelope
    where
        'env: 'local;

    /// Returns a mutable reference to the envelope.
    fn envelope_mut<'local>(&'local mut self) -> &'local mut Self::Envelope
    where
        'env: 'local;

    /// Returns a reference to the raw message buffer.
    ///
    /// Directly reading from the buffer is error-prone and discouraged except
    /// when implementing a new protocol.
    #[inline]
    fn mbuf<'local>(&'local self) -> &'local Mbuf
    where
        'env: 'local,
    {
        self.envelope().mbuf()
    }

    /// Returns a mutable reference to the raw message buffer.
    ///
    /// Directly writing to the buffer is error-prone and discouraged except
    /// when implementing a new protocol.
    #[inline]
    fn mbuf_mut<'local>(&'local mut self) -> &'local mut Mbuf
    where
        'env: 'local,
    {
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

    /// Parses the envelope's payload as this packet type.
    ///
    /// The implementation should perform the necessary buffer boundary
    /// checks and validate the invariants if any. For example, before parsing
    /// the [Ethernet]'s payload as an [IPv4] packet, there should be a
    /// check to assert that [`ether_type`] matches the expectation.
    ///
    /// # Remarks
    ///
    /// This function should not be invoked directly. It is internally used by
    /// [`parse`].
    ///
    /// [Ethernet]: Ethernet
    /// [IPv4]: ip::v4::Ipv4
    /// [`ether_type`]: Ethernet::ether_type
    /// [`parse`]: Packet::parse
    fn try_parse(envelope: &'env mut Self::Envelope) -> Result<Self>
    where
        Self: Sized;

    /// Parses the packet's payload as a packet of type `T`.
    #[inline]
    fn parse<T: Packet<'env, Envelope = Self>>(&'env mut self) -> Result<T>
    where
        Self: Sized,
    {
        T::try_parse(self)
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
    /// This function should not be invoked directly. It is internally used by
    /// [`push`].
    ///
    /// [`push`]: Packet::push
    fn try_push(envelope: &'env mut Self::Envelope) -> Result<Self>
    where
        Self: Sized;

    /// Prepends a new packet of type `T` to the beginning of the envelope's
    /// payload.
    #[inline]
    fn push<T: Packet<'env, Envelope = Self>>(&'env mut self) -> Result<T>
    where
        Self: Sized,
    {
        T::try_push(self)
    }

    /// Removes this packet's header from the message buffer.
    ///
    /// After the removal, the packet's payload becomes the payload of its
    /// envelope. The result of the removal is not guaranteed to be a valid
    /// packet. The protocol should make additional fixes if necessary.
    #[inline]
    fn remove(mut self) -> Result<()>
    where
        Self: Sized,
    {
        let offset = self.offset();
        let len = self.header_len();
        self.mbuf_mut().shrink(offset, len)?;
        Ok(())
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
        self.mbuf_mut().shrink(offset, len)?;
        Ok(())
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

    // /// Encapsulates the packet in a tunnel.
    // ///
    // /// Returns the delivery packet added by the tunnel. Once encapsulated,
    // /// the current packet and the current payload must not be modified.
    // /// The delivery packet treats the current packet as its opaque payload.
    // #[inline]
    // fn encap<T: Tunnel<Payload = Self>>(self) -> Result<T::Delivery>
    // where
    //     Self: Sized,
    // {
    //     T::encap(self)
    // }

    // /// Decapsulates the tunnel by removing the delivery packet.
    // ///
    // /// Returns the payload packet encapsulated in the tunnel.
    // #[inline]
    // fn decap<T: Tunnel<Delivery = Self>>(self) -> Result<T::Payload>
    // where
    //     Self: Sized,
    // {
    //     T::decap(self)
    // }
}

/// A trait datalink layer packet can implement.
///
/// A datalink packet must implement this trait if it needs to encapsulate
/// network packets like [IP] or [ARP]. Otherwise, it should not implement
/// this trait.
///
/// [IP]: crate::packets::ip::v4::Ipv4
/// [ARP]: crate::packets::arp::Arp
pub trait Datalink {
    /// Gets the encapsulated packet header type.
    ///
    /// Returns the ethernet protocol type codes because ethernet is the most
    /// ubiquitous datalink protocol. Other datalink like InfiniBand adopted
    /// the ethernet type codes. When implementing a datalink with its own
    /// type codes, a translation from ether type is needed.
    fn next_header(&self) -> EtherType;

    /// Sets the header type of the encapsulated packet.
    ///
    /// Uses the ethernet protocol type codes because ethernet is the most
    /// ubiquitous datalink protocol. Other datalink like InfiniBand adopted
    /// the ethernet type codes. When implementing a datalink with its own
    /// type codes, a translation from ether type is needed.
    fn set_next_header(&mut self, ether_type: EtherType);
}

// /// A trait all tunnel protocols must implement.
// ///
// /// This trait defines how the entry point should encapsulate the payload
// /// packet, and how the exit point should decapsulate the delivery packet.
// pub trait Tunnel {
//     /// The original packet type before entering the tunnel.
//     type Payload: Packet;

//     /// The packet type tunnel uses to deliver the datagram to the tunnel
//     /// exit point.
//     type Delivery: Packet;

//     /// Encapsulates the original packet and returns the new delivery packet.
//     ///
//     /// Once encapsulated, the original packet and its payload becomes the
//     /// opaque payload of the newly prepended delivery packet. The original
//     /// packet cannot be parsed and manipulated until it's decapsulated. The
//     /// encapsulator must construct the payload packet in its entirety before
//     /// invoking this.
//     ///
//     /// A tunnel protocol, for example GRE, may add multiple delivery packet
//     /// headers to the datagram. The return type should be the first
//     /// prepended packet type in the protocol stack.
//     fn encap(payload: Self::Payload) -> Result<Self::Delivery>;

//     /// Decapsulates the delivery packet and returns the original packet.
//     ///
//     /// Once decapsulated, the content of the delivery packet(s) are lost.
//     /// The decapsulator is responsible for caching the information before
//     /// invoking this.
//     fn decap(delivery: Self::Delivery) -> Result<Self::Payload>;
// }

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packets2::ethernet::Ethernet;
    use crate::packets2::ip::v4::Ipv4;
    use crate::packets2::udp::Udp4;
    use crate::testils::byte_arrays::UDP4_PACKET;

    #[capsule::test]
    fn ref_mut_parse() {
        let mut packet = Mbuf::from_bytes(&UDP4_PACKET).unwrap();
        let len = packet.data_len();

        {
            let ethernet = packet.parse::<Ethernet<'_>>().unwrap();
            assert_eq!(len, ethernet.len());
        }

        assert_eq!(len, packet.data_len());
    }

    #[capsule::test]
    fn remove_header_and_payload() {
        let mut packet = Mbuf::from_bytes(&UDP4_PACKET).unwrap();
        let mut ethernet = packet.parse::<Ethernet<'_>>().unwrap();
        let mut ip4 = ethernet.parse::<Ipv4<'_>>().unwrap();

        {
            let mut udp = ip4.parse::<Udp4<'_>>().unwrap();
            assert!(udp.payload_len() > 0);

            let _ = udp.remove_payload();
            assert_eq!(0, udp.payload_len());

            let _ = udp.remove().unwrap();
        }

        //assert_eq!(0, ip4.payload_len());
    }
}

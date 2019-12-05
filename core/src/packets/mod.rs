pub mod checksum;
mod ethernet;
pub mod icmp;
pub mod ip;
mod mbuf;
mod tcp;
mod udp;

pub use self::ethernet::*;
pub use self::tcp::*;
pub use self::udp::*;

use crate::{Mbuf, Result, SizeOf};
use failure::Fail;
use std::fmt;
use std::marker::PhantomData;
use std::ops::{Deref, DerefMut};
use std::rc::Rc;

/// Packet header marker trait.
///
/// Some packet headers are variable in length, such as the IPv6
/// segment routing header. The fixed portion can be statically
/// defined, but the variable portion has to be parsed separately.
pub trait Header: SizeOf {}

/// Common behaviors shared by all packets.
#[allow(clippy::len_without_is_empty)]
pub trait Packet: Clone {
    /// The header type of the packet.
    type Header: Header;
    /// The outer packet type that encapsulates the packet.
    type Envelope: Packet;

    /// Returns a reference to the DPDK message buffer.
    #[doc(hidden)]
    #[inline]
    fn mbuf(&self) -> &Mbuf {
        self.envelope().mbuf()
    }

    /// Returns a mutable reference to the DPDK message buffer.
    #[doc(hidden)]
    #[inline]
    fn mbuf_mut(&mut self) -> &mut Mbuf {
        self.envelope_mut().mbuf_mut()
    }

    /// Returns a reference to the encapsulating packet.
    fn envelope(&self) -> &Self::Envelope;

    /// Returns a mutable reference to the encapsulating packet.
    fn envelope_mut(&mut self) -> &mut Self::Envelope;

    /// Returns a reference to the packet header.
    #[doc(hidden)]
    fn header(&self) -> &Self::Header;

    /// Returns a mutable reference to the packet header.
    #[doc(hidden)]
    fn header_mut(&mut self) -> &mut Self::Header;

    /// Returns the buffer offset where the packet header begins.
    fn offset(&self) -> usize;

    /// Returns the length of the packet header.
    ///
    /// Includes both the fixed and variable portion of the header.
    #[inline]
    fn header_len(&self) -> usize {
        Self::Header::size_of()
    }

    /// Returns the length of the packet.
    #[inline]
    fn len(&self) -> usize {
        self.mbuf().data_len() - self.offset()
    }

    /// Returns if the length of the packet is empty or not.
    // #[inline]
    // fn is_empty(&self) -> bool {
    //     self.len() == 0
    // }

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

    /// Parses the payload as packet of `T`.
    ///
    /// The ownership of the packet is moved after invocation. To retain
    /// ownership, use `Packet::peek` instead to gain immutable access
    /// to the packet payload.
    #[inline]
    fn parse<T: Packet<Envelope = Self>>(self) -> Result<T>
    where
        Self: Sized,
    {
        T::do_parse(self)
    }

    // the public `parse::<T>` delegates to this function.
    #[doc(hidden)]
    fn do_parse(envelope: Self::Envelope) -> Result<Self>
    where
        Self: Sized;

    /// Peeks into the payload as packet of `T`.
    ///
    /// `Packet::peek` returns an immutable reference to the payload. Use
    /// `Packet::parse` instead to gain mutable access to the packet payload.
    #[inline]
    fn peek<'a, T: Packet<Envelope = Self>>(&'a self) -> Result<Immutable<'a, T>>
    where
        Self: Sized,
    {
        self.clone().parse::<T>().map(Immutable::new)
    }

    /// Pushes a new packet `T` as the payload.
    #[inline]
    fn push<T: Packet<Envelope = Self>>(self) -> Result<T>
    where
        Self: Sized,
    {
        T::do_push(self)
    }

    // the public `push::<T>` delegates to this function.
    #[doc(hidden)]
    fn do_push(envelope: Self::Envelope) -> Result<Self>
    where
        Self: Sized;

    /// Removes this packet's header from the message buffer.
    ///
    /// The packet's payload becomes the payload of its envelope. The
    /// result of the removal is not guaranteed to be a valid packet.
    fn remove(self) -> Result<Self::Envelope>
    where
        Self: Sized;

    /// Cascades the changes recursively through the layers.
    ///
    /// An upper layer change to message buffer size can have cascading
    /// effects on a lower layer packet header. This call recursively ensures
    /// such changes are propogated through all the layers.
    #[inline]
    fn cascade(&mut self) {
        self.envelope_mut().cascade();
    }

    /// Deparses the packet and returns its envelope.
    fn deparse(self) -> Self::Envelope;

    /// Resets the parsed packet back to raw packet.
    fn reset(self) -> Mbuf
    where
        Self: Sized,
    {
        self.deparse().reset()
    }
}

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

/// Conditional reference counted smart pointer.
///
/// The content of the pointer will be deep-copied the first time `clone` is
/// invoked. Subsequent calls to `clone` will clone a `std::rc::Rc` pointer,
/// and not perform deep copy any more.
#[doc(hidden)]
#[derive(Debug)]
pub(crate) enum CondRc<T: Packet> {
    Raw(T),
    Counted(Rc<T>),
}

impl<T: Packet> CondRc<T> {
    pub fn new(value: T) -> Self {
        CondRc::Raw(value)
    }

    pub fn into_owned(self) -> T {
        match self {
            CondRc::Raw(value) => value,
            // because this fn requires ownership move, it should
            // never be invoked on a reference counted one.
            CondRc::Counted(_) => unreachable!(),
        }
    }
}

impl<T: Packet> Clone for CondRc<T> {
    fn clone(&self) -> Self {
        match self {
            CondRc::Raw(value) => CondRc::Counted(Rc::new(value.clone())),
            CondRc::Counted(value) => CondRc::Counted(Rc::clone(value)),
        }
    }
}

impl<T: Packet> Deref for CondRc<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        match self {
            CondRc::Raw(value) => value,
            CondRc::Counted(value) => Deref::deref(value),
        }
    }
}

impl<T: Packet> DerefMut for CondRc<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            CondRc::Raw(value) => value,
            // because this fn requires a mutable reference, it should
            // never be invoked on a reference counted one.
            CondRc::Counted(_) => unreachable!(),
        }
    }
}

/// Error when packet failed to parse.
#[derive(Debug, Fail)]
#[fail(display = "{}", _0)]
pub struct ParseError(String);

impl ParseError {
    pub fn new(msg: &str) -> ParseError {
        ParseError(msg.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::MacAddr;
    use crate::packets::ip::v4::Ipv4;
    use crate::packets::{Udp, UDP_PACKET};

    #[nb2::test]
    fn parse_and_reset_packet() {
        let packet = Mbuf::from_bytes(&UDP_PACKET).unwrap();
        let len = packet.data_len();

        let ethernet = packet.parse::<Ethernet>().unwrap();
        let ipv4 = ethernet.parse::<Ipv4>().unwrap();
        let udp = ipv4.parse::<Udp<Ipv4>>().unwrap();
        let reset = udp.reset();

        assert_eq!(len, reset.data_len());
    }

    #[nb2::test]
    fn peek_packet() {
        let packet = Mbuf::from_bytes(&UDP_PACKET).unwrap();

        let ethernet = packet.peek::<Ethernet>().unwrap();
        assert_eq!(MacAddr::new(0, 0, 0, 0, 0, 2), ethernet.src());
        let v4 = ethernet.peek::<Ipv4>().unwrap();
        assert_eq!(255, v4.ttl());
        let udp = v4.peek::<Udp<Ipv4>>().unwrap();
        assert_eq!(39376, udp.src_port());
    }

    #[nb2::test]
    fn peek_back_via_envelope() {
        let packet = Mbuf::from_bytes(&UDP_PACKET).unwrap();
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

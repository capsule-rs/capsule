use crate::packets::icmp::v6::{Icmpv6, Icmpv6Packet, Icmpv6Payload, Icmpv6Type, Icmpv6Types};
use crate::packets::ip::v6::Ipv6Packet;
use crate::packets::Packet;
use crate::SizeOf;
use std::fmt;

/// Packet Too Big Message defined in [IETF RFC 4443].
///
/// ```
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Type      |     Code      |          Checksum             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                             MTU                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                    As much of invoking packet                 |
/// +               as possible without the ICMPv6 packet           +
/// |               exceeding the minimum IPv6 MTU [IPv6]           |
/// ```
///
/// MTU            The Maximum Transmission Unit of the next-hop link.
///
/// [IETF RFC 4443]: https://tools.ietf.org/html/rfc4443#section-3.2
#[derive(Clone, Copy, Debug, Default, SizeOf)]
#[repr(C, packed)]
pub struct PacketTooBig {
    mtu: u32,
}

impl Icmpv6Payload for PacketTooBig {
    fn msg_type() -> Icmpv6Type {
        Icmpv6Types::PacketTooBig
    }
}

impl<E: Ipv6Packet> Icmpv6<E, PacketTooBig> {
    /// Returns the MTU of the next-hop link.
    #[inline]
    pub fn mtu(&self) -> u32 {
        u32::from_be(self.payload().mtu)
    }

    /// Sets the MTU of the next-hop link.
    #[inline]
    pub fn set_mtu(&mut self, mtu: u32) {
        self.payload_mut().mtu = u32::to_be(mtu);
    }

    /// See: Packet trait `cascade`
    ///
    /// Implemented here as is required by `Icmpv6Packet` derive-macro.
    #[inline]
    pub fn cascade(&mut self) {
        let mtu = self.mtu() as usize;
        // ignores the error if there's nothing to truncate.
        let _ = self.envelope_mut().truncate(mtu);
        self.compute_checksum();
        self.envelope_mut().cascade();
    }
}

impl<E: Ipv6Packet> fmt::Debug for Icmpv6<E, PacketTooBig> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("icmpv6")
            .field("type", &format!("{}", self.msg_type()))
            .field("code", &self.code())
            .field("checksum", &format!("0x{:04x}", self.checksum()))
            .field("mtu", &self.mtu())
            .field("$offset", &self.offset())
            .field("$len", &self.len())
            .field("$header_len", &self.header_len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SizeOf;

    #[test]
    fn size_of_packet_too_big() {
        assert_eq!(4, PacketTooBig::size_of());
    }
}

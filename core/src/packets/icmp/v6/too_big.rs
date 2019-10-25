use crate::packets::icmp::v6::{Icmpv6, Icmpv6Packet, Icmpv6Payload, Icmpv6Type, Icmpv6Types};
use crate::packets::ip::v6::Ipv6Packet;
use crate::packets::{EthernetHeader, Packet};
use crate::SizeOf;
use std::fmt;

/*  From https://tools.ietf.org/html/rfc4443#section-3.2
    Packet Too Big Message

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Type      |     Code      |          Checksum             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                             MTU                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    As much of invoking packet                 |
    +               as possible without the ICMPv6 packet           +
    |               exceeding the minimum IPv6 MTU [IPv6]           |

    MTU            The Maximum Transmission Unit of the next-hop link.
*/

/// Packet too big message
#[derive(Clone, Copy, Debug, Default)]
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
    #[inline]
    pub fn mtu(&self) -> u32 {
        u32::from_be(self.payload().mtu)
    }

    #[inline]
    pub fn set_mtu(&mut self, mtu: u32) {
        self.payload_mut().mtu = u32::to_be(mtu);
    }
}

impl<E: Ipv6Packet> fmt::Display for Icmpv6<E, PacketTooBig> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("icmpv6")
            .field("type", &self.msg_type())
            .field("code", &self.code())
            .field("checksum", &format!("0x{:04x}", self.checksum()))
            .field("mtu", &self.mtu())
            .field("$offset", &self.offset())
            .field("$len", &self.len())
            .field("$header_len", &self.header_len())
            .finish()
    }
}

// TODO: need specialization to get this back
// https://github.com/rust-lang/rust/issues/31844

// impl<E: Ipv6Packet> Packet for Icmpv6<E, PacketTooBig> {
//     #[inline]
//     fn cascade(&mut self) {
//         // assuming inside an ethernet frame
//         let max_len = self.mtu() as usize + EthernetHeader::size_of();
//         // only err if nothing to trim, ignore the result
//         let _ = self.mbuf_mut().truncate(max_len);

//         self.compute_checksum();
//         self.envelope_mut().cascade();
//     }
// }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn size_of_packet_too_big() {
        assert_eq!(4, PacketTooBig::size_of());
    }
}

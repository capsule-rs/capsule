mod neighbor_advert;
mod neighbor_solicit;
mod options;
mod router_advert;
mod router_solicit;

pub use self::neighbor_advert::*;
pub use self::neighbor_solicit::*;
pub use self::options::*;
pub use self::router_advert::*;
pub use self::router_solicit::*;

use super::{Icmpv6, Icmpv6Packet, Icmpv6Payload};
use crate::packets::ip::v6::Ipv6Packet;
use crate::packets::Packet;
use crate::Result;

/// NDP message payload marker.
pub trait NdpPayload: Icmpv6Payload {}

/// Common behaviors shared by NDP packets.
///
/// NDP packets are also ICMPv6 packets.
pub trait NdpPacket<E: Ipv6Packet, P: NdpPayload>: Icmpv6Packet<E, P> {
    /// Returns an iterator that iterates through the options in the NDP packet.
    fn options(&self) -> NdpOptionsIterator<'_>;

    /// Add option to NDP messaged.
    fn push_option<T: NdpOption>(&mut self) -> Result<T>;
}

impl<E: Ipv6Packet, P: NdpPayload> NdpPacket<E, P> for Icmpv6<E, P>
where
    Icmpv6<E, P>: Icmpv6Packet<E, P>,
{
    fn options(&self) -> NdpOptionsIterator<'_> {
        let mbuf = self.mbuf();
        let offset = self.payload_offset() + P::size_of();
        NdpOptionsIterator::new(mbuf, offset)
    }

    fn push_option<T: NdpOption>(&mut self) -> Result<T> {
        T::do_push(self.mbuf_mut())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::MacAddr;
    use crate::packets::ethernet::Ethernet;
    use crate::packets::icmp::v6::ndp::{NdpOptions, SOURCE_LINK_LAYER_ADDR};
    use crate::packets::ip::v6::Ipv6;
    use crate::packets::ip::ProtocolNumbers;
    use crate::Mbuf;
    use fallible_iterator::FallibleIterator;
    use std::str::FromStr;

    #[nb2::test]
    fn test_add_source_link_layer_address() {
        let mac_addr = MacAddr::from_str("01:00:00:00:00:00").unwrap();
        let raw_packet = Mbuf::new().unwrap();
        let eth = raw_packet.push::<Ethernet>().unwrap();
        let mut ipv6 = eth.push::<Ipv6>().unwrap();
        ipv6.set_next_header(ProtocolNumbers::Icmpv6);
        let mut router_advert = ipv6.push::<Icmpv6<Ipv6, RouterAdvertisement>>().unwrap();

        let mut option: LinkLayerAddress = router_advert.push_option().unwrap();
        option.set_addr(mac_addr);
        option.set_option_type(SOURCE_LINK_LAYER_ADDR);

        let mut iter = router_advert.options();

        while let Ok(Some(option_parse)) = iter.next() {
            if let NdpOptions::SourceLinkLayerAddress(option_type) = option_parse {
                assert_eq!(option_type.addr(), mac_addr);
            } else {
                panic!("Option was not source link layer address");
            }
        }
    }
}

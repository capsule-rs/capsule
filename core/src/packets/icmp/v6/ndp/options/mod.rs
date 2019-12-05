mod link_layer_addr;
mod mtu;
mod prefix_info;

pub use self::link_layer_addr::*;
pub use self::mtu::*;
pub use self::prefix_info::*;

use crate::packets::ParseError;
use crate::{Mbuf, Result};
use fallible_iterator::FallibleIterator;

pub const SOURCE_LINK_LAYER_ADDR: u8 = 1;
pub const TARGET_LINK_LAYER_ADDR: u8 = 2;
pub const PREFIX_INFORMATION: u8 = 3;
//const REDIRECTED_HEADER: u8 = 4;
pub const MTU: u8 = 5;

/// A parsed NDP option.
pub enum NdpOptions {
    SourceLinkLayerAddress(LinkLayerAddress),
    TargetLinkLayerAddress(LinkLayerAddress),
    PrefixInformation(PrefixInformation),
    Mtu(Mtu),
    /// An undefined NDP option.
    Undefined(u8, u8),
}

/// Common behaviors shared by NDP options.
pub trait NdpOption {
    #[doc(hidden)]
    fn do_push(mbuf: &mut Mbuf) -> Result<Self>
    where
        Self: Sized;
}

/// NDP options iterator.
pub struct NdpOptionsIterator<'a> {
    mbuf: &'a Mbuf,
    offset: usize,
}

impl<'a> NdpOptionsIterator<'a> {
    pub fn new(mbuf: &'a Mbuf, offset: usize) -> NdpOptionsIterator<'a> {
        NdpOptionsIterator { mbuf, offset }
    }
}

impl FallibleIterator for NdpOptionsIterator<'_> {
    type Item = NdpOptions;
    type Error = failure::Error;

    fn next(&mut self) -> std::result::Result<Option<Self::Item>, Self::Error> {
        let buffer_len = self.mbuf.data_len();

        if self.offset <= buffer_len {
            let &[option_type, length] =
                unsafe { self.mbuf.read_data::<[u8; 2]>(self.offset)?.as_ref() };

            if length == 0 {
                Err(ParseError::new("NDP option has zero length.").into())
            } else {
                let option = match option_type {
                    SOURCE_LINK_LAYER_ADDR => {
                        let option = LinkLayerAddress::parse(self.mbuf, self.offset)?;
                        NdpOptions::SourceLinkLayerAddress(option)
                    }
                    TARGET_LINK_LAYER_ADDR => {
                        let option = LinkLayerAddress::parse(self.mbuf, self.offset)?;
                        NdpOptions::TargetLinkLayerAddress(option)
                    }
                    PREFIX_INFORMATION => {
                        let option = PrefixInformation::parse(self.mbuf, self.offset)?;
                        NdpOptions::PrefixInformation(option)
                    }
                    MTU => {
                        let option = Mtu::parse(self.mbuf, self.offset)?;
                        NdpOptions::Mtu(option)
                    }
                    _ => NdpOptions::Undefined(option_type, length),
                };

                self.offset += (length * 8) as usize;
                Ok(Some(option))
            }
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
#[rustfmt::skip]
const INVALID_OPTION_LENGTH: [u8;78] = [
    // ** ethernet Header
    0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
    0x86, 0xDD,
    // ** IPv6 Header
    0x60, 0x00, 0x00, 0x00,
    // payload length
    0x00, 0x18,
    0x3a,
    0xff,
    0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd4, 0xf0, 0x45, 0xff, 0xfe, 0x0c, 0x66, 0x4b,
    0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    // ** ICMPv6 Header
    // type
    0x86,
    // code
    0x00,
    // checksum
    0xf5, 0x0c,
    // current hop limit
    0x40,
    // flags
    0x58,
    // router lifetime
    0x07, 0x08,
    // reachable time
    0x00,0x00, 0x08, 0x07,
    // retrans timer
    0x00,0x00, 0x05, 0xdc,
    // MTU option with invalid length
    0x05, 0x08, 0x00, 0x00, 0x00, 0x00, 0x05, 0xdc,
];

#[cfg(test)]
#[rustfmt::skip]
const UNDEFINED_OPTION: [u8;78] = [
    // ** ethernet Header
    0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
    0x86, 0xDD,
    // ** IPv6 Header
    0x60, 0x00, 0x00, 0x00,
    // payload length
    0x00, 0x18,
    0x3a,
    0xff,
    0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd4, 0xf0, 0x45, 0xff, 0xfe, 0x0c, 0x66, 0x4b,
    0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    // ** ICMPv6 Header
    // type
    0x86,
    // code
    0x00,
    // checksum
    0xf5, 0x0c,
    // current hop limit
    0x40,
    // flags
    0x58,
    // router lifetime
    0x07, 0x08,
    // reachable time
    0x00,0x00, 0x08, 0x07,
    // retrans timer
    0x00,0x00, 0x05, 0xdc,
    // unknown/undefined NDP option
    0x07, 0x01, 0x00, 0x00, 0x00, 0x00, 0x05, 0xdc,
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packets::icmp::v6::ndp::NdpPacket;
    use crate::packets::icmp::v6::{Icmpv6Message, Icmpv6Parse};
    use crate::packets::ip::v6::Ipv6;
    use crate::packets::{Ethernet, Packet};

    #[nb2::test]
    fn invalid_ndp_option_length() {
        let packet = Mbuf::from_bytes(&INVALID_OPTION_LENGTH).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();
        let ipv6 = ethernet.parse::<Ipv6>().unwrap();

        if let Ok(Icmpv6Message::RouterAdvertisement(advert)) = ipv6.parse_icmpv6() {
            assert!(advert.options().next().is_err());
        } else {
            panic!("bad packet");
        }
    }

    #[nb2::test]
    fn undefined_ndp_option() {
        let packet = Mbuf::from_bytes(&UNDEFINED_OPTION).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();
        let ipv6 = ethernet.parse::<Ipv6>().unwrap();

        if let Ok(Icmpv6Message::RouterAdvertisement(advert)) = ipv6.parse_icmpv6() {
            let mut undefined = false;
            let mut iter = advert.options();
            while let Ok(Some(option)) = iter.next() {
                if let NdpOptions::Undefined(option_type, length) = option {
                    assert_eq!(7, option_type);
                    assert_eq!(1, length);
                    undefined = true;
                }
            }

            assert!(undefined);
        } else {
            panic!("bad packet");
        }
    }
}

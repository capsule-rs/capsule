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

//! Neighbor Discovery Protocol
//!
//! NDP is a protocol used in IPv6, using ICMPv6 messages and operates at
//! the link layer of the Internet model, as per [`IETF RFC 4861`]. It
//! defines three mechanisms:
//!
//! - Substitute of ARP for use in IPv6 domains.
//! - Stateless auto-configuration, allowing nodes on the local link to
//!   configure their IPv6 addresses by themselves.
//! - Router redirection to IPv6 nodes
//!
//! [`IETF RFC 4861`]: https://tools.ietf.org/html/rfc4861

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

use crate::packets::Packet;
use failure::Fallible;

/// A trait for common NDP accessors.
pub trait NdpPacket: Packet {
    /// Returns the buffer offset where the options begin.
    fn options_offset(&self) -> usize;

    /// Returns an iterator that iterates through the options in the NDP packet.
    fn options(&self) -> NdpOptionsIterator<'_> {
        let mbuf = self.mbuf();
        let offset = self.options_offset();
        NdpOptionsIterator::new(mbuf, offset)
    }

    /// Pushes a new option to the NDP message.
    fn push_option<T: NdpOption>(&mut self) -> Fallible<T> {
        T::do_push(self.mbuf_mut())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::MacAddr;
    use crate::packets::icmp::v6::ndp::NdpOptions;
    use crate::packets::ip::v6::Ipv6;
    use crate::packets::{Ethernet, Packet};
    use crate::testils::byte_arrays::ROUTER_ADVERT_PACKET;
    use crate::Mbuf;
    use fallible_iterator::FallibleIterator;
    use std::str::FromStr;

    #[capsule::test]
    fn find_source_link_layer_address() {
        let packet = Mbuf::from_bytes(&ROUTER_ADVERT_PACKET).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();
        let ipv6 = ethernet.parse::<Ipv6>().unwrap();
        let mut advert = ipv6.parse::<RouterAdvertisement<Ipv6>>().unwrap();

        let mut source_link_address: LinkLayerAddress = advert.push_option().unwrap();
        source_link_address.set_addr(MacAddr::from_str("70:3a:cb:1b:f9:7a").unwrap());
        source_link_address.set_option_type_source();

        let mut slla_found = false;
        let mut iter = advert.options();
        while let Ok(Some(option)) = iter.next() {
            if let NdpOptions::SourceLinkLayerAddress(addr) = option {
                assert_eq!(1, addr.length());
                assert_eq!("70:3a:cb:1b:f9:7a", addr.addr().to_string());
                slla_found = true;
            }
        }

        assert!(slla_found);
    }

    #[capsule::test]
    fn add_source_link_layer_address() {
        let mac_addr = MacAddr::from_str("01:00:00:00:00:00").unwrap();
        let raw_packet = Mbuf::new().unwrap();
        let eth = raw_packet.push::<Ethernet>().unwrap();
        let ipv6 = eth.push::<Ipv6>().unwrap();
        let mut advert = ipv6.push::<RouterAdvertisement<Ipv6>>().unwrap();

        let mut option: LinkLayerAddress = advert.push_option().unwrap();
        option.set_addr(mac_addr);
        option.set_option_type_source();

        let mut iter = advert.options();

        while let Ok(Some(option_parse)) = iter.next() {
            if let NdpOptions::SourceLinkLayerAddress(option_type) = option_parse {
                assert_eq!(option_type.addr(), mac_addr);
            } else {
                panic!("Option was not source link layer address");
            }
        }
    }
}

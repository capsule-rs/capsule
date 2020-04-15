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

use crate::packets::icmp::v6::ndp::NdpPayload;
use crate::packets::icmp::v6::{Icmpv6, Icmpv6Packet, Icmpv6Payload, Icmpv6Type, Icmpv6Types};
use crate::packets::ip::v6::Ipv6Packet;
use crate::{Icmpv6Packet, SizeOf};
use std::fmt;

const M_FLAG: u8 = 0b1000_0000;
const O_FLAG: u8 = 0b0100_0000;

/// Router Advertisement Message defined in [`IETF RFC 4861`].
///
/// ```
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Type      |     Code      |          Checksum             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | Cur Hop Limit |M|O|  Reserved |       Router Lifetime         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                         Reachable Time                        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                          Retrans Timer                        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   Options ...
/// +-+-+-+-+-+-+-+-+-+-+-+-
/// ```
///
/// - *Cur Hop Limit*:              8-bit unsigned integer. The default value
///                                 that should be placed in the Hop Count field
///                                 of the IP header for outgoing IP packets. A
///                                 value of zero means unspecified (by this
///                                 router).
///
/// - *M*:                          1-bit "Managed address configuration" flag.
///                                 When set, it indicates that addresses are
///                                 available via Dynamic Host Configuration
///                                 Protocol (DHCPv6). *Note*: If the M flag is
///                                 set, the O flag is redundant and can be
///                                 ignored because DHCPv6 will return all
///                                 available configuration information.
///
/// - *O*:                          1-bit "Other configuration" flag. When set,
///                                 it indicates that other configuration
///                                 information is available via DHCPv6.
///                                 Examples of such information are DNS-related
///                                 information or information on other servers
///                                 within the network.
///
/// Note: If neither M nor O flags are set, this indicates that no
///         information is available via DHCPv6.
///
/// - *Reserved*                    A 6-bit unused field. It *MUST* be
///                                 initialized to zero by the sender and
///                                 *MUST* be ignored by the receiver.
///
/// - *Router Lifetime*:            16-bit unsigned integer. The lifetime
///                                 associated with the default router in units
///                                 of seconds. The field can contain values up
///                                 to 65535 and receivers should handle any
///                                 value, while the sending rules in Section 6
///                                 limit the lifetime to 9000 seconds. A
///                                 Lifetime of 0 indicates that the router is
///                                 not a default router and *SHOULD NOT* appear
///                                 on the default router list. The Router
///                                 Lifetime applies only to the router's
///                                 usefulness as a default router; it does not
///                                 apply to information contained in other
///                                 message fields or options. Options that need
///                                 time limits for their information include
///                                 their own lifetime fields.
///
/// - *Reachable Time*:             32-bit unsigned integer. The time, in
///                                 milliseconds, that a node assumes a neighbor
///                                 is reachable after having received a
///                                 reachability confirmation. Used by the
///                                 Neighbor Unreachability Detection algorithm
///                                 (see Section 7.3).  A value of zero means
///                                 unspecified (by this router).
///
/// - *Retrans Timer*:              32-bit unsigned integer.  The time, in
///                                 milliseconds, between retransmitted Neighbor
///                                 Solicitation messages.  Used by address
///                                 resolution and the Neighbor Unreachability
///                                 Detection algorithm (see Sections 7.2
///                                 and 7.3).  A value of zero means unspecified
///                                 (by this router).
///
/// Possible options:
///
/// - *Source link-layer address*:  The link-layer address of the interface from
///                                 which the Router Advertisement is sent. Only
///                                 used on link layers that have addresses. A
///                                 router MAY omit this option in order to
///                                 enable inbound load sharing across multiple
///                                 link-layer addresses.
///
/// - *MTU*:                        *SHOULD* be sent on links that have a
///                                 variable MTU (as specified in the document
///                                 that describes how to run IP over the
///                                 particular link type). *MAY* be sent on
///                                 other links.
///
/// - *Prefix Information*:         These options specify the prefixes that are
///                                 on-link and/or are used for stateless
///                                 address auto-configuration. A router *SHOULD*
///                                 include all its on-link prefixes (except the
///                                 link-local prefix) so that multihomed hosts
///                                 have complete prefix information about
///                                 on-link destinations for the links to which
///                                 they attach. If complete information is
///                                 lacking, a host with multiple interfaces may
///                                 not be able to choose the correct outgoing
///                                 interface when sending traffic to its
///                                 neighbors.
///
/// The fields are accessible through [`Icmpv6<E, RouterAdvertisement>`].
///
/// [`IETF RFC 4861`]: https://tools.ietf.org/html/rfc4861#section-4.2
/// [`Icmpv6<E, RouterAdvertisement>`]: Icmpv6
#[derive(Clone, Copy, Debug, Default, Icmpv6Packet, SizeOf)]
#[repr(C, packed)]
pub struct RouterAdvertisement {
    current_hop_limit: u8,
    flags: u8,
    router_lifetime: u16,
    reachable_time: u32,
    retrans_timer: u32,
}

impl Icmpv6Payload for RouterAdvertisement {
    #[inline]
    fn msg_type() -> Icmpv6Type {
        Icmpv6Types::RouterAdvertisement
    }
}

impl NdpPayload for RouterAdvertisement {}

impl<E: Ipv6Packet> Icmpv6<E, RouterAdvertisement> {
    /// Returns the current hop limit.
    #[inline]
    pub fn current_hop_limit(&self) -> u8 {
        self.payload().current_hop_limit
    }

    /// Sets the current hop limit.
    #[inline]
    pub fn set_current_hop_limit(&mut self, current_hop_limit: u8) {
        self.payload_mut().current_hop_limit = current_hop_limit;
    }

    /// Returns a flag indicating that addresses are available via DHCPv6.
    #[inline]
    pub fn managed_addr_cfg(&self) -> bool {
        self.payload().flags & M_FLAG != 0
    }

    /// Sets the managed address flag.
    #[inline]
    pub fn set_managed_addr_cfg(&mut self) {
        self.payload_mut().flags |= M_FLAG;
    }

    /// Unsets the managed address flag.
    #[inline]
    pub fn unset_managed_addr_cfg(&mut self) {
        self.payload_mut().flags &= !M_FLAG;
    }

    /// Returns a flag indicating that other configuration information is
    /// available via DHCPv6.
    #[inline]
    pub fn other_cfg(&self) -> bool {
        self.payload().flags & O_FLAG != 0
    }

    /// Sets the other configuration flag.
    #[inline]
    pub fn set_other_cfg(&mut self) {
        self.payload_mut().flags |= O_FLAG;
    }

    /// Unsets the other configuration flag.
    #[inline]
    pub fn unset_other_cfg(&mut self) {
        self.payload_mut().flags &= !O_FLAG;
    }

    /// Returns the lifetime associated with the default router in units
    /// of seconds.
    #[inline]
    pub fn router_lifetime(&self) -> u16 {
        u16::from_be(self.payload().router_lifetime)
    }

    /// Sets the router's default lifetime.
    #[inline]
    pub fn set_router_lifetime(&mut self, router_lifetime: u16) {
        self.payload_mut().router_lifetime = u16::to_be(router_lifetime);
    }

    /// Returns the time, in milliseconds, that a node assumes a neighbor
    /// is reachable.
    #[inline]
    pub fn reachable_time(&self) -> u32 {
        u32::from_be(self.payload().reachable_time)
    }

    /// Sets the neighbor reachable time.
    #[inline]
    pub fn set_reachable_time(&mut self, reachable_time: u32) {
        self.payload_mut().reachable_time = u32::to_be(reachable_time);
    }

    /// Returns the time, in milliseconds, between retransmitted Neighbor
    /// Solicitation messages.
    #[inline]
    pub fn retrans_timer(&self) -> u32 {
        u32::from_be(self.payload().retrans_timer)
    }

    /// Sets the retransmission timer.
    #[inline]
    pub fn set_retrans_timer(&mut self, retrans_timer: u32) {
        self.payload_mut().retrans_timer = u32::to_be(retrans_timer);
    }

    #[inline]
    fn fix_invariants(&mut self) {
        self.compute_checksum();
    }
}

impl<E: Ipv6Packet> fmt::Debug for Icmpv6<E, RouterAdvertisement> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("router advertisement")
            .field("type", &format!("{}", self.msg_type()))
            .field("code", &self.code())
            .field("checksum", &format!("0x{:04x}", self.checksum()))
            .field("current_hop_limit", &self.current_hop_limit())
            .field("managed_addr_cfg", &self.managed_addr_cfg())
            .field("other_cfg", &self.other_cfg())
            .field("router_lifetime", &self.router_lifetime())
            .field("reachable_time", &self.reachable_time())
            .field("retrans_timer", &self.retrans_timer())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::MacAddr;
    use crate::packets::icmp::v6::ndp::{LinkLayerAddress, NdpOptions, NdpPacket};
    use crate::packets::icmp::v6::{Icmpv6Message, Icmpv6Parse, Icmpv6Types};
    use crate::packets::ip::v6::Ipv6;
    use crate::packets::{Ethernet, Packet};
    use crate::testils::byte_arrays::ROUTER_ADVERT_PACKET;
    use crate::{Mbuf, SizeOf};
    use fallible_iterator::FallibleIterator;
    use std::str::FromStr;

    #[test]
    fn size_of_router_advertisement() {
        assert_eq!(12, RouterAdvertisement::size_of());
    }

    #[capsule::test]
    fn parse_router_advertisement_packet() {
        let packet = Mbuf::from_bytes(&ROUTER_ADVERT_PACKET).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();
        let ipv6 = ethernet.parse::<Ipv6>().unwrap();

        if let Ok(Icmpv6Message::RouterAdvertisement(advert)) = ipv6.parse_icmpv6() {
            assert_eq!(Icmpv6Types::RouterAdvertisement, advert.msg_type());
            assert_eq!(0, advert.code());
            assert_eq!(0xf50c, advert.checksum());
            assert_eq!(64, advert.current_hop_limit());
            assert!(!advert.managed_addr_cfg());
            assert!(advert.other_cfg());
            assert_eq!(3600, advert.router_lifetime());
            assert_eq!(0, advert.reachable_time());
            assert_eq!(0, advert.retrans_timer());
        } else {
            panic!("bad packet");
        }
    }

    #[capsule::test]
    fn find_source_link_layer_address() {
        let packet = Mbuf::from_bytes(&ROUTER_ADVERT_PACKET).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();
        let ipv6 = ethernet.parse::<Ipv6>().unwrap();

        if let Ok(Icmpv6Message::RouterAdvertisement(mut advert)) = ipv6.parse_icmpv6() {
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
        } else {
            panic!("not a router advertisement packet");
        }
    }
}

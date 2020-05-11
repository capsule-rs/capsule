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

use super::NdpPacket;
use crate::packets::icmp::v6::{Icmpv6, Icmpv6Message, Icmpv6Packet, Icmpv6Type, Icmpv6Types};
use crate::packets::ip::v6::Ipv6Packet;
use crate::packets::types::{u16be, u32be};
use crate::packets::{Internal, Packet};
use crate::SizeOf;
use failure::Fallible;
use std::fmt;
use std::ptr::NonNull;

const M_FLAG: u8 = 0b1000_0000;
const O_FLAG: u8 = 0b0100_0000;

/// Router Advertisement Message defined in [IETF RFC 4861].
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
/// - *Cur Hop Limit*:  8-bit unsigned integer. The default value that
///                     should be placed in the Hop Count field of the IP
///                     header for outgoing IP packets. A value of zero
///                     means unspecified (by this router).
///
/// - *M*:              1-bit "Managed address configuration" flag. When
///                     set, it indicates that addresses are available via
///                     Dynamic Host Configuration Protocol DHCPv6.
///
/// - *O*:              1-bit "Other configuration" flag. When set, it
///                     indicates that other configuration information is
///                     available via DHCPv6.
///
/// Note: If neither M nor O flags are set, this indicates that no
/// information is available via DHCPv6.
///
/// - *Reserved*:       A 6-bit unused field. It MUST be initialized to
///                     zero by the sender and MUST be ignored by the
///                     receiver.
///
/// - *Router Lifetime*:
///                     16-bit unsigned integer. The lifetime associated
///                     with the default router in units of seconds.
///
/// - *Reachable Time*: 32-bit unsigned integer. The time, in
///                     milliseconds, that a node assumes a neighbor is
///                     reachable after having received a reachability
///                     confirmation.
///
/// - *Retrans Timer*:  32-bit unsigned integer. The time, in
///                     milliseconds, between retransmitted Neighbor
///                     Solicitation messages.
///
/// Possible options:
///
/// - *Source link-layer address*:
///                     The link-layer address of the interface from which
///                     the Router Advertisement is sent.
///
/// - *MTU*:            SHOULD be sent on links that have a variable MTU
///                     (as specified in the document that describes how to
///                     run IP over the particular link type). MAY be sent
///                     on other links.
///
/// - *Prefix Information*:
///                     These options specify the prefixes that are on-link
///                     and/or are used for stateless address
///                     autoconfiguration.
///
/// [IETF RFC 4861]: https://tools.ietf.org/html/rfc4861#section-4.2
#[derive(Icmpv6Packet)]
pub struct RouterAdvertisement<E: Ipv6Packet> {
    icmp: Icmpv6<E>,
    body: NonNull<RouterAdvertisementBody>,
}

impl<E: Ipv6Packet> RouterAdvertisement<E> {
    #[inline]
    fn body(&self) -> &RouterAdvertisementBody {
        unsafe { self.body.as_ref() }
    }

    #[inline]
    fn body_mut(&mut self) -> &mut RouterAdvertisementBody {
        unsafe { self.body.as_mut() }
    }

    /// Returns the current hop limit.
    #[inline]
    pub fn current_hop_limit(&self) -> u8 {
        self.body().current_hop_limit
    }

    /// Sets the current hop limit.
    #[inline]
    pub fn set_current_hop_limit(&mut self, current_hop_limit: u8) {
        self.body_mut().current_hop_limit = current_hop_limit;
    }

    /// Returns a flag indicating that addresses are available via DHCPv6.
    #[inline]
    pub fn managed_addr_cfg(&self) -> bool {
        self.body().flags & M_FLAG != 0
    }

    /// Sets the managed address flag.
    #[inline]
    pub fn set_managed_addr_cfg(&mut self) {
        self.body_mut().flags |= M_FLAG;
    }

    /// Unsets the managed address flag.
    #[inline]
    pub fn unset_managed_addr_cfg(&mut self) {
        self.body_mut().flags &= !M_FLAG;
    }

    /// Returns a flag indicating that other configuration information is
    /// available via DHCPv6.
    #[inline]
    pub fn other_cfg(&self) -> bool {
        self.body().flags & O_FLAG != 0
    }

    /// Sets the other configuration flag.
    #[inline]
    pub fn set_other_cfg(&mut self) {
        self.body_mut().flags |= O_FLAG;
    }

    /// Unsets the other configuration flag.
    #[inline]
    pub fn unset_other_cfg(&mut self) {
        self.body_mut().flags &= !O_FLAG;
    }

    /// Returns the lifetime associated with the default router in units
    /// of seconds.
    #[inline]
    pub fn router_lifetime(&self) -> u16 {
        self.body().router_lifetime.into()
    }

    /// Sets the router's default lifetime.
    #[inline]
    pub fn set_router_lifetime(&mut self, router_lifetime: u16) {
        self.body_mut().router_lifetime = router_lifetime.into();
    }

    /// Returns the time, in milliseconds, that a node assumes a neighbor
    /// is reachable.
    #[inline]
    pub fn reachable_time(&self) -> u32 {
        self.body().reachable_time.into()
    }

    /// Sets the neighbor reachable time.
    #[inline]
    pub fn set_reachable_time(&mut self, reachable_time: u32) {
        self.body_mut().reachable_time = reachable_time.into();
    }

    /// Returns the time, in milliseconds, between retransmitted Neighbor
    /// Solicitation messages.
    #[inline]
    pub fn retrans_timer(&self) -> u32 {
        self.body().retrans_timer.into()
    }

    /// Sets the retransmission timer.
    #[inline]
    pub fn set_retrans_timer(&mut self, retrans_timer: u32) {
        self.body_mut().retrans_timer = retrans_timer.into();
    }
}

impl<E: Ipv6Packet> fmt::Debug for RouterAdvertisement<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RouterAdvertisement")
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

impl<E: Ipv6Packet> Icmpv6Message for RouterAdvertisement<E> {
    type Envelope = E;

    #[inline]
    fn msg_type() -> Icmpv6Type {
        Icmpv6Types::RouterAdvertisement
    }

    #[inline]
    fn icmp(&self) -> &Icmpv6<Self::Envelope> {
        &self.icmp
    }

    #[inline]
    fn icmp_mut(&mut self) -> &mut Icmpv6<Self::Envelope> {
        &mut self.icmp
    }

    #[inline]
    fn into_icmp(self) -> Icmpv6<Self::Envelope> {
        self.icmp
    }

    #[inline]
    unsafe fn clone(&self, internal: Internal) -> Self {
        RouterAdvertisement {
            icmp: self.icmp.clone(internal),
            body: self.body,
        }
    }

    #[inline]
    fn try_parse(icmp: Icmpv6<Self::Envelope>, _internal: Internal) -> Fallible<Self> {
        let mbuf = icmp.mbuf();
        let offset = icmp.payload_offset();
        let body = mbuf.read_data(offset)?;

        Ok(RouterAdvertisement { icmp, body })
    }

    #[inline]
    fn try_push(mut icmp: Icmpv6<Self::Envelope>, _internal: Internal) -> Fallible<Self> {
        let offset = icmp.payload_offset();
        let mbuf = icmp.mbuf_mut();

        mbuf.extend(offset, RouterAdvertisementBody::size_of())?;
        let body = mbuf.write_data(offset, &RouterAdvertisementBody::default())?;

        Ok(RouterAdvertisement { icmp, body })
    }
}

impl<E: Ipv6Packet> NdpPacket for RouterAdvertisement<E> {
    fn options_offset(&self) -> usize {
        self.payload_offset() + RouterAdvertisementBody::size_of()
    }
}

#[derive(Clone, Copy, Debug, Default, SizeOf)]
#[repr(C, packed)]
struct RouterAdvertisementBody {
    current_hop_limit: u8,
    flags: u8,
    router_lifetime: u16be,
    reachable_time: u32be,
    retrans_timer: u32be,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packets::ip::v6::Ipv6;
    use crate::packets::Ethernet;
    use crate::Mbuf;

    #[test]
    fn size_of_router_advertisement_body() {
        assert_eq!(12, RouterAdvertisementBody::size_of());
    }

    #[capsule::test]
    fn push_and_set_router_advertisement() {
        let packet = Mbuf::new().unwrap();
        let ethernet = packet.push::<Ethernet>().unwrap();
        let ipv6 = ethernet.push::<Ipv6>().unwrap();
        let mut advert = ipv6.push::<RouterAdvertisement<Ipv6>>().unwrap();

        assert_eq!(4, advert.header_len());
        assert_eq!(RouterAdvertisementBody::size_of(), advert.payload_len());
        assert_eq!(Icmpv6Types::RouterAdvertisement, advert.msg_type());
        assert_eq!(0, advert.code());

        advert.set_current_hop_limit(64);
        assert_eq!(64, advert.current_hop_limit());
        advert.set_managed_addr_cfg();
        assert!(advert.managed_addr_cfg());
        advert.unset_managed_addr_cfg();
        assert!(!advert.managed_addr_cfg());
        advert.set_other_cfg();
        assert!(advert.other_cfg());
        advert.unset_other_cfg();
        assert!(!advert.other_cfg());
        advert.set_router_lifetime(3600);
        assert_eq!(3600, advert.router_lifetime());
        advert.set_reachable_time(300);
        assert_eq!(300, advert.reachable_time());
        advert.set_retrans_timer(60);
        assert_eq!(60, advert.retrans_timer());

        advert.reconcile_all();
        assert!(advert.checksum() != 0);
    }
}

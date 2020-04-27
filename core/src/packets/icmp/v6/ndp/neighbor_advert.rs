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
use crate::packets::{Internal, Packet};
use crate::SizeOf;
use failure::Fallible;
use std::fmt;
use std::net::Ipv6Addr;
use std::ptr::NonNull;

/// Masks.
const R_FLAG: u8 = 0b1000_0000;
const S_FLAG: u8 = 0b0100_0000;
const O_FLAG: u8 = 0b0010_0000;

/// Neighbor Advertisement Message defined in [`IETF RFC 4861`].
///
/// ```
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Type      |     Code      |          Checksum             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |R|S|O|                     Reserved                            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |            Target Address (128 bits IPv6 address)             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   Options ...
/// +-+-+-+-+-+-+-+-+-+-+-+-
/// ```
///
/// - *R*:                          Router flag. When set, the R-bit
///                                 indicates that the sender is a router.
///                                 The R-bit is used by Neighbor
///                                 Unreachability Detection to detect a
///                                 router that changes to a host.
///
/// - *S*:                          Solicited flag. When set, the S-bit
///                                 indicates that the advertisement was sent in
///                                 response to a Neighbor Solicitation from the
///                                 Destination address. The S-bit is used as a
///                                 reachability confirmation for Neighbor
///                                 Unreachability Detection. It *MUST NOT*
///                                 be set in multicast advertisements or in
///                                 unsolicited unicast advertisements.
///
/// - *O*:                          Override flag. When set, the O-bit
///                                 indicates that the advertisement should
///                                 override an existing cache entry and update
///                                 the cached link-layer address. When it is
///                                 not set the advertisement will not update a
///                                 cached link-layer address though it will
///                                 update an existing Neighbor Cache entry for
///                                 which no link-layer address is known. It
///                                 *SHOULD NOT* be set in solicited
///                                 advertisements for anycast addresses and in
///                                 solicited proxy advertisements. It *SHOULD*
///                                 be set in other solicited advertisements and
///                                 in unsolicited advertisements.
///
/// - *Reserved*:                   29-bit unused field. It *MUST* be
///                                 initialized to zero by the sender and *MUST*
///                                 be ignored by the receiver.
///
/// - *Target Address*:             For solicited advertisements, the Target
///                                 Address field in the Neighbor Solicitation
///                                 message that prompted this advertisement.
///                                 For an unsolicited advertisement, the
///                                 address whose link-layer address has changed.
///                                 The Target Address *MUST NOT* be a
///                                 multicast address.
///
/// Possible options:
///
/// - *Target link-layer address*:  The link-layer address for the target, i.e.,
///                                 the sender of the advertisement. This
///                                 option *MUST* be included on link layers
///                                 that have addresses when responding to
///                                 multicast solicitations. When responding to
///                                 a unicast Neighbor Solicitation this option
///                                 *SHOULD* be included.
///
/// [`IETF RFC 4861`]: https://tools.ietf.org/html/rfc4861#section-4.4
#[derive(Icmpv6Packet)]
pub struct NeighborAdvertisement<E: Ipv6Packet> {
    icmp: Icmpv6<E>,
    body: NonNull<NeighborAdvertisementBody>,
}

impl<E: Ipv6Packet> NeighborAdvertisement<E> {
    #[inline]
    fn body(&self) -> &NeighborAdvertisementBody {
        unsafe { self.body.as_ref() }
    }

    #[inline]
    fn body_mut(&mut self) -> &mut NeighborAdvertisementBody {
        unsafe { self.body.as_mut() }
    }

    /// Returns a flag indicating the sender is a router.
    #[inline]
    pub fn router(&self) -> bool {
        self.body().flags & R_FLAG != 0
    }

    /// Sets the router flag.
    #[inline]
    pub fn set_router(&mut self) {
        self.body_mut().flags |= R_FLAG;
    }

    /// Unsets the router flag.
    #[inline]
    pub fn unset_router(&mut self) {
        self.body_mut().flags &= !R_FLAG;
    }

    /// Returns a flag indicating the advertisement is sent in response to
    /// a solicitation message.
    #[inline]
    pub fn solicited(&self) -> bool {
        self.body().flags & S_FLAG != 0
    }

    /// Sets the solicited flag.
    #[inline]
    pub fn set_solicited(&mut self) {
        self.body_mut().flags |= S_FLAG;
    }

    /// Unsets the solicited flag.
    #[inline]
    pub fn unset_solicited(&mut self) {
        self.body_mut().flags &= !S_FLAG;
    }

    /// Returns a flag indicating the advertisement should override an
    /// existing cache entry.
    #[inline]
    pub fn r#override(&self) -> bool {
        self.body().flags & O_FLAG != 0
    }

    /// Sets the override flag.
    #[inline]
    pub fn set_override(&mut self) {
        self.body_mut().flags |= O_FLAG;
    }

    /// Unsets the override flag.
    #[inline]
    pub fn unset_override(&mut self) {
        self.body_mut().flags &= !O_FLAG;
    }

    /// Returns the target address.
    #[inline]
    pub fn target_addr(&self) -> Ipv6Addr {
        self.body().target_addr
    }

    /// Sets the target address.
    #[inline]
    pub fn set_target_addr(&mut self, target_addr: Ipv6Addr) {
        self.body_mut().target_addr = target_addr
    }
}

impl<E: Ipv6Packet> fmt::Debug for NeighborAdvertisement<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("neighbor advertisement")
            .field("type", &format!("{}", self.msg_type()))
            .field("code", &self.code())
            .field("checksum", &format!("0x{:04x}", self.checksum()))
            .field("router", &self.router())
            .field("solicited", &self.solicited())
            .field("override", &self.r#override())
            .field("target_addr", &self.target_addr())
            .finish()
    }
}

impl<E: Ipv6Packet> Icmpv6Message for NeighborAdvertisement<E> {
    type Envelope = E;

    #[inline]
    fn msg_type() -> Icmpv6Type {
        Icmpv6Types::NeighborAdvertisement
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
        NeighborAdvertisement {
            icmp: self.icmp.clone(internal),
            body: self.body,
        }
    }

    #[inline]
    fn try_parse(icmp: Icmpv6<Self::Envelope>, _internal: Internal) -> Fallible<Self> {
        let mbuf = icmp.mbuf();
        let offset = icmp.payload_offset();
        let body = mbuf.read_data(offset)?;

        Ok(NeighborAdvertisement { icmp, body })
    }

    #[inline]
    fn try_push(mut icmp: Icmpv6<Self::Envelope>, _internal: Internal) -> Fallible<Self> {
        let offset = icmp.payload_offset();
        let mbuf = icmp.mbuf_mut();

        mbuf.extend(offset, NeighborAdvertisementBody::size_of())?;
        let body = mbuf.write_data(offset, &NeighborAdvertisementBody::default())?;

        Ok(NeighborAdvertisement { icmp, body })
    }
}

impl<E: Ipv6Packet> NdpPacket for NeighborAdvertisement<E> {
    fn options_offset(&self) -> usize {
        self.payload_offset() + NeighborAdvertisementBody::size_of()
    }
}

#[derive(Clone, Copy, Debug, SizeOf)]
#[repr(C)]
struct NeighborAdvertisementBody {
    flags: u8,
    reserved1: u8,
    reserved2: u16,
    target_addr: Ipv6Addr,
}

impl Default for NeighborAdvertisementBody {
    fn default() -> Self {
        NeighborAdvertisementBody {
            flags: 0,
            reserved1: 0,
            reserved2: 0,
            target_addr: Ipv6Addr::UNSPECIFIED,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packets::ip::v6::Ipv6;
    use crate::packets::Ethernet;
    use crate::Mbuf;

    #[test]
    fn size_of_neighbor_advertisement_body() {
        assert_eq!(20, NeighborAdvertisementBody::size_of());
    }

    #[capsule::test]
    fn push_and_set_neighbor_advertisement() {
        let packet = Mbuf::new().unwrap();
        let ethernet = packet.push::<Ethernet>().unwrap();
        let ipv6 = ethernet.push::<Ipv6>().unwrap();
        let mut advert = ipv6.push::<NeighborAdvertisement<Ipv6>>().unwrap();

        assert_eq!(4, advert.header_len());
        assert_eq!(NeighborAdvertisementBody::size_of(), advert.payload_len());
        assert_eq!(Icmpv6Types::NeighborAdvertisement, advert.msg_type());
        assert_eq!(0, advert.code());

        advert.set_router();
        assert!(advert.router());
        advert.unset_router();
        assert!(!advert.router());
        advert.set_solicited();
        assert!(advert.solicited());
        advert.unset_solicited();
        assert!(!advert.solicited());
        advert.set_override();
        assert!(advert.r#override());
        advert.unset_override();
        assert!(!advert.r#override());
        advert.set_target_addr(Ipv6Addr::LOCALHOST);
        assert_eq!(Ipv6Addr::LOCALHOST, advert.target_addr());

        advert.reconcile_all();
        assert!(advert.checksum() != 0);
    }
}

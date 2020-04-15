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
use std::net::Ipv6Addr;

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
/// The fields are accessible through [`Icmpv6<E, NeighborAdvertisement>`].
///
/// [`IETF RFC 4861`]: https://tools.ietf.org/html/rfc4861#section-4.4
/// [`Icmpv6<E, NeighborAdvertisement>`]: Icmpv6
#[derive(Clone, Copy, Debug, Icmpv6Packet, SizeOf)]
#[repr(C)]
pub struct NeighborAdvertisement {
    flags: u8,
    reserved1: u8,
    reserved2: u16,
    target_addr: Ipv6Addr,
}

impl Default for NeighborAdvertisement {
    fn default() -> NeighborAdvertisement {
        NeighborAdvertisement {
            flags: 0,
            reserved1: 0,
            reserved2: 0,
            target_addr: Ipv6Addr::UNSPECIFIED,
        }
    }
}

impl Icmpv6Payload for NeighborAdvertisement {
    #[inline]
    fn msg_type() -> Icmpv6Type {
        Icmpv6Types::NeighborAdvertisement
    }
}

impl NdpPayload for NeighborAdvertisement {}

impl<E: Ipv6Packet> Icmpv6<E, NeighborAdvertisement> {
    /// Returns a flag indicating the sender is a router.
    #[inline]
    pub fn router(&self) -> bool {
        self.payload().flags & R_FLAG != 0
    }

    /// Sets the router flag.
    #[inline]
    pub fn set_router(&mut self) {
        self.payload_mut().flags |= R_FLAG;
    }

    /// Unsets the router flag.
    #[inline]
    pub fn unset_router(&mut self) {
        self.payload_mut().flags &= !R_FLAG;
    }

    /// Returns a flag indicating the advertisement is sent in response to
    /// a solicitation message.
    #[inline]
    pub fn solicited(&self) -> bool {
        self.payload().flags & S_FLAG != 0
    }

    /// Sets the solicited flag.
    #[inline]
    pub fn set_solicited(&mut self) {
        self.payload_mut().flags |= S_FLAG;
    }

    /// Unsets the solicited flag.
    #[inline]
    pub fn unset_solicited(&mut self) {
        self.payload_mut().flags &= !S_FLAG;
    }

    /// Returns a flag indicating the advertisement should override an
    /// existing cache entry.
    #[inline]
    pub fn r#override(&self) -> bool {
        self.payload().flags & O_FLAG != 0
    }

    /// Sets the override flag.
    #[inline]
    pub fn set_override(&mut self) {
        self.payload_mut().flags |= O_FLAG;
    }

    /// Unsets the override flag.
    #[inline]
    pub fn unset_override(&mut self) {
        self.payload_mut().flags &= !O_FLAG;
    }

    /// Returns the target address.
    #[inline]
    pub fn target_addr(&self) -> Ipv6Addr {
        self.payload().target_addr
    }

    /// Sets the target address.
    #[inline]
    pub fn set_target_addr(&mut self, target_addr: Ipv6Addr) {
        self.payload_mut().target_addr = target_addr
    }

    #[inline]
    fn fix_invariants(&mut self) {
        self.compute_checksum();
    }
}

impl<E: Ipv6Packet> fmt::Debug for Icmpv6<E, NeighborAdvertisement> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SizeOf;

    #[test]
    fn size_of_neighbor_advertisement() {
        assert_eq!(20, NeighborAdvertisement::size_of());
    }
}

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

use packets::icmp::v6::{Icmpv6, Icmpv6Packet, Icmpv6Payload, Icmpv6Type, Icmpv6Types, NdpPayload};
use packets::ip::v6::Ipv6Packet;
use std::fmt;
use std::net::Ipv6Addr;

/*  From https://tools.ietf.org/html/rfc4861#section-4.3
    Neighbor Solicitation Message Format

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Type      |     Code      |          Checksum             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                           Reserved                            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    +                                                               +
    |                                                               |
    +                       Target Address                          +
    |                                                               |
    +                                                               +
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |   Options ...
    +-+-+-+-+-+-+-+-+-+-+-+-

    Reserved        This field is unused.  It MUST be initialized to
                    zero by the sender and MUST be ignored by the
                    receiver.

    Target Address  The IP address of the target of the solicitation.
                    It MUST NOT be a multicast address.

    Possible options:

     Source link-layer address
                    The link-layer address for the sender.  MUST NOT be
                    included when the source IP address is the
                    unspecified address.  Otherwise, on link layers
                    that have addresses this option MUST be included in
                    multicast solicitations and SHOULD be included in
                    unicast solicitations.
*/

/// NDP neighbor solicitation message
#[derive(Debug)]
#[repr(C)]
pub struct NeighborSolicitation {
    reserved: u32,
    target_addr: Ipv6Addr,
}

impl Default for NeighborSolicitation {
    fn default() -> NeighborSolicitation {
        NeighborSolicitation {
            reserved: 0,
            target_addr: Ipv6Addr::UNSPECIFIED,
        }
    }
}

impl Icmpv6Payload for NeighborSolicitation {
    #[inline]
    fn msg_type() -> Icmpv6Type {
        Icmpv6Types::NeighborSolicitation
    }
}

impl NdpPayload for NeighborSolicitation {}

/// NDP neighbor solicitation packet
impl<E: Ipv6Packet> Icmpv6<E, NeighborSolicitation> {
    #[inline]
    pub fn reserved(&self) -> u32 {
        u32::from_be(self.payload().reserved)
    }

    #[inline]
    pub fn target_addr(&self) -> Ipv6Addr {
        self.payload().target_addr
    }

    #[inline]
    pub fn set_target_addr(&mut self, target_addr: Ipv6Addr) {
        self.payload_mut().target_addr = target_addr
    }
}

impl<E: Ipv6Packet> fmt::Display for Icmpv6<E, NeighborSolicitation> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "type: {}, code: {}, checksum: 0x{:04x}, reserved: {}, target address: {}",
            self.msg_type(),
            self.code(),
            self.checksum(),
            self.reserved(),
            self.target_addr()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use packets::Fixed;

    #[test]
    fn size_of_neighbor_solicitation() {
        assert_eq!(20, NeighborSolicitation::size());
    }
}

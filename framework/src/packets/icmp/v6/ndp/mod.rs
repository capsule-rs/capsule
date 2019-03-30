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

use packets::buffer;
use packets::icmp::v6::{Icmpv6, Icmpv6Packet, Icmpv6Payload, NdpOptionsIterator};
use packets::ip::v6::Ipv6Packet;
use packets::Packet;

pub mod neighbor_advert;
pub mod neighbor_solicit;
pub mod options;
pub mod router_advert;
pub mod router_solicit;

/// NDP message payload marker
pub trait NdpPayload: Icmpv6Payload {}

/// Common behaviors shared by NDP packets
///
/// NDP packets are also ICMPv6 packets.
pub trait NdpPacket<E: Ipv6Packet, P: NdpPayload>: Icmpv6Packet<E, P> {
    /// Returns an iterator that iterates through the options in the NDP packet
    fn options(&self) -> NdpOptionsIterator;
}

impl<E: Ipv6Packet, P: NdpPayload> NdpPacket<E, P> for Icmpv6<E, P>
where
    Icmpv6<E, P>: Icmpv6Packet<E, P>,
{
    fn options(&self) -> NdpOptionsIterator {
        let mbuf = self.mbuf();
        let offset = self.payload_offset() + P::size();
        NdpOptionsIterator::new(mbuf, offset)
    }
}

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

/// Router Solicitation Message defined in [`IETF RFC 4861`].
///
/// ```
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Type      |     Code      |          Checksum             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                            Reserved                           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   Options ...
/// +-+-+-+-+-+-+-+-+-+-+-+-
/// ```
///
/// - *Reserved*:                   This field is unused. It *MUST* be
///                                 initialized to zero by the sender and
///                                 *MUST* be ignored by the receiver.
///
/// Valid Options:
///
/// - *Source link-layer address*:  The link-layer address of the sender, if
///                                 known. *MUST NOT* be included if the
///                                 Source Address is the unspecified address.
///                                 Otherwise, it *SHOULD* be included on link
///                                 layers that have addresses.
///
/// The fields are accessible through [`Icmpv6<E, RouterSolicitation>`].
///
/// [`IETF RFC 4861`]: https://tools.ietf.org/html/rfc4861#section-4.1
/// [`Icmpv6<E, RouterSolicitation>`]: Icmpv6
#[derive(Clone, Copy, Debug, Default, Icmpv6Packet, SizeOf)]
#[repr(C, packed)]
pub struct RouterSolicitation {
    _reserved: u32,
}

impl Icmpv6Payload for RouterSolicitation {
    #[inline]
    fn msg_type() -> Icmpv6Type {
        Icmpv6Types::RouterSolicitation
    }
}

impl NdpPayload for RouterSolicitation {}

impl<E: Ipv6Packet> Icmpv6<E, RouterSolicitation> {
    #[inline]
    fn reconcile(&mut self) {
        self.compute_checksum();
    }
}

impl<E: Ipv6Packet> fmt::Debug for Icmpv6<E, RouterSolicitation> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("router solicit")
            .field("type", &format!("{}", self.msg_type()))
            .field("code", &self.code())
            .field("checksum", &format!("0x{:04x}", self.checksum()))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packets::icmp::v6::{Icmpv6Message, Icmpv6Parse, Icmpv6Types};
    use crate::packets::ip::v6::Ipv6;
    use crate::packets::{Ethernet, Packet};
    use crate::testils::byte_arrays::ROUTER_SOLICIT_PACKET;
    use crate::{Mbuf, SizeOf};

    #[test]
    fn size_of_router_solicitation() {
        assert_eq!(4, RouterSolicitation::size_of());
    }

    #[capsule::test]
    fn parse_router_solicitation_packet() {
        let packet = Mbuf::from_bytes(&ROUTER_SOLICIT_PACKET).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();
        let ipv6 = ethernet.parse::<Ipv6>().unwrap();

        if let Ok(Icmpv6Message::RouterSolicitation(solicit)) = ipv6.parse_icmpv6() {
            assert_eq!(Icmpv6Types::RouterSolicitation, solicit.msg_type());
        } else {
            panic!("bad packet");
        }
    }
}

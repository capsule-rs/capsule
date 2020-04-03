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
use crate::packets::Packet;
use crate::{Icmpv6Packet, Result, SizeOf};
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
/// [`IETF RFC 4861`]: https://tools.ietf.org/html/rfc4861#section-4.1
#[derive(Clone, Copy, Debug, Default, Icmpv6Packet, SizeOf)]
#[repr(C, packed)]
pub struct RouterSolicitation {
    reserved: u32,
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
    /// Unused field that must be initialized to zero by sender and ignored
    /// by the receiver.
    pub fn reserved(&self) -> u32 {
        u32::from_be(self.payload().reserved)
    }

    #[inline]
    fn cascade(&mut self) {
        self.compute_checksum();
        self.envelope_mut().cascade();
    }
}

impl<E: Ipv6Packet> fmt::Debug for Icmpv6<E, RouterSolicitation> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("router solicit")
            .field("type", &format!("{}", self.msg_type()))
            .field("code", &self.code())
            .field("checksum", &format!("0x{:04x}", self.checksum()))
            .field("reserved", &self.reserved())
            .finish()
    }
}

/// ICMPv6 Router Solicitation packet as byte-array.
#[cfg(any(test, feature = "testils"))]
#[cfg_attr(docsrs, doc(cfg(feature = "testils")))]
#[rustfmt::skip]
pub const ROUTER_SOLICIT_PACKET: [u8; 70] = [
    // ** ethernet header
    0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
    0x86, 0xDD,
    // ** IPv6 header
    0x60, 0x00, 0x00, 0x00,
    // payload length
    0x00, 0x10,
    0x3a,
    0xff,
    0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd4, 0xf0, 0x45, 0xff, 0xfe, 0x0c, 0x66, 0x4b,
    0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    // ** ICMPv6 header
    // type
    0x85,
    // code
    0x00,
    // checksum
    0xf5, 0x0c,
    // ** router solicitation message
    // reserved
    0x00, 0x00, 0x00, 0x00,
    // ** source link-layer address option
    0x01, 0x01, 0x70, 0x3a, 0xcb, 0x1b, 0xf9, 0x7a
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packets::icmp::v6::{Icmpv6Message, Icmpv6Parse, Icmpv6Types};
    use crate::packets::ip::v6::Ipv6;
    use crate::packets::{Ethernet, Packet};
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
            assert_eq!(0, solicit.reserved());
        } else {
            panic!("bad packet");
        }
    }
}

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
use crate::packets::types::u32be;
use crate::packets::{Internal, Packet};
use crate::SizeOf;
use failure::Fallible;
use std::fmt;
use std::net::Ipv6Addr;
use std::ptr::NonNull;

/// Neighbor Solicitation Message defined in [IETF RFC 4861].
///
/// ```
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Type      |     Code      |          Checksum             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                           Reserved                            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |            Target Address (128 bits IPv6 address)             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   Options ...
/// +-+-+-+-+-+-+-+-+-+-+-+-
/// ```
///
/// - *Reserved*:       This field is unused. It MUST be initialized to
///                     zero by the sender and MUST be ignored by the
///                     receiver.
///
/// - *Target Address*: The IP address of the target of the solicitation.
///                     It MUST NOT be a multicast address.
///
/// Possible options:
///
/// - *Source link-layer address*:
///                     The link-layer address for the sender.
///
/// [IETF RFC 4861]: https://tools.ietf.org/html/rfc4861#section-4.3
#[derive(Icmpv6Packet)]
pub struct NeighborSolicitation<E: Ipv6Packet> {
    icmp: Icmpv6<E>,
    body: NonNull<NeighborSolicitationBody>,
}

impl<E: Ipv6Packet> NeighborSolicitation<E> {
    #[inline]
    fn body(&self) -> &NeighborSolicitationBody {
        unsafe { self.body.as_ref() }
    }

    #[inline]
    fn body_mut(&mut self) -> &mut NeighborSolicitationBody {
        unsafe { self.body.as_mut() }
    }

    /// Returns the target address.
    #[inline]
    pub fn target(&self) -> Ipv6Addr {
        self.body().target
    }

    /// Sets the target address.
    #[inline]
    pub fn set_target(&mut self, target: Ipv6Addr) {
        self.body_mut().target = target
    }
}

impl<E: Ipv6Packet> fmt::Debug for NeighborSolicitation<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NeighborSolicitation")
            .field("type", &format!("{}", self.msg_type()))
            .field("code", &self.code())
            .field("checksum", &format!("0x{:04x}", self.checksum()))
            .field("target", &self.target())
            .finish()
    }
}

impl<E: Ipv6Packet> Icmpv6Message for NeighborSolicitation<E> {
    type Envelope = E;

    #[inline]
    fn msg_type() -> Icmpv6Type {
        Icmpv6Types::NeighborSolicitation
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
        NeighborSolicitation {
            icmp: self.icmp.clone(internal),
            body: self.body,
        }
    }

    #[inline]
    fn try_parse(icmp: Icmpv6<Self::Envelope>, _internal: Internal) -> Fallible<Self> {
        let mbuf = icmp.mbuf();
        let offset = icmp.payload_offset();
        let body = mbuf.read_data(offset)?;

        Ok(NeighborSolicitation { icmp, body })
    }

    #[inline]
    fn try_push(mut icmp: Icmpv6<Self::Envelope>, _internal: Internal) -> Fallible<Self> {
        let offset = icmp.payload_offset();
        let mbuf = icmp.mbuf_mut();

        mbuf.extend(offset, NeighborSolicitationBody::size_of())?;
        let body = mbuf.write_data(offset, &NeighborSolicitationBody::default())?;

        Ok(NeighborSolicitation { icmp, body })
    }
}

impl<E: Ipv6Packet> NdpPacket for NeighborSolicitation<E> {
    fn options_offset(&self) -> usize {
        self.payload_offset() + NeighborSolicitationBody::size_of()
    }
}

#[derive(Clone, Copy, Debug, SizeOf)]
#[repr(C)]
struct NeighborSolicitationBody {
    reserved: u32be,
    target: Ipv6Addr,
}

impl Default for NeighborSolicitationBody {
    fn default() -> Self {
        NeighborSolicitationBody {
            reserved: u32be::default(),
            target: Ipv6Addr::UNSPECIFIED,
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
    fn size_of_neighbor_solicitation_body() {
        assert_eq!(20, NeighborSolicitationBody::size_of());
    }

    #[capsule::test]
    fn push_and_set_neighbor_solicitation() {
        let packet = Mbuf::new().unwrap();
        let ethernet = packet.push::<Ethernet>().unwrap();
        let ipv6 = ethernet.push::<Ipv6>().unwrap();
        let mut solicit = ipv6.push::<NeighborSolicitation<Ipv6>>().unwrap();

        assert_eq!(4, solicit.header_len());
        assert_eq!(NeighborSolicitationBody::size_of(), solicit.payload_len());
        assert_eq!(Icmpv6Types::NeighborSolicitation, solicit.msg_type());
        assert_eq!(0, solicit.code());

        solicit.set_target(Ipv6Addr::LOCALHOST);
        assert_eq!(Ipv6Addr::LOCALHOST, solicit.target());

        solicit.reconcile_all();
        assert!(solicit.checksum() != 0);
    }
}

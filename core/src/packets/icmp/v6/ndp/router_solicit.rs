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
use std::ptr::NonNull;

/// Router Solicitation Message defined in [IETF RFC 4861].
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
/// - *Reserved*:       This field is unused. It MUST be initialized to
///                     zero by the sender and MUST be ignored by the
///                     receiver.
/// Valid Options:
///
/// - *Source link-layer address*:
///                     The link-layer address of the sender, if known.
///
/// [IETF RFC 4861]: https://tools.ietf.org/html/rfc4861#section-4.1
#[derive(Icmpv6Packet)]
pub struct RouterSolicitation<E: Ipv6Packet> {
    icmp: Icmpv6<E>,
    body: NonNull<RouterSolicitationBody>,
}

impl<E: Ipv6Packet> fmt::Debug for RouterSolicitation<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RouterSolicitation")
            .field("type", &format!("{}", self.msg_type()))
            .field("code", &self.code())
            .field("checksum", &format!("0x{:04x}", self.checksum()))
            .finish()
    }
}

impl<E: Ipv6Packet> Icmpv6Message for RouterSolicitation<E> {
    type Envelope = E;

    #[inline]
    fn msg_type() -> Icmpv6Type {
        Icmpv6Types::RouterSolicitation
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
        RouterSolicitation {
            icmp: self.icmp.clone(internal),
            body: self.body,
        }
    }

    #[inline]
    fn try_parse(icmp: Icmpv6<Self::Envelope>, _internal: Internal) -> Fallible<Self> {
        let mbuf = icmp.mbuf();
        let offset = icmp.payload_offset();
        let body = mbuf.read_data(offset)?;

        Ok(RouterSolicitation { icmp, body })
    }

    #[inline]
    fn try_push(mut icmp: Icmpv6<Self::Envelope>, _internal: Internal) -> Fallible<Self> {
        let offset = icmp.payload_offset();
        let mbuf = icmp.mbuf_mut();

        mbuf.extend(offset, RouterSolicitationBody::size_of())?;
        let body = mbuf.write_data(offset, &RouterSolicitationBody::default())?;

        Ok(RouterSolicitation { icmp, body })
    }
}

impl<E: Ipv6Packet> NdpPacket for RouterSolicitation<E> {
    fn options_offset(&self) -> usize {
        self.payload_offset() + RouterSolicitationBody::size_of()
    }
}

#[derive(Clone, Copy, Debug, Default, SizeOf)]
#[repr(C, packed)]
struct RouterSolicitationBody {
    _reserved: u32be,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packets::ip::v6::Ipv6;
    use crate::packets::Ethernet;
    use crate::Mbuf;

    #[test]
    fn size_of_router_solicitation_body() {
        assert_eq!(4, RouterSolicitationBody::size_of());
    }

    #[capsule::test]
    fn push_and_set_router_solicitation() {
        let packet = Mbuf::new().unwrap();
        let ethernet = packet.push::<Ethernet>().unwrap();
        let ipv6 = ethernet.push::<Ipv6>().unwrap();
        let mut solicit = ipv6.push::<RouterSolicitation<Ipv6>>().unwrap();

        assert_eq!(4, solicit.header_len());
        assert_eq!(RouterSolicitationBody::size_of(), solicit.payload_len());
        assert_eq!(Icmpv6Types::RouterSolicitation, solicit.msg_type());
        assert_eq!(0, solicit.code());

        solicit.reconcile_all();
        assert!(solicit.checksum() != 0);
    }
}

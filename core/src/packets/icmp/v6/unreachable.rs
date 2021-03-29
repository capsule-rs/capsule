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

use crate::packets::icmp::v6::{Icmpv6, Icmpv6Message, Icmpv6Packet, Icmpv6Type, Icmpv6Types};
use crate::packets::ip::v6::{Ipv6Packet, IPV6_MIN_MTU};
use crate::packets::types::u32be;
use crate::packets::{Internal, Packet, SizeOf};
use anyhow::Result;
use std::fmt;
use std::ptr::NonNull;

/// Destination Unreachable Message defined in [IETF RFC 4443].
///
/// ```
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Type      |     Code      |          Checksum             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                             Unused                            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                    As much of invoking packet                 |
/// +               as possible without the ICMPv6 packet           +
/// |               exceeding the minimum IPv6 MTU [IPv6]           |
/// ```
///
/// [IETF RFC 4443]: https://tools.ietf.org/html/rfc4443#section-3.1
#[derive(Icmpv6Packet)]
pub struct DestinationUnreachable<E: Ipv6Packet> {
    icmp: Icmpv6<E>,
    body: NonNull<DestinationUnreachableBody>,
}

impl<E: Ipv6Packet> DestinationUnreachable<E> {
    /// Returns the invoking packet as a `u8` slice.
    #[inline]
    pub fn data(&self) -> &[u8] {
        let offset = self.payload_offset() + DestinationUnreachableBody::size_of();
        let len = self.payload_len() - DestinationUnreachableBody::size_of();

        if let Ok(data) = self.icmp().mbuf().read_data_slice(offset, len) {
            unsafe { &*data.as_ptr() }
        } else {
            &[]
        }
    }
}

impl<E: Ipv6Packet> fmt::Debug for DestinationUnreachable<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DestinationUnreachable")
            .field("type", &format!("{}", self.msg_type()))
            .field("code", &self.code())
            .field("checksum", &format!("0x{:04x}", self.checksum()))
            .field("$offset", &self.offset())
            .field("$len", &self.len())
            .field("$header_len", &self.header_len())
            .finish()
    }
}

impl<E: Ipv6Packet> Icmpv6Message for DestinationUnreachable<E> {
    type Envelope = E;

    #[inline]
    fn msg_type() -> Icmpv6Type {
        Icmpv6Types::DestinationUnreachable
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
        DestinationUnreachable {
            icmp: self.icmp.clone(internal),
            body: self.body,
        }
    }

    /// Parses the ICMPv6 packet's payload as destination unreachable.
    ///
    /// # Errors
    ///
    /// Returns an error if the payload does not have sufficient data for
    /// the destination unreachable message body.
    #[inline]
    fn try_parse(icmp: Icmpv6<Self::Envelope>, _internal: Internal) -> Result<Self> {
        let mbuf = icmp.mbuf();
        let offset = icmp.payload_offset();
        let body = mbuf.read_data(offset)?;

        Ok(DestinationUnreachable { icmp, body })
    }

    /// Prepends a new destination unreachable message to the beginning of the ICMPv6's
    /// payload.
    ///
    /// # Errors
    ///
    /// Returns an error if the buffer does not have enough free space.
    #[inline]
    fn try_push(mut icmp: Icmpv6<Self::Envelope>, _internal: Internal) -> Result<Self> {
        let offset = icmp.payload_offset();
        let mbuf = icmp.mbuf_mut();

        mbuf.extend(offset, DestinationUnreachableBody::size_of())?;
        let body = mbuf.write_data(offset, &DestinationUnreachableBody::default())?;

        Ok(DestinationUnreachable { icmp, body })
    }

    /// Reconciles the derivable header fields against the changes made to
    /// the packet.
    ///
    /// * the whole packet is truncated so it doesn't exceed the [minimum
    /// IPv6 MTU].
    /// * [`checksum`] is computed based on the pseudo-header and the
    /// `DestinationUnreachable` message.
    ///
    /// [minimum IPv6 MTU]: IPV6_MIN_MTU
    /// [`checksum`]: Icmpv6::checksum
    #[inline]
    fn reconcile(&mut self) {
        let _ = self.envelope_mut().truncate(IPV6_MIN_MTU);
        self.icmp_mut().compute_checksum();
    }
}

#[derive(Clone, Copy, Debug, Default, SizeOf)]
#[repr(C, packed)]
struct DestinationUnreachableBody {
    _unused: u32be,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packets::ethernet::Ethernet;
    use crate::packets::ip::v6::Ipv6;
    use crate::packets::Mbuf;
    use crate::testils::byte_arrays::IPV6_TCP_PACKET;

    #[test]
    fn size_of_destination_unreachable_body() {
        assert_eq!(4, DestinationUnreachableBody::size_of());
    }

    #[capsule::test]
    fn push_and_set_destination_unreachable() {
        let packet = Mbuf::from_bytes(&IPV6_TCP_PACKET).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();
        let ipv6 = ethernet.parse::<Ipv6>().unwrap();
        let tcp_len = ipv6.payload_len();

        let mut unreachable = ipv6.push::<DestinationUnreachable<Ipv6>>().unwrap();

        assert_eq!(4, unreachable.header_len());
        assert_eq!(
            DestinationUnreachableBody::size_of() + tcp_len,
            unreachable.payload_len()
        );
        assert_eq!(Icmpv6Types::DestinationUnreachable, unreachable.msg_type());
        assert_eq!(0, unreachable.code());
        assert_eq!(tcp_len, unreachable.data().len());

        unreachable.set_code(1);
        assert_eq!(1, unreachable.code());

        unreachable.reconcile_all();
        assert!(unreachable.checksum() != 0);
    }

    #[capsule::test]
    fn truncate_to_ipv6_min_mtu() {
        // starts with a buffer larger than min MTU.
        let packet = Mbuf::from_bytes(&[42; 1600]).unwrap();
        let ethernet = packet.push::<Ethernet>().unwrap();
        let ipv6 = ethernet.push::<Ipv6>().unwrap();

        // the max packet len is MTU + Ethernet header
        let max_len = IPV6_MIN_MTU + 14;

        let mut unreachable = ipv6.push::<DestinationUnreachable<Ipv6>>().unwrap();
        assert!(unreachable.mbuf().data_len() > max_len);

        unreachable.reconcile_all();
        assert_eq!(max_len, unreachable.mbuf().data_len());
    }
}

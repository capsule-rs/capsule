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
use crate::packets::{Internal, Packet};
use crate::SizeOf;
use failure::Fallible;
use std::fmt;
use std::ptr::NonNull;

/// Time Exceeded Message defined in [IETF RFC 4443].
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
/// [IETF RFC 4443]: https://tools.ietf.org/html/rfc4443#section-3.3
#[derive(Icmpv6Packet)]
pub struct TimeExceeded<E: Ipv6Packet> {
    icmp: Icmpv6<E>,
    body: NonNull<TimeExceededBody>,
}

impl<E: Ipv6Packet> TimeExceeded<E> {
    /// Returns the invoking packet as a `u8` slice.
    #[inline]
    pub fn data(&self) -> &[u8] {
        let offset = self.payload_offset() + TimeExceededBody::size_of();
        let len = self.payload_len() - TimeExceededBody::size_of();

        if let Ok(data) = self.icmp().mbuf().read_data_slice(offset, len) {
            unsafe { &*data.as_ptr() }
        } else {
            &[]
        }
    }
}

impl<E: Ipv6Packet> fmt::Debug for TimeExceeded<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TimeExceeded")
            .field("type", &format!("{}", self.msg_type()))
            .field("code", &self.code())
            .field("checksum", &format!("0x{:04x}", self.checksum()))
            .field("$offset", &self.offset())
            .field("$len", &self.len())
            .field("$header_len", &self.header_len())
            .finish()
    }
}

impl<E: Ipv6Packet> Icmpv6Message for TimeExceeded<E> {
    type Envelope = E;

    #[inline]
    fn msg_type() -> Icmpv6Type {
        Icmpv6Types::TimeExceeded
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
        TimeExceeded {
            icmp: self.icmp.clone(internal),
            body: self.body,
        }
    }

    #[inline]
    fn try_parse(icmp: Icmpv6<Self::Envelope>, _internal: Internal) -> Fallible<Self> {
        let mbuf = icmp.mbuf();
        let offset = icmp.payload_offset();
        let body = mbuf.read_data(offset)?;

        Ok(TimeExceeded { icmp, body })
    }

    #[inline]
    fn try_push(mut icmp: Icmpv6<Self::Envelope>, _internal: Internal) -> Fallible<Self> {
        let offset = icmp.payload_offset();
        let mbuf = icmp.mbuf_mut();

        mbuf.extend(offset, TimeExceededBody::size_of())?;
        let body = mbuf.write_data(offset, &TimeExceededBody::default())?;

        Ok(TimeExceeded { icmp, body })
    }

    /// Reconciles the derivable header fields against the changes made to
    /// the packet.
    ///
    /// * the whole packet is truncated so it doesn't exceed the [minimum
    /// IPv6 MTU].
    /// * [`checksum`] is computed based on the pseudo-header and the
    /// `TimeExceeded` message.
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
struct TimeExceededBody {
    _unused: u32be,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packets::ip::v6::Ipv6;
    use crate::packets::Ethernet;
    use crate::testils::byte_arrays::IPV6_TCP_PACKET;
    use crate::Mbuf;

    #[test]
    fn size_of_time_exceeded_body() {
        assert_eq!(4, TimeExceededBody::size_of());
    }

    #[capsule::test]
    fn push_and_set_time_exceeded() {
        let packet = Mbuf::from_bytes(&IPV6_TCP_PACKET).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();
        let ipv6 = ethernet.parse::<Ipv6>().unwrap();
        let tcp_len = ipv6.payload_len();

        let mut exceeded = ipv6.push::<TimeExceeded<Ipv6>>().unwrap();

        assert_eq!(4, exceeded.header_len());
        assert_eq!(
            TimeExceededBody::size_of() + tcp_len,
            exceeded.payload_len()
        );
        assert_eq!(Icmpv6Types::TimeExceeded, exceeded.msg_type());
        assert_eq!(0, exceeded.code());
        assert_eq!(tcp_len, exceeded.data().len());

        exceeded.set_code(1);
        assert_eq!(1, exceeded.code());

        exceeded.reconcile_all();
        assert!(exceeded.checksum() != 0);
    }

    #[capsule::test]
    fn truncate_to_ipv6_min_mtu() {
        // starts with a buffer larger than min MTU.
        let packet = Mbuf::from_bytes(&[42; 1600]).unwrap();
        let ethernet = packet.push::<Ethernet>().unwrap();
        let ipv6 = ethernet.push::<Ipv6>().unwrap();

        // the max packet len is MTU + Ethernet header
        let max_len = IPV6_MIN_MTU + 14;

        let mut exceeded = ipv6.push::<TimeExceeded<Ipv6>>().unwrap();
        assert!(exceeded.mbuf().data_len() > max_len);

        exceeded.reconcile_all();
        assert_eq!(max_len, exceeded.mbuf().data_len());
    }
}

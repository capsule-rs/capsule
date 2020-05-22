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

use crate::packets::icmp::v4::{Icmpv4, Icmpv4Message, Icmpv4Packet, Icmpv4Type, Icmpv4Types};
use crate::packets::ip::v4::IPV4_MIN_MTU;
use crate::packets::types::u32be;
use crate::packets::{Internal, Packet};
use crate::SizeOf;
use failure::Fallible;
use std::fmt;
use std::ptr::NonNull;

/// Time Exceeded Message defined in [IETF RFC 792].
///
/// ```
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Type      |     Code      |          Checksum             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                             Unused                            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |    Internet Header + 64 bits of Original Data Datagram        |
/// ```
///
/// [IETF RFC 792]: https://tools.ietf.org/html/rfc792
#[derive(Icmpv4Packet)]
pub struct TimeExceeded {
    icmp: Icmpv4,
    body: NonNull<TimeExceededBody>,
}

impl TimeExceeded {
    /// Returns the offset where the data field in the message body starts.
    #[inline]
    fn data_offset(&self) -> usize {
        self.payload_offset() + TimeExceededBody::size_of()
    }

    /// Returns the length of the data field in the message body.
    #[inline]
    fn data_len(&self) -> usize {
        self.payload_len() - TimeExceededBody::size_of()
    }

    /// Returns the invoking packet as a `u8` slice.
    #[inline]
    pub fn data(&self) -> &[u8] {
        if let Ok(data) = self
            .icmp()
            .mbuf()
            .read_data_slice(self.data_offset(), self.data_len())
        {
            unsafe { &*data.as_ptr() }
        } else {
            &[]
        }
    }
}

impl fmt::Debug for TimeExceeded {
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

impl Icmpv4Message for TimeExceeded {
    #[inline]
    fn msg_type() -> Icmpv4Type {
        Icmpv4Types::TimeExceeded
    }

    #[inline]
    fn icmp(&self) -> &Icmpv4 {
        &self.icmp
    }

    #[inline]
    fn icmp_mut(&mut self) -> &mut Icmpv4 {
        &mut self.icmp
    }

    #[inline]
    fn into_icmp(self) -> Icmpv4 {
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
    fn try_parse(icmp: Icmpv4, _internal: Internal) -> Fallible<Self> {
        let mbuf = icmp.mbuf();
        let offset = icmp.payload_offset();
        let body = mbuf.read_data(offset)?;

        Ok(TimeExceeded { icmp, body })
    }

    #[inline]
    fn try_push(mut icmp: Icmpv4, _internal: Internal) -> Fallible<Self> {
        let offset = icmp.payload_offset();
        let mbuf = icmp.mbuf_mut();

        mbuf.extend(offset, TimeExceededBody::size_of())?;
        let body = mbuf.write_data(offset, &TimeExceededBody::default())?;

        Ok(TimeExceeded { icmp, body })
    }

    /// Reconciles the derivable header fields against the changes made to
    /// the packet.
    ///
    /// * the data field in the message body is trimmed if it exceeds the
    /// [minimum IPV4 MTU], as we only need enough for port information.
    /// * [`checksum`] is computed based on the `TimeExceeded` message.
    ///
    /// [minimum IPv4 MTU]: IPV4_MIN_MTU
    /// [`checksum`]: Icmpv4::checksum
    #[inline]
    fn reconcile(&mut self) {
        let len = self.data_len();
        let offset = self.data_offset();

        if len > IPV4_MIN_MTU {
            let _ = self
                .mbuf_mut()
                .shrink(offset + IPV4_MIN_MTU, len - IPV4_MIN_MTU);
        }

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
    use crate::packets::ip::v4::Ipv4;
    use crate::packets::Ethernet;
    use crate::testils::byte_arrays::IPV4_TCP_PACKET;
    use crate::Mbuf;

    #[test]
    fn size_of_time_exceeded_body() {
        assert_eq!(4, TimeExceededBody::size_of());
    }

    #[capsule::test]
    fn push_and_set_time_exceeded() {
        let packet = Mbuf::from_bytes(&IPV4_TCP_PACKET).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();
        let ipv4 = ethernet.parse::<Ipv4>().unwrap();
        let tcp_len = ipv4.payload_len();

        let mut exceeded = ipv4.push::<TimeExceeded>().unwrap();

        assert_eq!(4, exceeded.header_len());
        assert_eq!(
            TimeExceededBody::size_of() + tcp_len,
            exceeded.payload_len()
        );
        assert_eq!(Icmpv4Types::TimeExceeded, exceeded.msg_type());
        assert_eq!(0, exceeded.code());
        assert_eq!(tcp_len, exceeded.data().len());

        exceeded.set_code(1);
        assert_eq!(1, exceeded.code());

        exceeded.reconcile_all();
        assert!(exceeded.checksum() != 0);
    }

    #[capsule::test]
    fn shrinks_to_ipv4_min_mtu() {
        // starts with a buffer with a message body larger than min MTU.
        let packet = Mbuf::from_bytes(&[42; 100]).unwrap();
        let ethernet = packet.push::<Ethernet>().unwrap();
        let ipv4 = ethernet.push::<Ipv4>().unwrap();
        let mut exceeded = ipv4.push::<TimeExceeded>().unwrap();
        assert!(exceeded.data_len() > IPV4_MIN_MTU);

        exceeded.reconcile_all();
        assert_eq!(IPV4_MIN_MTU, exceeded.data_len());
    }

    #[capsule::test]
    fn message_body_no_shrink() {
        // starts with a buffer with a message body smaller than min MTU.
        let packet = Mbuf::from_bytes(&[42; 50]).unwrap();
        let ethernet = packet.push::<Ethernet>().unwrap();
        let ipv4 = ethernet.push::<Ipv4>().unwrap();
        let mut exceeded = ipv4.push::<TimeExceeded>().unwrap();
        assert!(exceeded.data_len() < IPV4_MIN_MTU);

        exceeded.reconcile_all();
        assert_eq!(50, exceeded.data_len());
    }
}

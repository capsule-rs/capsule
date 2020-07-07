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
use crate::packets::{Internal, Packet};
use crate::SizeOf;
use failure::Fallible;
use std::fmt;
use std::net::Ipv4Addr;
use std::ptr::NonNull;

/// Redirect Message defined in [IETF RFC 792].
///
/// ```
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Type      |     Code      |          Checksum             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                 Gateway Internet Address                      |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |      Internet Header + 64 bits of Original Data Datagram      |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
/// *Type*: Identifier for redirect message = 5.
///
/// *Gateway Internet Address*: The ip address of the redirected gateway.
///
/// [IETF RFC 792]: https://tools.ietf.org/html/rfc792
#[derive(Icmpv4Packet)]
pub struct Redirect {
    icmp: Icmpv4,
    body: NonNull<RedirectBody>,
}

impl Redirect {
    #[inline]
    fn body(&self) -> &RedirectBody {
        unsafe { self.body.as_ref() }
    }

    #[inline]
    fn body_mut(&mut self) -> &mut RedirectBody {
        unsafe { self.body.as_mut() }
    }

    /// Returns the gateway ip address.
    #[inline]
    pub fn gateway(&self) -> Ipv4Addr {
        self.body().gateway
    }

    /// Sets the gateway ip address.
    #[inline]
    pub fn set_gateway(&mut self, gateway: Ipv4Addr) {
        self.body_mut().gateway = gateway
    }

    #[inline]
    fn data_offset(&self) -> usize {
        self.payload_offset() + RedirectBody::size_of()
    }

    #[inline]
    fn data_len(&self) -> usize {
        self.payload_len() - RedirectBody::size_of()
    }

    /// Returns the data packet as a `u8` slice.
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

impl fmt::Debug for Redirect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Redirect")
            .field("type", &format!("{}", self.msg_type()))
            .field("code", &self.code())
            .field("checksum", &format!("0x{:04x}", self.checksum()))
            .field("$offset", &self.offset())
            .field("$len", &self.len())
            .field("$header_len", &self.header_len())
            .field("gateway", &self.gateway())
            .finish()
    }
}

impl Icmpv4Message for Redirect {
    #[inline]
    fn msg_type() -> Icmpv4Type {
        Icmpv4Types::Redirect
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
        Redirect {
            icmp: self.icmp.clone(internal),
            body: self.body,
        }
    }

    #[inline]
    fn try_parse(icmp: Icmpv4, _internal: Internal) -> Fallible<Self> {
        let mbuf = icmp.mbuf();
        let offset = icmp.payload_offset();
        let body = mbuf.read_data(offset)?;

        Ok(Redirect { icmp, body })
    }

    #[inline]
    fn try_push(mut icmp: Icmpv4, _internal: Internal) -> Fallible<Self> {
        let offset = icmp.payload_offset();
        let mbuf = icmp.mbuf_mut();

        mbuf.extend(offset, RedirectBody::size_of())?;
        let body = mbuf.write_data(offset, &RedirectBody::default())?;

        Ok(Redirect { icmp, body })
    }

    /// Reconciles the derivable header fields against the changes made to
    /// the packet.
    ///
    /// * the data field in the message body is trimmed if it exceeds the
    /// [minimum IPV4 MTU].
    /// * [`checksum`] is computed based on the `Redirect` message.
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

/// The ICMPv4 Redirect message body.
///
/// This contains only the fixed portion of the message body.
#[derive(Clone, Copy, Debug, SizeOf)]
#[repr(C, packed)]
struct RedirectBody {
    gateway: Ipv4Addr,
}

impl Default for RedirectBody {
    fn default() -> Self {
        RedirectBody {
            gateway: Ipv4Addr::UNSPECIFIED,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packets::ip::v4::Ipv4;
    use crate::packets::Ethernet;
    use crate::testils::byte_arrays::IPV4_TCP_PACKET;
    use crate::Mbuf;

    #[test]
    fn size_of_redirect_body() {
        assert_eq!(4, RedirectBody::size_of());
    }

    #[capsule::test]
    fn push_and_set_redirect() {
        let packet = Mbuf::from_bytes(&IPV4_TCP_PACKET).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();
        let ipv4 = ethernet.parse::<Ipv4>().unwrap();
        let tcp_len = ipv4.payload_len();

        let mut redirect = ipv4.push::<Redirect>().unwrap();

        assert_eq!(4, redirect.header_len());
        assert_eq!(RedirectBody::size_of() + tcp_len, redirect.payload_len());

        assert_eq!(Icmpv4Types::Redirect, redirect.msg_type());
        assert_eq!(0, redirect.code());
        assert_eq!(tcp_len, redirect.data().len());

        redirect.set_code(1);
        assert_eq!(1, redirect.code());

        redirect.set_gateway(Ipv4Addr::LOCALHOST);
        assert_eq!(Ipv4Addr::LOCALHOST, redirect.gateway());

        redirect.reconcile_all();
        assert!(redirect.checksum() != 0);
    }

    #[capsule::test]
    fn shrinks_to_ipv4_min_mtu() {
        // starts with buffer larger than min MTU of 68 bytes.
        let packet = Mbuf::from_bytes(&[42; 100]).unwrap();
        let ethernet = packet.push::<Ethernet>().unwrap();
        let ipv4 = ethernet.push::<Ipv4>().unwrap();
        let mut redirect = ipv4.push::<Redirect>().unwrap();
        assert!(redirect.data_len() > IPV4_MIN_MTU);

        redirect.reconcile_all();
        assert_eq!(IPV4_MIN_MTU, redirect.data_len());
    }

    #[capsule::test]
    fn message_body_no_shrink() {
        // starts with buffer smaller than min MTU of 68 bytes.
        let packet = Mbuf::from_bytes(&[42; 50]).unwrap();
        let ethernet = packet.push::<Ethernet>().unwrap();
        let ipv4 = ethernet.push::<Ipv4>().unwrap();
        let mut redirect = ipv4.push::<Redirect>().unwrap();
        assert!(redirect.data_len() < IPV4_MIN_MTU);

        redirect.reconcile_all();
        assert_eq!(50, redirect.data_len());
    }
}

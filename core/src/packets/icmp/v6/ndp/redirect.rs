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

use super::{NdpPacket, RedirectedHeader};
use crate::packets::icmp::v6::{Icmpv6, Icmpv6Message, Icmpv6Packet, Icmpv6Type, Icmpv6Types};
use crate::packets::ip::v6::{Ipv6Packet, IPV6_MIN_MTU};
use crate::packets::types::u32be;
use crate::packets::{Internal, Packet};
use crate::SizeOf;
use failure::Fallible;
use std::fmt;
use std::net::Ipv6Addr;
use std::ptr::NonNull;

/// Redirect Message defined in [IETF RFC 4861].
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
/// |          Destination Address (128 bits IPv6 address)          |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   Options ...
/// +-+-+-+-+-+-+-+-+-+-+-+-
/// ```
///
/// - *Reserved*:       This field is unused. It MUST be initialized to
///                     zero by the sender and MUST be ignored by the
///                     receiver.
///
/// - *Target Address*: An IP address that is a better first hop to use for
///                     the ICMP Destination Address.
///
/// - *Destination Address*:
///                     The IP address of the destination which is
///                     redirected to the target.
///
/// Possible options:
///
/// - *Target link-layer address*:
///                     The link-layer address for the target. It SHOULD
///                     be included (if known).
///
/// - *Redirected Header*:
///                     As much as possible of the IP packet that triggered
///                     the sending of the Redirect without making the
///                     redirect packet exceed 1280 octets.
///
/// [IETF RFC 4861]: https://tools.ietf.org/html/rfc2461#section-4.5
#[derive(Icmpv6Packet)]
pub struct Redirect<E: Ipv6Packet> {
    icmp: Icmpv6<E>,
    body: NonNull<RedirectBody>,
}

impl<E: Ipv6Packet> Redirect<E> {
    #[inline]
    fn body(&self) -> &RedirectBody {
        unsafe { self.body.as_ref() }
    }

    #[inline]
    fn body_mut(&mut self) -> &mut RedirectBody {
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

    /// Returns the destination address.
    #[inline]
    pub fn destination(&self) -> Ipv6Addr {
        self.body().destination
    }

    /// Sets the destination address.
    #[inline]
    pub fn set_destination(&mut self, destination: Ipv6Addr) {
        self.body_mut().destination = destination
    }
}

impl<E: Ipv6Packet> fmt::Debug for Redirect<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Redirect")
            .field("type", &format!("{}", self.msg_type()))
            .field("code", &self.code())
            .field("checksum", &format!("0x{:04x}", self.checksum()))
            .field("target", &self.target())
            .field("destination", &self.destination())
            .finish()
    }
}

impl<E: Ipv6Packet> Icmpv6Message for Redirect<E> {
    type Envelope = E;

    #[inline]
    fn msg_type() -> Icmpv6Type {
        Icmpv6Types::Redirect
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
        Redirect {
            icmp: self.icmp.clone(internal),
            body: self.body,
        }
    }

    #[inline]
    fn try_parse(icmp: Icmpv6<Self::Envelope>, _internal: Internal) -> Fallible<Self> {
        let mbuf = icmp.mbuf();
        let offset = icmp.payload_offset();
        let body = mbuf.read_data(offset)?;

        Ok(Redirect { icmp, body })
    }

    #[inline]
    fn try_push(mut icmp: Icmpv6<Self::Envelope>, _internal: Internal) -> Fallible<Self> {
        let offset = icmp.payload_offset();
        let mbuf = icmp.mbuf_mut();

        mbuf.extend(offset, RedirectBody::size_of())?;
        let body = mbuf.write_data(offset, &RedirectBody::default())?;

        Ok(Redirect { icmp, body })
    }

    /// Reconciles the derivable header fields and options against the
    /// changes made to the packet.
    ///
    /// * the whole packet is truncated so it doesn't exceed the [minimum
    /// IPv6 MTU].
    /// * [`checksum`] is computed based on the pseudo-header and the
    /// `Redirect` message.
    /// * if a [`RedirectedHeader`] option is present, the option length
    /// is set to account for the original IP header and data.
    ///
    /// [minimum IPv6 MTU]: IPV6_MIN_MTU
    /// [`checksum`]: Icmpv6::checksum
    /// [`RedirectedHeader`]: RedirectedHeader
    #[inline]
    fn reconcile(&mut self) {
        let _ = self.envelope_mut().truncate(IPV6_MIN_MTU);

        let mut options = self.options_mut();
        let mut iter = options.iter();
        while let Ok(Some(mut option)) = iter.next() {
            if let Ok(mut header) = option.downcast::<RedirectedHeader<'_>>() {
                header.set_length();
                break;
            }
        }

        self.icmp_mut().compute_checksum();
    }
}

impl<E: Ipv6Packet> NdpPacket for Redirect<E> {
    fn options_offset(&self) -> usize {
        self.payload_offset() + RedirectBody::size_of()
    }
}

#[derive(Clone, Copy, Debug, SizeOf)]
#[repr(C)]
struct RedirectBody {
    reserved: u32be,
    target: Ipv6Addr,
    destination: Ipv6Addr,
}

impl Default for RedirectBody {
    fn default() -> Self {
        RedirectBody {
            reserved: u32be::default(),
            target: Ipv6Addr::UNSPECIFIED,
            destination: Ipv6Addr::UNSPECIFIED,
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
    fn size_of_redirect_body() {
        assert_eq!(36, RedirectBody::size_of());
    }

    #[capsule::test]
    fn push_and_set_redirect() {
        let packet = Mbuf::new().unwrap();
        let ethernet = packet.push::<Ethernet>().unwrap();
        let ipv6 = ethernet.push::<Ipv6>().unwrap();
        let mut redirect = ipv6.push::<Redirect<Ipv6>>().unwrap();

        assert_eq!(4, redirect.header_len());
        assert_eq!(RedirectBody::size_of(), redirect.payload_len());
        assert_eq!(Icmpv6Types::Redirect, redirect.msg_type());
        assert_eq!(0, redirect.code());

        redirect.set_target(Ipv6Addr::LOCALHOST);
        assert_eq!(Ipv6Addr::LOCALHOST, redirect.target());
        redirect.set_destination(Ipv6Addr::LOCALHOST);
        assert_eq!(Ipv6Addr::LOCALHOST, redirect.destination());

        redirect.reconcile_all();
        assert!(redirect.checksum() != 0);
    }

    #[capsule::test]
    fn truncate_to_ipv6_min_mtu() {
        // starts with a buffer larger than min MTU.
        let packet = Mbuf::from_bytes(&[42; 1600]).unwrap();
        let ethernet = packet.push::<Ethernet>().unwrap();
        let ipv6 = ethernet.push::<Ipv6>().unwrap();
        let mut redirect = ipv6.push::<Redirect<Ipv6>>().unwrap();
        let mut options = redirect.options_mut();
        let _ = options.prepend::<RedirectedHeader<'_>>().unwrap();

        // the max packet len is MTU + Ethernet header
        let max_len = IPV6_MIN_MTU + 14;
        assert!(redirect.mbuf().data_len() > max_len);

        redirect.reconcile_all();
        assert_eq!(max_len, redirect.mbuf().data_len());
    }
}

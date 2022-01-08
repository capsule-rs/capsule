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

//! IPv4 in IPv4 tunnel.

use crate::ensure;
use crate::packets::ethernet::Ethernet;
use crate::packets::ip::v4::Ipv4;
use crate::packets::ip::ProtocolNumbers;
use crate::packets::{Datalink, Packet, Tunnel};
use anyhow::{anyhow, Result};
use std::marker::PhantomData;

/// [IPv4] encapsulation within IPv4 based on [IETF RFC 2003].
///
/// IP in IP tunnel connects two separate IPv4 networks. an outer IP header
/// is inserted before the datagram's existing IP header, as follows:
///
///                                     +---------------------------+
///                                     |                           |
///                                     |      Outer IP Header      |
///                                     |                           |
/// +---------------------------+       +---------------------------+
/// |                           |       |                           |
/// |         IP Header         |       |         IP Header         |
/// |                           |       |                           |
/// +---------------------------+ ====> +---------------------------+
/// |                           |       |                           |
/// |                           |       |                           |
/// |         IP Payload        |       |         IP Payload        |
/// |                           |       |                           |
/// |                           |       |                           |
/// +---------------------------+       +---------------------------+
///
/// This tunnel only supports unicast packets.
///
/// [IPv4]: Ipv4
/// [IETF RFC 2003]: https://datatracker.ietf.org/doc/html/rfc2003
#[derive(Debug)]
pub struct IpIp<E: Datalink = Ethernet> {
    _phantom: PhantomData<E>,
}

impl<E: Datalink> Tunnel for IpIp<E> {
    type Payload = Ipv4<E>;
    type Delivery = Ipv4<E>;

    /// Encapsulates the existing IPv4 packet by prepending an outer IPv4
    /// packet.
    ///
    /// The DSCP and ECN options are copied from existing header to the new
    /// outer header.
    ///
    /// # Remarks
    ///
    /// If the 'don't fragment' flag is set to true on the outer header, it
    /// must not be unset. Otherwise, it may be set after tunnel encapsulation.
    ///
    /// # Errors
    ///
    /// Returns an error if the payload's time-to-live is `0`. The packet
    /// should be discarded.
    fn encap(payload: Self::Payload) -> Result<Self::Delivery> {
        ensure!(payload.ttl() != 0, anyhow!("payload's TTL is 0."));

        let dscp = payload.dscp();
        let ecn = payload.ecn();
        let dont_fragment = payload.dont_fragment();

        let envelope = payload.deparse();
        let mut delivery = envelope.push::<Self::Delivery>()?;
        delivery.set_dscp(dscp);
        delivery.set_ecn(ecn);
        if dont_fragment {
            delivery.set_dont_fragment();
        }
        delivery.set_protocol(ProtocolNumbers::Ipv4);
        delivery.reconcile_all();

        Ok(delivery)
    }

    /// Decapsulates the outer IPv4 packet and returns the original payload
    /// IPv4 packet.
    ///
    /// # Errors
    ///
    /// Returns an error if the protocol is not set to `ProtocolNumbers::Ipv4`,
    /// indicating the packet is not from an IpIp tunnel.
    fn decap(delivery: Self::Delivery) -> Result<Self::Payload> {
        ensure!(
            delivery.protocol() == ProtocolNumbers::Ipv4,
            anyhow!("not an IPIP tunnel.")
        );

        let envelope = delivery.remove()?;
        envelope.parse::<Self::Payload>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packets::ethernet::Ethernet;
    use crate::packets::icmp::v4::EchoRequest;
    use crate::packets::Mbuf;
    use crate::testils::byte_arrays::IPIP_PACKET;

    #[capsule::test]
    fn encap_ipip_payload() {
        let packet = Mbuf::new().unwrap();
        let ethernet = packet.push::<Ethernet>().unwrap();
        let ip4 = ethernet.push::<Ipv4>().unwrap();
        let mut ip4 = ip4.push::<EchoRequest>().unwrap().deparse();
        ip4.set_dscp(5);
        ip4.set_ecn(1);
        ip4.set_dont_fragment();
        ip4.reconcile();
        let payload_len = ip4.len();

        let delivery = ip4.encap::<IpIp>().unwrap();
        assert_eq!(5, delivery.dscp());
        assert_eq!(1, delivery.ecn());
        assert!(delivery.dont_fragment());
        assert_eq!(payload_len + 20, delivery.len());
    }

    #[capsule::test]
    fn encap_0ttl_payload() {
        let packet = Mbuf::new().unwrap();
        let ethernet = packet.push::<Ethernet>().unwrap();
        let ip4 = ethernet.push::<Ipv4>().unwrap();
        let mut ip4 = ip4.push::<EchoRequest>().unwrap().deparse();
        ip4.set_ttl(0);
        ip4.reconcile();

        assert!(ip4.encap::<IpIp>().is_err());
    }

    #[capsule::test]
    fn decap_ipip_delivery() {
        let packet = Mbuf::from_bytes(&IPIP_PACKET).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();
        let delivery = ethernet.parse::<Ipv4>().unwrap();
        let payload = delivery.decap::<IpIp>().unwrap();

        assert_eq!("1.1.1.1", payload.src().to_string());
        assert_eq!("2.2.2.2", payload.dst().to_string());

        // parse the payload's payload to verify packet integrity
        assert!(payload.parse::<EchoRequest>().is_ok());
    }

    #[capsule::test]
    fn decap_not_ipip() {
        let packet = Mbuf::new().unwrap();
        let ethernet = packet.push::<Ethernet>().unwrap();
        let ip4 = ethernet.push::<Ipv4>().unwrap();
        let notipip = ip4.push::<EchoRequest>().unwrap().deparse();

        // the protocol is icmpv4 not ipv4, not an ipip tunnel
        assert!(notipip.decap::<IpIp>().is_err());
    }
}

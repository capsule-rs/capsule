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

//! IPv6 in IPv4 tunnel.

use crate::ensure;
use crate::packets::ethernet::{EtherTypes, Ethernet};
use crate::packets::ip::v4::Ipv4;
use crate::packets::ip::v6::Ipv6;
use crate::packets::ip::ProtocolNumbers;
use crate::packets::{Datalink, Packet, Tunnel};
use anyhow::{anyhow, Result};
use std::marker::PhantomData;

/// [IPv6] encapsulation within [IPv4] based on [IETF RFC 4213].
///
/// An IPv4 compatibility mechanisms designed to be employed by IPv6 hosts
/// and routers that need to interoperate with IPv4 hosts and utilize IPv4
/// routing infrastructures.
///
/// ```
///                                              +-------------+
///                                              |    IPv4     |
///                                              |   Header    |
///              +-------------+                 +-------------+
///              |    IPv6     |                 |    IPv6     |
///              |   Header    |                 |   Header    |
///              +-------------+                 +-------------+
///              |  Transport  |                 |  Transport  |
///              |   Layer     |      ===>       |   Layer     |
///              |   Header    |                 |   Header    |
///              +-------------+                 +-------------+
///              |             |                 |             |
///              ~    Data     ~                 ~    Data     ~
///              |             |                 |             |
///              +-------------+                 +-------------+
/// ```
///
/// [IPv6]: Ipv6
/// [IPv4]: Ipv4
/// [IETF RFC 4213]: https://datatracker.ietf.org/doc/html/rfc4213
#[derive(Debug)]
pub struct Ip6in4<D: Datalink = Ethernet> {
    _phantom: PhantomData<D>,
}

impl<D: Datalink> Tunnel for Ip6in4<D> {
    type Payload = Ipv6<D>;
    type Delivery = Ipv4<D>;

    /// Encapsulates the existing IPv6 packet by prepending an outer IPv4
    /// packet.
    ///
    /// The DSCP and ECN options are copied from existing header to the new
    /// outer header.
    ///
    /// # Errors
    ///
    /// Returns an error if the payload's hop limit is `0`. The packet should
    /// be discarded.
    fn encap(payload: Self::Payload) -> Result<Self::Delivery> {
        ensure!(
            payload.hop_limit() != 0,
            anyhow!("payload's hop limit is 0.")
        );

        let dscp = payload.dscp();
        let ecn = payload.ecn();

        let envelope = payload.deparse();
        let mut delivery = envelope.push::<Self::Delivery>()?;
        delivery.set_dscp(dscp);
        delivery.set_ecn(ecn);
        delivery.set_protocol(ProtocolNumbers::Ipv6);
        delivery.reconcile_all();

        Ok(delivery)
    }

    /// Decapsulates the outer IPv4 packet and returns the original payload
    /// IPv6 packet.
    ///
    /// # Errors
    ///
    /// Returns an error if the protocol is not set to `ProtocolNumbers::Ipv6`,
    /// indicating the packet is not from an Ip6in4 tunnel.
    fn decap(delivery: Self::Delivery) -> Result<Self::Payload> {
        ensure!(
            delivery.protocol() == ProtocolNumbers::Ipv6,
            anyhow!("not an Ip6in4 tunnel.")
        );

        let mut envelope = delivery.remove()?;
        envelope.set_protocol_type(EtherTypes::Ipv6);
        envelope.parse::<Self::Payload>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packets::ethernet::Ethernet;
    use crate::packets::icmp::v6::EchoRequest;
    use crate::packets::Mbuf;
    use crate::testils::byte_arrays::{IP6IN4_PACKET, IPIP_PACKET};

    #[capsule::test]
    fn encap_ip6in4_payload() {
        let packet = Mbuf::new().unwrap();
        let ethernet = packet.push::<Ethernet>().unwrap();
        let ip6 = ethernet.push::<Ipv6>().unwrap();
        let mut ip6 = ip6.push::<EchoRequest>().unwrap().deparse();
        ip6.set_dscp(5);
        ip6.set_ecn(1);
        ip6.reconcile();
        let payload_len = ip6.len();

        let delivery = ip6.encap::<Ip6in4>().unwrap();
        assert_eq!(5, delivery.dscp());
        assert_eq!(1, delivery.ecn());

        // check payload matches original packet length
        assert_eq!(payload_len, delivery.payload_len());
    }

    #[capsule::test]
    fn encap_0_hop_limit_payload() {
        let packet = Mbuf::new().unwrap();
        let ethernet = packet.push::<Ethernet>().unwrap();
        let ip6 = ethernet.push::<Ipv6>().unwrap();
        let mut ip6 = ip6.push::<EchoRequest>().unwrap().deparse();
        ip6.set_hop_limit(0);
        ip6.reconcile();

        assert!(ip6.encap::<Ip6in4>().is_err());
    }

    #[capsule::test]
    fn decap_ip6in4_delivery() {
        let packet = Mbuf::from_bytes(&IP6IN4_PACKET).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();
        let delivery = ethernet.parse::<Ipv4>().unwrap();
        let payload = delivery.decap::<Ip6in4>().unwrap();

        assert_eq!("2001:db8:0:1::1", payload.src().to_string());
        assert_eq!("2001:db8:0:1::2", payload.dst().to_string());

        // parse the payload's payload to verify packet integrity
        assert!(payload.parse::<EchoRequest>().is_ok());
    }

    #[capsule::test]
    fn decap_not_ip6in4() {
        let packet = Mbuf::from_bytes(&IPIP_PACKET).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();
        let not6in4 = ethernet.parse::<Ipv4>().unwrap();

        // not an ip6in4 tunnel
        assert!(not6in4.decap::<Ip6in4>().is_err());
    }
}

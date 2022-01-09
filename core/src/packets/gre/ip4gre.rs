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

use crate::ensure;
use crate::packets::ethernet::Ethernet;
use crate::packets::gre::{Gre, GreTunnelPacket};
use crate::packets::ip::v4::Ipv4;
use crate::packets::ip::{IpPacket, ProtocolNumbers};
use crate::packets::{Datalink, Packet, Tunnel};
use anyhow::{anyhow, Result};
use std::marker::PhantomData;

/// Arbitrary layer 3 protocol encapsulated in IPv4 with GRE based on
/// [IETF RFC 2784].
///
/// The payload is first encapsulated in a GRE packet.  The resulting
/// GRE packet is then encapsulated in IPv4 and then forwarded.
///
/// [IETF RFC 2784]: https://datatracker.ietf.org/doc/html/rfc2784
/// [IPv4]: crate::packets::ip::v4::Ipv4
#[derive(Debug)]
pub struct Ip4Gre<P: Packet<Envelope = D>, D: Datalink = Ethernet> {
    _phantom1: PhantomData<P>,
    _phantom2: PhantomData<D>,
}

impl<P: Packet<Envelope = D>, D: Datalink> Tunnel for Ip4Gre<P, D> {
    type Payload = P;
    type Delivery = Ipv4<D>;

    /// Encapsulates the existing layer-3 packet by prepending an outer IPv4
    /// and a GRE packets.
    fn encap(payload: Self::Payload) -> Result<Self::Delivery> {
        let envelope = payload.deparse();
        let protocol_type = envelope.protocol_type();
        let ip4 = envelope.push::<Self::Delivery>()?;
        let mut gre = ip4.push::<Gre<Self::Delivery>>()?;
        gre.set_protocol_type(protocol_type);
        gre.reconcile_all();
        Ok(gre.deparse())
    }

    /// Decapsulates the outer IPv4 and GRE packets and returns the original
    /// layer-3 packet.
    fn decap(delivery: Self::Delivery) -> Result<Self::Payload> {
        ensure!(delivery.gre_payload(), anyhow!("not an Ip4Gre tunnel."));

        let gre = delivery.parse::<Gre<Self::Delivery>>()?;
        let protocol_type = gre.protocol_type();

        let mut envelope = gre.remove()?.remove()?;
        envelope.set_protocol_type(protocol_type);
        envelope.parse::<Self::Payload>()
    }
}

/// Generic impl for all IpPacket.
impl<T: IpPacket> GreTunnelPacket for T {
    fn gre_payload(&self) -> bool {
        self.next_protocol() == ProtocolNumbers::Gre
    }

    fn mark_gre_payload(&mut self) {
        self.set_next_protocol(ProtocolNumbers::Gre)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packets::ethernet::EtherTypes;
    use crate::packets::icmp::v4::EchoRequest;
    use crate::packets::icmp::v6::EchoReply;
    use crate::packets::ip::v6::Ipv6;
    use crate::packets::Mbuf;
    use crate::testils::byte_arrays::{IP4GRE_PACKET, IPIP_PACKET};

    #[capsule::test]
    fn encap_ip4gre_payload() {
        let packet = Mbuf::new().unwrap();
        let ethernet = packet.push::<Ethernet>().unwrap();
        let ip6 = ethernet.push::<Ipv6>().unwrap();
        let mut ip6 = ip6.push::<EchoReply>().unwrap().deparse();
        ip6.reconcile();
        let payload_len = ip6.len();

        let delivery = ip6.encap::<Ip4Gre<Ipv6>>().unwrap();
        assert_eq!(EtherTypes::Ipv4, delivery.envelope().protocol_type());
        assert_eq!(ProtocolNumbers::Gre, delivery.protocol());

        let gre = delivery.parse::<Gre<Ipv4>>().unwrap();
        assert_eq!(EtherTypes::Ipv6, gre.protocol_type());

        // check payload matches original packet length
        assert_eq!(payload_len, gre.payload_len());
    }

    #[capsule::test]
    fn decap_ip4gre_delivery() {
        let packet = Mbuf::from_bytes(&IP4GRE_PACKET).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();
        let delivery = ethernet.parse::<Ipv4>().unwrap();
        let payload = delivery.decap::<Ip4Gre<Ipv4>>().unwrap();

        assert_eq!("1.1.1.1", payload.src().to_string());
        assert_eq!("2.2.2.2", payload.dst().to_string());

        // parse the payload's payload to verify packet integrity
        assert!(payload.parse::<EchoRequest>().is_ok());
    }

    #[capsule::test]
    fn decap_not_ip4gre() {
        let packet = Mbuf::from_bytes(&IPIP_PACKET).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();
        let notip4gre = ethernet.parse::<Ipv4>().unwrap();

        // not an ip4gre tunnel
        assert!(notip4gre.decap::<Ip4Gre<Ipv4>>().is_err());
    }
}

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
use crate::packets::gtpu::{Gtpu, GtpuTunnelPacket, MessageTypes};
use crate::packets::ip::v4::Ipv4;
use crate::packets::udp::Udp;
use crate::packets::{Datalink, Packet, Tunnel};
use anyhow::{anyhow, Result};
use std::marker::PhantomData;

const GTPU_PORT: u16 = 2152;

/// Arbitrary layer 3 protocol encapsulated in IPv4 and UDP with GTP-U based on
/// [3GPP TS 29.281].
///
/// The payload is first encapsulated in a GRE packet.  The resulting
/// GRE packet is then encapsulated in UDP and IPv4 and then forwarded.
///
/// [3GPP TS 29.281]: https://www.etsi.org/deliver/etsi_ts/129200_129299/129281/15.07.00_60/ts_129281v150700p.pdf
/// [IPv4]: crate::packets::ip::v4::Ipv4
#[derive(Debug)]
pub struct Ip4Gtpu<P: Packet<Envelope = D>, D: Datalink = Ethernet> {
    _phantom1: PhantomData<P>,
    _phantom2: PhantomData<D>,
}

impl<P: Packet<Envelope = D>, D: Datalink> Tunnel for Ip4Gtpu<P, D> {
    type Payload = P;
    type Delivery = Udp<Ipv4<D>>;

    /// Encapsulates the existing layer-3 packet by prepending an outer IPv4,
    /// UDP and a GTP-U packet.
    fn encap(payload: Self::Payload) -> Result<Self::Delivery> {
        let envelope = payload.deparse();
        let ip4 = envelope.push::<Ipv4<D>>()?;
        let udp = ip4.push::<Self::Delivery>()?;
        let mut gtpu = udp.push::<Gtpu<Self::Delivery>>()?;
        gtpu.set_message_type(MessageTypes::PDU);
        gtpu.reconcile_all();
        Ok(gtpu.deparse())
    }

    /// Decapsulates the outer IPv4, UDP and GTP-U packets and returns the original
    /// layer-3 packet.
    fn decap(delivery: Self::Delivery) -> Result<Self::Payload> {
        ensure!(delivery.gtpu_payload(), anyhow!("not an Ip4Gtpu tunnel."));

        let gtpu = delivery.parse::<Gtpu<Self::Delivery>>()?;
        let message_type = gtpu.message_type();

        if message_type != MessageTypes::PDU {
            return Err(anyhow!(
                "Can only decapsulate payment from Message Type PDU - not {:?}",
                message_type
            ));
        }

        let envelope = gtpu.remove()?.remove()?.remove()?;
        envelope.parse::<Self::Payload>()
    }
}

/// Impl for all Udp<Ipv4>. Identifies GTP-U based on the src and dst
/// port numbers of the UDP wrapper being the well-known port 2152
impl<D: Datalink> GtpuTunnelPacket for Udp<Ipv4<D>> {
    fn gtpu_payload(&self) -> bool {
        self.src_port() == GTPU_PORT && self.dst_port() == GTPU_PORT
    }

    fn mark_gtpu_payload(&mut self) {
        self.set_src_port(GTPU_PORT);
        self.set_dst_port(GTPU_PORT);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packets::ethernet::EtherTypes;
    use crate::packets::icmp::v4::{EchoReply, EchoRequest};
    use crate::packets::ip::v4::Ipv4;
    use crate::packets::ip::ProtocolNumbers;
    use crate::packets::Mbuf;
    use crate::testils::byte_arrays::{IP4GTPU_PACKET, UDP4_PACKET};

    #[capsule::test]
    fn encap_ip4gtpu_payload() {
        let packet = Mbuf::new().unwrap();
        let ethernet = packet.push::<Ethernet>().unwrap();
        let ip4 = ethernet.push::<Ipv4>().unwrap();
        let mut ip4 = ip4.push::<EchoReply>().unwrap().deparse();
        ip4.reconcile();
        let payload_len = ip4.len();

        let transport = ip4.encap::<Ip4Gtpu<Ipv4>>().unwrap();

        let mut gtpu = transport.parse::<Gtpu<Udp<Ipv4>>>().unwrap();
        gtpu.set_sequence_number_present().unwrap();
        gtpu.set_sequence_number(1234);
        let transport = gtpu.deparse();

        assert_eq!(
            EtherTypes::Ipv4,
            transport.envelope().envelope().protocol_type()
        );
        assert_eq!(ProtocolNumbers::Udp, transport.envelope().protocol());
        assert_eq!(GTPU_PORT, transport.src_port());
        assert_eq!(GTPU_PORT, transport.dst_port());

        let gtpu = transport.parse::<Gtpu<Udp<Ipv4>>>().unwrap();
        assert_eq!(Some(1234), gtpu.sequence_number());

        // check payload matches original packet length
        assert_eq!(payload_len, gtpu.payload_len());
    }

    #[capsule::test]
    fn decap_ip4gtpu_delivery() {
        let packet = Mbuf::from_bytes(&IP4GTPU_PACKET).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();
        let delivery = ethernet.parse::<Ipv4>().unwrap();
        let transport = delivery.parse::<Udp<Ipv4>>().unwrap();
        let payload = transport.decap::<Ip4Gtpu<Ipv4>>().unwrap();

        assert_eq!("202.11.40.158", payload.src().to_string());
        assert_eq!("192.168.40.178", payload.dst().to_string());

        //parse the payload's payload to verify packet integrity
        assert!(payload.parse::<EchoRequest>().is_ok());
    }

    #[capsule::test]
    fn decap_not_ip4gtpu() {
        let packet = Mbuf::from_bytes(&UDP4_PACKET).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();
        let delivery = ethernet.parse::<Ipv4>().unwrap();
        let transport = delivery.parse::<Udp<Ipv4>>().unwrap();

        // not an ip4gtpu tunnel
        assert!(transport.decap::<Ip4Gtpu<Ipv4>>().is_err());
    }
}

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

use packets::buffer;
use packets::ip::v6::Ipv6Packet;
use packets::icmp::v6::{Icmpv6, Icmpv6Packet, Icmpv6Payload, NdpOption};

pub mod options;
pub mod router_advert;
pub mod router_solicit;

/// NDP message payload marker
pub trait NdpPayload: Icmpv6Payload {}

/// Common behaviors shared by NDP packets
/// 
/// NDP packets are also ICMPv6 packets.
pub trait NdpPacket<P: NdpPayload>: Icmpv6Packet<P> {
    /// finds a NDP option in the payload by option type
    fn find_option<O: NdpOption>(&self) -> Option<&mut O> {
        let payload_size = std::mem::size_of::<P>();
        let option_size = std::mem::size_of::<O>();

        unsafe {
            // options are after the fixed part of the payload
            let mut offset = self.payload_offset() + payload_size;
            let mut buffer_left = self.payload_len() - payload_size;

            while buffer_left > option_size {
                let mbuf = self.mbuf();
                let [option_type, length] = *(buffer::read_item::<[u8; 2]>(mbuf, offset).unwrap());

                if option_type == O::option_type() {
                    return Some(&mut (*(buffer::read_item::<O>(mbuf, offset).unwrap())))
                } else if length == 0 {
                    return None    // TODO: should we error?
                } else {
                    let length = (length * 8) as usize;
                    offset += length;
                    buffer_left -= length;
                }
            }

            None
        }
    }
}

impl<E: Ipv6Packet, P: NdpPayload> NdpPacket<P> for Icmpv6<E, P> where Icmpv6<E, P>: Icmpv6Packet<P> {}

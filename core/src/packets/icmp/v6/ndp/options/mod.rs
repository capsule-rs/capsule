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

mod link_layer_addr;
mod mtu;
mod prefix_info;

#[allow(unreachable_pub)] // https://github.com/rust-lang/rust/issues/57411
pub use self::link_layer_addr::*;
#[allow(unreachable_pub)]
pub use self::mtu::*;
#[allow(unreachable_pub)]
pub use self::prefix_info::*;

#[cfg(test)]
#[rustfmt::skip]
const UNDEFINED_OPTION: [u8;78] = [
    // ** ethernet Header
    0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
    0x86, 0xDD,
    // ** IPv6 Header
    0x60, 0x00, 0x00, 0x00,
    // payload length
    0x00, 0x18,
    0x3a,
    0xff,
    0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd4, 0xf0, 0x45, 0xff, 0xfe, 0x0c, 0x66, 0x4b,
    0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    // ** ICMPv6 Header
    // type
    0x86,
    // code
    0x00,
    // checksum
    0xf5, 0x0c,
    // current hop limit
    0x40,
    // flags
    0x58,
    // router lifetime
    0x07, 0x08,
    // reachable time
    0x00,0x00, 0x08, 0x07,
    // retrans timer
    0x00,0x00, 0x05, 0xdc,
    // unknown/undefined NDP option
    0x07, 0x01, 0x00, 0x00, 0x00, 0x00, 0x05, 0xdc,
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packets::icmp::v6::ndp::{NdpPacket, RouterAdvertisement};
    use crate::packets::ip::v6::Ipv6;
    use crate::packets::{Ethernet, Packet};

    #[capsule::test]
    fn undefined_ndp_option() {
        let packet = Mbuf::from_bytes(&UNDEFINED_OPTION).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();
        let ipv6 = ethernet.parse::<Ipv6>().unwrap();
        let advert = ipv6.parse::<RouterAdvertisement<Ipv6>>().unwrap();

        let mut undefined = false;
        let mut iter = advert.options();
        while let Ok(Some(option)) = iter.next() {
            if let NdpOptions::Undefined(option_type, length) = option {
                assert_eq!(7, option_type);
                assert_eq!(1, length);
                undefined = true;
            }
        }

        assert!(undefined);
    }
}

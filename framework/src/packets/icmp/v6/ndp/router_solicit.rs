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

use std::fmt;
use packets::icmp::v6::{Icmpv6, Icmpv6Packet, Icmpv6Payload, NdpPayload};

/*  From (https://tools.ietf.org/html/rfc4861#section-4.1)
    Router Solicitation Message Format

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Type      |     Code      |          Checksum             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                            Reserved                           |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |   Options ...
    +-+-+-+-+-+-+-+-+-+-+-+-

    Reserved       This field is unused.  It MUST be initialized to
                   zero by the sender and MUST be ignored by the
                   receiver.
    
   Valid Options:

    Source link-layer address
                   The link-layer address of the sender, if
                   known.  MUST NOT be included if the Source Address
                   is the unspecified address.  Otherwise, it SHOULD
                   be included on link layers that have addresses.
*/

/// router solicitation payload
#[derive(Default, Debug)]
#[repr(C, packed)]
pub struct RouterSolicitation {
    reserved: u32
}

impl NdpPayload for RouterSolicitation {}

impl Icmpv6Payload for RouterSolicitation {
    fn size() -> usize {
        4
    }
}

/// router solicitation packet
impl Icmpv6<RouterSolicitation> {
    #[inline]
    pub fn reserved(&self) -> u32 {
        u32::from_be(self.payload().reserved)
    }
}

impl fmt::Display for Icmpv6<RouterSolicitation> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "type: {} code: {} checksum: 0x{:04x} reserved: {}",
            self.msg_type(),
            self.code(),
            self.checksum(),
            self.reserved()
        )
    }
}

impl Icmpv6Packet<RouterSolicitation> for Icmpv6<RouterSolicitation> {
    fn payload(&self) -> &mut RouterSolicitation {
        unsafe { &mut (*self.payload) }
    }
}

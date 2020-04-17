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

use crate::packets::icmp::v6::{Icmpv6, Icmpv6Packet, Icmpv6Payload, Icmpv6Type, Icmpv6Types};
use crate::packets::ip::v6::{Ipv6Packet, IPV6_MIN_MTU};
use crate::packets::Packet;
use crate::{Icmpv6Packet, SizeOf};
use std::fmt;

/// Time Exceeded Message defined in [`IETF RFC 4443`].
///
/// ```
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Type      |     Code      |          Checksum             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                             Unused                            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                    As much of invoking packet                 |
/// +               as possible without the ICMPv6 packet           +
/// |               exceeding the minimum IPv6 MTU [IPv6]           |
/// ```
///
/// The fields are accessible through [`Icmpv6<E, TimeExceeded>`].
///
/// [`IETF RFC 4443`]: https://tools.ietf.org/html/rfc4443#section-3.3
/// [`Icmpv6<E, TimeExceeded>`]: Icmpv6
#[derive(Clone, Copy, Debug, Default, Icmpv6Packet, SizeOf)]
#[repr(C, packed)]
pub struct TimeExceeded {
    _unused: u32,
}

impl Icmpv6Payload for TimeExceeded {
    fn msg_type() -> Icmpv6Type {
        Icmpv6Types::TimeExceeded
    }
}

impl<E: Ipv6Packet> Icmpv6<E, TimeExceeded> {
    #[inline]
    fn reconcile(&mut self) {
        // keeps as much of the invoking packet without exceeding the
        // minimum MTU, and ignores the error if there's nothing to
        // truncate.
        let _ = self.envelope_mut().truncate(IPV6_MIN_MTU);
        self.compute_checksum();
    }
}

impl<E: Ipv6Packet> fmt::Debug for Icmpv6<E, TimeExceeded> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("icmpv6")
            .field("type", &format!("{}", self.msg_type()))
            .field("code", &self.code())
            .field("checksum", &format!("0x{:04x}", self.checksum()))
            .field("$offset", &self.offset())
            .field("$len", &self.len())
            .field("$header_len", &self.header_len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SizeOf;

    #[test]
    fn size_of_time_exceeded() {
        assert_eq!(4, TimeExceeded::size_of());
    }
}

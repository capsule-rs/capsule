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

//! Common checksum capabilities and computations for all packet types,
//! including calculation involving *pseudo headers*.

use crate::packets::ip::{IpPacketError, ProtocolNumber};
use failure::Fallible;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::slice;

/// Generic pseudo header used to calculate checksum.
#[derive(Debug)]
pub enum PseudoHeader {
    /// IPv4 pseudo header.
    V4 {
        /// Source address.
        src: Ipv4Addr,
        /// Destination address.
        dst: Ipv4Addr,
        /// Packet length.
        packet_len: u16,
        /// Next layer's protocol.
        protocol: ProtocolNumber,
    },
    /// IPv6 pseudo header.
    V6 {
        /// Source address.
        src: Ipv6Addr,
        /// Destination address.
        dst: Ipv6Addr,
        /// Packet length.
        packet_len: u16,
        /// Next layer's protocol.
        protocol: ProtocolNumber,
    },
}

impl PseudoHeader {
    /// Calculates the upper-layer checksum based on the psuedo header.
    pub fn sum(&self) -> u16 {
        let mut sum = match *self {
            PseudoHeader::V4 {
                src,
                dst,
                packet_len,
                protocol,
            } => v4_csum(src, dst, packet_len, protocol),
            PseudoHeader::V6 {
                src,
                dst,
                packet_len,
                protocol,
            } => v6_csum(src, dst, packet_len, protocol),
        };

        while sum >> 16 != 0 {
            sum = (sum >> 16) + (sum & 0xFFFF);
        }

        sum as u16
    }
}

/// Calculates the upper-layer checksum using the IPv4 psuedo-header.
///
/// ```
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                       Source Address                          |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                     Destination Address                       |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Zero      |    Protocol   |         Packet Length         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
fn v4_csum(src: Ipv4Addr, dst: Ipv4Addr, packet_len: u16, protocol: ProtocolNumber) -> u32 {
    let src: u32 = src.into();
    let dst: u32 = dst.into();

    (src >> 16)
        + (src & 0xFFFF)
        + (dst >> 16)
        + (dst & 0xFFFF)
        + u32::from(protocol.0)
        + u32::from(packet_len)
}

/// Calculates the upper-layer checksum using the IPv6 psuedo-header as
/// defined in [IETF RFC 2460].
///
/// ```
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |             Source Address (128 bits IPv6 address)            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |          Destination Address (128 bits IPv6 address)          |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                   Upper-Layer Packet Length                   |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                      Zero                     |  Next Header  |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// [IETF RFC 2460]: https://tools.ietf.org/html/rfc2460#section-8.1
fn v6_csum(src: Ipv6Addr, dst: Ipv6Addr, packet_len: u16, protocol: ProtocolNumber) -> u32 {
    src.segments().iter().fold(0, |acc, &x| acc + u32::from(x))
        + dst.segments().iter().fold(0, |acc, &x| acc + u32::from(x))
        + u32::from(packet_len)
        + u32::from(protocol.0)
}

/// Computes the Internet checksum as defined in [IETF RFC 1071].
///
/// 1. Adjacent octets to be checksummed are paired to form 16-bit integers,
/// and the 1's complement sum of these 16-bit integers is formed.
///
/// 2. To generate a checksum, the checksum field itself is cleared, the
/// 16-bit 1's complement sum is computed over the octets concerned, and the
/// 1's complement of this sum is placed in the checksum field.
///
/// 3. To check a checksum, the 1's complement sum is computed over the same
/// set of octets, including the checksum field.  If the result is all 1 bits
/// (-0 in 1's complement arithmetic), the check succeeds.
///
/// [IETF RFC 1071]: https://tools.ietf.org/html/rfc1071
#[allow(clippy::cast_ptr_alignment)]
pub fn compute(pseudo_header_sum: u16, payload: &[u8]) -> u16 {
    let len = payload.len();
    let mut data = payload;
    let mut checksum = u32::from(pseudo_header_sum);

    // odd # of bytes, we add the last byte with padding separately
    if len % 2 > 0 {
        checksum += u32::from(payload[len - 1]) << 8;
        data = &payload[..(len - 1)];
    }

    // a bit of unsafe magic to cast [u8] to [u16], and fix endianness later
    let data = unsafe { slice::from_raw_parts(data.as_ptr() as *const u16, len / 2) };

    checksum = data
        .iter()
        .fold(checksum, |acc, &x| acc + u32::from(u16::from_be(x)));

    while checksum >> 16 != 0 {
        checksum = (checksum >> 16) + (checksum & 0xFFFF);
    }

    !(checksum as u16)
}

/// Computes the Internet checksum via incremental update as defined in
/// [IETF RFC 1624].
///
/// Given the following notation:
/// * `HC`  - old checksum in header
/// * `HC'` - new checksum in header
/// * `m`   - old value of a 16-bit field
/// * `m'`  - new value of a 16-bit field
///
/// `HC' = ~(~HC + ~m + m')`
///
/// [IETF RFC 1624]: https://tools.ietf.org/html/rfc1624
pub fn compute_inc(old_checksum: u16, old_value: &[u16], new_value: &[u16]) -> u16 {
    let mut checksum = old_value
        .iter()
        .zip(new_value.iter())
        .fold(u32::from(!old_checksum), |acc, (&old, &new)| {
            acc + u32::from(!old) + u32::from(new)
        });

    while checksum >> 16 != 0 {
        checksum = (checksum >> 16) + (checksum & 0xFFFF);
    }

    !(checksum as u16)
}

/// Incrementally computes the new checksum for an IP address change.
pub fn compute_with_ipaddr(
    old_checksum: u16,
    old_value: &IpAddr,
    new_value: &IpAddr,
) -> Fallible<u16> {
    match (old_value, new_value) {
        (IpAddr::V4(old), IpAddr::V4(new)) => {
            let old: u32 = (*old).into();
            let old = [(old >> 16) as u16, (old & 0xFFFF) as u16];
            let new: u32 = (*new).into();
            let new = [(new >> 16) as u16, (new & 0xFFFF) as u16];
            Ok(compute_inc(old_checksum, &old, &new))
        }
        (IpAddr::V6(old), IpAddr::V6(new)) => {
            Ok(compute_inc(old_checksum, &old.segments(), &new.segments()))
        }
        _ => Err(IpPacketError::IpAddrMismatch.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_checksum_incrementally() {
        assert_eq!(0x0000, compute_inc(0xdd2f, &[0x5555], &[0x3285]));
    }
}

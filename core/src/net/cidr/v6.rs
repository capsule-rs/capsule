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

use super::{Cidr, CidrError};
use std::fmt;
use std::net::Ipv6Addr;
use std::str::FromStr;

const IPV6ADDR_BITS: usize = 128;

/// [CIDR] range for IPv6 addresses.
///
/// [CIDR]: https://tools.ietf.org/html/rfc4291#section-2.3
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct Ipv6Cidr {
    address: Ipv6Addr,
    mask: u128,
}

impl Ipv6Cidr {
    /// Iterate through CIDR range addresses.
    pub fn iter(self) -> Ipv6CidrIterator {
        Ipv6CidrIterator::new(self.network(), self.size())
    }

    #[inline]
    fn netmask_length(netmask: Ipv6Addr) -> Result<usize, CidrError> {
        let mask = u128::from(netmask);

        let length = (!mask).leading_zeros();
        if mask.leading_zeros() == 0 && mask.trailing_zeros() == mask.count_zeros() {
            Ok(length as usize)
        } else {
            Err(CidrError::InvalidPrefixLength)
        }
    }
}

impl Default for Ipv6Cidr {
    fn default() -> Ipv6Cidr {
        Ipv6Cidr {
            address: Ipv6Addr::UNSPECIFIED,
            mask: Default::default(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Ipv6CidrIterator {
    next: Option<u128>,
    end: u128,
}

impl Ipv6CidrIterator {
    fn new(start: Ipv6Addr, end: usize) -> Self {
        let start = u128::from(start);
        Ipv6CidrIterator {
            next: Some(start),
            end: start + (end as u128 - 1),
        }
    }
}

impl Iterator for Ipv6CidrIterator {
    type Item = Ipv6Addr;

    fn next(&mut self) -> Option<Ipv6Addr> {
        let next = self.next?;
        self.next = if next == self.end {
            None
        } else {
            Some(next + 1)
        };
        Some(next.into())
    }
}

impl Cidr for Ipv6Cidr {
    type Addr = Ipv6Addr;

    #[inline]
    fn address(&self) -> Self::Addr {
        self.address
    }

    #[inline]
    fn broadcast(&self) -> Self::Addr {
        Ipv6Addr::from(self.mask & u128::from(self.address) | !self.mask)
    }

    #[inline]
    fn contains(&self, address: Self::Addr) -> bool {
        (self.mask & u128::from(self.address)) == (self.mask & u128::from(address))
    }

    #[inline]
    fn network(&self) -> Self::Addr {
        Ipv6Addr::from(self.mask & u128::from(self.address))
    }

    #[inline]
    fn length(&self) -> usize {
        (!self.mask).leading_zeros() as usize
    }

    #[inline]
    fn hostmask(&self) -> Self::Addr {
        Ipv6Addr::from(!self.mask)
    }

    #[inline]
    fn netmask(&self) -> Self::Addr {
        Ipv6Addr::from(self.mask)
    }

    #[inline]
    fn new(address: Self::Addr, length: usize) -> Result<Self, CidrError> {
        let mask = match length {
            0 => u128::max_value(),
            1..=IPV6ADDR_BITS => u128::max_value() << (IPV6ADDR_BITS - length),
            _ => return Err(CidrError::Malformed("Not a valid length".to_owned())),
        };

        Ok(Ipv6Cidr { address, mask })
    }

    #[inline]
    fn size(&self) -> usize {
        2usize.pow((IPV6ADDR_BITS - self.length()) as u32)
    }

    #[inline]
    fn with_netmask(address: Self::Addr, netmask: Self::Addr) -> Result<Self, CidrError> {
        let length = Ipv6Cidr::netmask_length(netmask)?;
        Ipv6Cidr::new(address, length)
    }
}

impl FromStr for Ipv6Cidr {
    type Err = CidrError;

    fn from_str(s: &str) -> Result<Self, CidrError> {
        match s.split('/').collect::<Vec<&str>>().as_slice() {
            [addr, len_or_netmask] => {
                let address =
                    Ipv6Addr::from_str(addr).map_err(|e| CidrError::Malformed(e.to_string()))?;

                if let Ok(len) = usize::from_str_radix(len_or_netmask, 10) {
                    Ipv6Cidr::new(address, len)
                } else {
                    let netmask = Ipv6Addr::from_str(len_or_netmask)
                        .map_err(|e| CidrError::Malformed(e.to_string()))?;

                    Ipv6Cidr::with_netmask(address, netmask)
                }
            }
            _ => Err(CidrError::Malformed("No `/` found".to_owned())),
        }
    }
}

impl fmt::Display for Ipv6Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.address(), self.length())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const IPV6_SEGMENT: &str = "[0-9a-f]{1,4}";

    #[test]
    fn parse_bad_cidr() {
        assert!(Ipv6Cidr::from_str("not-a-cidr").is_err());
    }

    #[test]
    fn cidr_parse_error() {
        let bad = Ipv6Cidr::new(Ipv6Addr::from_str("acdc::1").unwrap(), 129);
        assert!(bad.is_err());
        let e = bad.unwrap_err();
        assert_eq!(
            e.to_string(),
            "Failed to parse CIDR: Not a valid length".to_string()
        );
    }

    #[test]
    fn cidr_parse_error_with_netmask() {
        let bad = Ipv6Cidr::with_netmask(
            Ipv6Addr::from_str("ff01:0:0:17::2").unwrap(),
            Ipv6Addr::from_str("0:0:ffff:ffff::").unwrap(),
        );
        assert!(bad.is_err());
        let e = bad.unwrap_err();
        assert_eq!(e.to_string(), "Invalid prefix length".to_string());
    }

    #[test]
    fn hostmask() {
        let cidr = Ipv6Cidr::new(Ipv6Addr::from_str("fd00::").unwrap(), 24).unwrap();
        assert_eq!(
            cidr.hostmask(),
            Ipv6Addr::from_str("::ff:ffff:ffff:ffff:ffff:ffff:ffff").unwrap()
        );
    }

    #[test]
    fn netmask() {
        let cidr = Ipv6Cidr::new(Ipv6Addr::from_str("fd00::").unwrap(), 24).unwrap();
        assert_eq!(cidr.netmask(), Ipv6Addr::from_str("ffff:ff00::").unwrap());
    }

    #[test]
    fn netmask_length() {
        let ip1 = Ipv6Addr::from_str("ffff:ffff:ffff::").unwrap();
        assert_eq!(Ipv6Cidr::netmask_length(ip1).unwrap(), 48);

        let cidr = Ipv6Cidr::from_str("5d88:2be8:9cc7:0f86::/64").unwrap();
        assert_eq!(Ipv6Cidr::netmask_length(cidr.netmask()).unwrap(), 64);
    }

    #[test]
    fn cidr_network_address() {
        let cidr = Ipv6Cidr::new(Ipv6Addr::from_str("fd00::").unwrap(), 24).unwrap();
        assert_eq!(cidr.network(), Ipv6Addr::from_str("fd00::").unwrap());
    }

    #[test]
    fn cidr_broadcast_address() {
        let cidr = Ipv6Cidr::new(Ipv6Addr::from_str("fd00::").unwrap(), 24).unwrap();
        assert_eq!(
            cidr.broadcast(),
            Ipv6Addr::from_str("fd00:ff:ffff:ffff:ffff:ffff:ffff:ffff").unwrap()
        );
    }

    #[test]
    fn addresses() {
        let cidr = Ipv6Cidr::new(Ipv6Addr::from_str("fd00::").unwrap(), 96).unwrap();
        assert_eq!(cidr.size(), 4_294_967_296);
    }

    #[test]
    fn iter_addresses() {
        let cidr = Ipv6Cidr::new(Ipv6Addr::from_str("20f6:1b85:cc34::").unwrap(), 126).unwrap();
        let mut iter = cidr.iter();
        assert_eq!(cidr.size(), 4);
        assert_eq!(
            Ipv6Addr::from_str("20f6:1b85:cc34:0:0:0:0:0").unwrap(),
            iter.next().unwrap()
        );
        assert_eq!(
            Ipv6Addr::from_str("20f6:1b85:cc34:0:0:0:0:1").unwrap(),
            iter.next().unwrap()
        );
        assert_eq!(
            Ipv6Addr::from_str("20f6:1b85:cc34:0:0:0:0:2").unwrap(),
            iter.next().unwrap()
        );
        assert_eq!(
            Ipv6Addr::from_str("20f6:1b85:cc34:0:0:0:0:3").unwrap(),
            iter.next().unwrap()
        );

        assert_eq!(None, iter.next());
    }

    #[test]
    fn cidr_contains_address() {
        let cidr = Ipv6Cidr::from_str("acdc::0/16").unwrap();

        assert!(cidr.contains(Ipv6Addr::from_str("acdc::1").unwrap()));
        assert!(!cidr.contains(Ipv6Addr::from_str("acdb::1").unwrap()));
    }

    proptest! {
        #[test]
        fn parse_cidr(
            a in IPV6_SEGMENT,
            b in IPV6_SEGMENT,
            c in IPV6_SEGMENT,
            d in IPV6_SEGMENT,
            e in IPV6_SEGMENT,
            f in IPV6_SEGMENT,
            g in IPV6_SEGMENT,
            h in IPV6_SEGMENT,
            length in 0..128
        ) {
            let cidr = format!("{}:{}:{}:{}:{}:{}:{}:{}/{}", a, b, c, d, e, f, g, h, length);
            assert!(Ipv6Cidr::from_str(cidr.as_str()).is_ok());
        }

        #[test]
        fn parse_cidr_with_netmask(
            a in IPV6_SEGMENT,
            b in IPV6_SEGMENT,
            c in IPV6_SEGMENT,
            d in IPV6_SEGMENT,
            e in IPV6_SEGMENT,
            f in IPV6_SEGMENT,
            g in IPV6_SEGMENT,
            h in IPV6_SEGMENT,
        ) {
            let netmask =  Ipv6Addr::new(0xffff, 0xffff, 0xffff, 0, 0, 0, 0, 0);
            let cidr = format!("{}:{}:{}:{}:{}:{}:{}:{}/{}", a, b, c, d, e, f, g, h, netmask);
            assert!(Ipv6Cidr::from_str(cidr.as_str()).is_ok());
            assert_eq!(Ipv6Cidr::from_str(cidr.as_str()).unwrap().netmask(), netmask);
        }

    }
}

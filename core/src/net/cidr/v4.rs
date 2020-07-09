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
use std::net::Ipv4Addr;
use std::str::FromStr;

const IPV4ADDR_BITS: usize = 32;

/// [CIDR] range for IPv4 addresses.
///
/// [CIDR]: https://tools.ietf.org/html/rfc4632#section-3.1
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct Ipv4Cidr {
    address: Ipv4Addr,
    mask: u32,
}

impl Ipv4Cidr {
    #[inline]
    /// Iterate through CIDR range addresses.
    pub fn iter(self) -> Ipv4CidrIterator {
        Ipv4CidrIterator::new(self.network(), self.size())
    }

    #[inline]
    fn netmask_length(netmask: Ipv4Addr) -> Result<usize, CidrError> {
        let mask = u32::from(netmask);
        let length = (!mask).leading_zeros();
        if mask.leading_zeros() == 0 && mask.trailing_zeros() == mask.count_zeros() {
            Ok(length as usize)
        } else {
            Err(CidrError::InvalidPrefixLength)
        }
    }
}

impl Default for Ipv4Cidr {
    fn default() -> Ipv4Cidr {
        Ipv4Cidr {
            address: Ipv4Addr::UNSPECIFIED,
            mask: Default::default(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Ipv4CidrIterator {
    next: Option<u32>,
    end: u32,
}

impl Ipv4CidrIterator {
    fn new(start: Ipv4Addr, end: usize) -> Self {
        let start = u32::from(start);
        Ipv4CidrIterator {
            next: Some(start),
            end: start + (end as u32 - 1),
        }
    }
}

impl Iterator for Ipv4CidrIterator {
    type Item = Ipv4Addr;

    fn next(&mut self) -> Option<Ipv4Addr> {
        let next = self.next?;
        self.next = if next == self.end {
            None
        } else {
            Some(next + 1)
        };
        Some(next.into())
    }
}

impl Cidr for Ipv4Cidr {
    type Addr = Ipv4Addr;

    #[inline]
    fn address(&self) -> Self::Addr {
        self.address
    }

    #[inline]
    fn broadcast(&self) -> Self::Addr {
        Ipv4Addr::from((self.mask & u32::from(self.address)) | !self.mask)
    }

    #[inline]
    fn contains(&self, address: Self::Addr) -> bool {
        (self.mask & u32::from(self.address)) == (self.mask & u32::from(address))
    }

    #[inline]
    fn length(&self) -> usize {
        (!self.mask).leading_zeros() as usize
    }

    #[inline]
    fn hostmask(&self) -> Self::Addr {
        Ipv4Addr::from(!self.mask)
    }

    #[inline]
    fn netmask(&self) -> Self::Addr {
        Ipv4Addr::from(self.mask)
    }

    #[inline]
    fn network(&self) -> Self::Addr {
        Ipv4Addr::from(self.mask & u32::from(self.address))
    }

    #[inline]
    fn new(address: Self::Addr, length: usize) -> Result<Self, CidrError> {
        let mask = match length {
            0 => u32::max_value(),
            1..=IPV4ADDR_BITS => u32::max_value() << (IPV4ADDR_BITS - length),
            _ => return Err(CidrError::Malformed("Not a valid length".to_owned())),
        };

        Ok(Ipv4Cidr { address, mask })
    }

    #[inline]
    fn size(&self) -> usize {
        2usize.pow((IPV4ADDR_BITS - self.length()) as u32)
    }

    #[inline]
    fn with_netmask(address: Self::Addr, netmask: Self::Addr) -> Result<Self, CidrError> {
        let length = Ipv4Cidr::netmask_length(netmask)?;
        Ipv4Cidr::new(address, length)
    }
}

impl FromStr for Ipv4Cidr {
    type Err = CidrError;

    fn from_str(s: &str) -> Result<Self, CidrError> {
        match s.split('/').collect::<Vec<&str>>().as_slice() {
            [addr, len_or_netmask] => {
                let address =
                    Ipv4Addr::from_str(addr).map_err(|e| CidrError::Malformed(e.to_string()))?;

                if let Ok(len) = usize::from_str_radix(len_or_netmask, 10) {
                    Ipv4Cidr::new(address, len)
                } else {
                    let netmask = Ipv4Addr::from_str(len_or_netmask)
                        .map_err(|e| CidrError::Malformed(e.to_string()))?;

                    Ipv4Cidr::with_netmask(address, netmask)
                }
            }
            _ => Err(CidrError::Malformed("No `/` found".to_string())),
        }
    }
}

impl fmt::Display for Ipv4Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.address(), self.length())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const IPV4_SEGMENT: ::std::ops::Range<u32> = 0..255u32;

    #[test]
    fn parse_bad_cidr() {
        assert!(Ipv4Cidr::from_str("not-a-cidr").is_err());
    }

    #[test]
    fn cidr_parse_error() {
        let bad = Ipv4Cidr::new(Ipv4Addr::from_str("10.0.0.0").unwrap(), 99);
        assert!(bad.is_err());
        let e = bad.unwrap_err();
        assert_eq!(
            e.to_string(),
            "Failed to parse CIDR: Not a valid length".to_string()
        );
    }

    #[test]
    fn cidr_parse_error_with_netmask() {
        let bad = Ipv4Cidr::with_netmask(
            Ipv4Addr::from_str("127.0.0.1").unwrap(),
            Ipv4Addr::from_str("255.0.255.0").unwrap(),
        );
        assert!(bad.is_err());
        let e = bad.unwrap_err();
        assert_eq!(e.to_string(), "Invalid prefix length".to_string());
    }

    #[test]
    fn hostmask() {
        let cidr = Ipv4Cidr::new(Ipv4Addr::from_str("10.1.0.0").unwrap(), 20).unwrap();
        assert_eq!(cidr.hostmask(), Ipv4Addr::from_str("0.0.15.255").unwrap());
    }

    #[test]
    fn netmask() {
        let cidr = Ipv4Cidr::new(Ipv4Addr::from_str("10.1.0.0").unwrap(), 20).unwrap();
        assert_eq!(cidr.netmask(), Ipv4Addr::from_str("255.255.240.0").unwrap());
    }

    #[test]
    fn cidr_network_address() {
        let cidr = Ipv4Cidr::new(Ipv4Addr::from_str("10.1.0.10").unwrap(), 20).unwrap();
        assert_eq!(cidr.network(), Ipv4Addr::from_str("10.1.0.0").unwrap());
    }

    #[test]
    fn cidr_broadcast_address() {
        let cidr = Ipv4Cidr::new(Ipv4Addr::from_str("10.1.0.10").unwrap(), 20).unwrap();
        assert_eq!(cidr.broadcast(), Ipv4Addr::from_str("10.1.15.255").unwrap());
    }

    #[test]
    fn addresses() {
        let cidr = Ipv4Cidr::new(Ipv4Addr::from_str("10.1.0.10").unwrap(), 24).unwrap();
        assert_eq!(cidr.size(), 256);
    }

    #[test]
    fn iter_addresses() {
        let cidr = Ipv4Cidr::new(Ipv4Addr::from_str("10.1.0.10").unwrap(), 30).unwrap();
        let mut iter = cidr.iter();
        assert_eq!(cidr.size(), 4);
        assert_eq!(
            Ipv4Addr::from_str("10.1.0.8").unwrap(),
            iter.next().unwrap()
        );
        assert_eq!(
            Ipv4Addr::from_str("10.1.0.9").unwrap(),
            iter.next().unwrap()
        );
        assert_eq!(
            Ipv4Addr::from_str("10.1.0.10").unwrap(),
            iter.next().unwrap()
        );
        assert_eq!(
            Ipv4Addr::from_str("10.1.0.11").unwrap(),
            iter.next().unwrap()
        );

        assert_eq!(None, iter.next());
    }

    #[test]
    fn cidr_contains_address() {
        let cidr = Ipv4Cidr::from_str("10.0.0.0/25").unwrap();
        assert!(cidr.contains(Ipv4Addr::from_str("10.0.0.0").unwrap()));
        assert!(cidr.contains(Ipv4Addr::from_str("10.0.0.127").unwrap()));
        assert!(!cidr.contains(Ipv4Addr::from_str("10.0.0.128").unwrap()));
    }

    proptest! {
        #[test]
        fn parse_cidr(
            a in IPV4_SEGMENT,
            b in IPV4_SEGMENT,
            c in IPV4_SEGMENT,
            d in IPV4_SEGMENT,
            length in 0..32
        ) {
            let cidr = format!("{}.{}.{}.{}/{}", a, b, c, d, length);
            assert!(Ipv4Cidr::from_str(cidr.as_str()).is_ok());
        }

        #[test]
        fn parse_cidr_with_netmask(
            a in IPV4_SEGMENT,
            b in IPV4_SEGMENT,
            c in IPV4_SEGMENT,
            d in IPV4_SEGMENT
        ) {
            let netmask =  Ipv4Addr::new(255, 0, 0, 0);
            let cidr = format!("{}.{}.{}.{}/{}", a, b, c, d, netmask);
            assert!(Ipv4Cidr::from_str(cidr.as_str()).is_ok());
            assert_eq!(Ipv4Cidr::from_str(cidr.as_str()).unwrap().netmask(), netmask);
        }
    }
}

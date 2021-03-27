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

use std::convert::From;
use std::fmt;
use std::str::FromStr;
use thiserror::Error;

/// Ethernet MAC address.
#[derive(Default, Debug, Copy, Clone, PartialEq, Eq)]
#[repr(C, packed)]
pub struct MacAddr([u8; 6]);

impl MacAddr {
    /// A MAC address representing an unspecified address: 00:00:00:00:00:00.
    pub const UNSPECIFIED: Self = MacAddr([0, 0, 0, 0, 0, 0]);

    /// Creates a MAC address from 6 octets.
    #[allow(clippy::many_single_char_names)]
    pub const fn new(a: u8, b: u8, c: u8, d: u8, e: u8, f: u8) -> Self {
        MacAddr([a, b, c, d, e, f])
    }

    /// Returns the six bytes the MAC address consists of.
    #[allow(clippy::trivially_copy_pass_by_ref)]
    pub fn octets(&self) -> [u8; 6] {
        self.0
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

impl From<[u8; 6]> for MacAddr {
    fn from(octets: [u8; 6]) -> MacAddr {
        MacAddr(octets)
    }
}

/// Error returned when parsing a malformed MAC address.
#[derive(Debug, Error)]
#[error("Failed to parse '{0}' as MAC address.")]
pub struct MacParseError(String);

impl FromStr for MacAddr {
    type Err = MacParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let u8s = s
            .split(|c| c == ':' || c == '-')
            .map(|s| u8::from_str_radix(s, 16))
            .filter_map(Result::ok)
            .collect::<Vec<_>>();

        if u8s.len() == 6 {
            let mut octets = [0; 6];
            octets.copy_from_slice(u8s.as_slice());
            Ok(octets.into())
        } else {
            Err(MacParseError(s.to_owned()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_addr_to_string() {
        assert_eq!(
            "00:00:00:00:00:00",
            MacAddr::new(0, 0, 0, 0, 0, 0).to_string()
        );
        assert_eq!(
            "ff:ff:ff:ff:ff:ff",
            MacAddr::new(255, 255, 255, 255, 255, 255).to_string()
        );
        assert_eq!(
            "12:34:56:ab:cd:ef",
            MacAddr::new(0x12, 0x34, 0x56, 0xAB, 0xCD, 0xEF).to_string()
        );
    }

    #[test]
    fn string_to_mac_addr() {
        assert_eq!(
            MacAddr::new(0, 0, 0, 0, 0, 0),
            "00:00:00:00:00:00".parse().unwrap()
        );
        assert_eq!(
            MacAddr::new(255, 255, 255, 255, 255, 255),
            "ff:ff:ff:ff:ff:ff".parse().unwrap()
        );
        assert_eq!(
            MacAddr::new(0x12, 0x34, 0x56, 0xAB, 0xCD, 0xEF),
            "12:34:56:ab:cd:ef".parse().unwrap()
        );
    }
}

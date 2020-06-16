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

mod v4;
mod v6;

#[allow(unreachable_pub)] // https://github.com/rust-lang/rust/issues/57411
pub use self::v4::Ipv4Cidr;
#[allow(unreachable_pub)]
pub use self::v6::Ipv6Cidr;

use failure::Fail;
use std::net::IpAddr;

/// Error indicating that a CIDR range cannot be parsed or is handled with an invalid prefix length.
#[derive(Debug, Fail)]
pub enum CidrError {
    /// Error returned when parsing a malformed CIDR range.
    #[fail(display = "Failed to parse CIDR: {}", _0)]
    ParseFailure(String),

    /// Error returned when converting from v4/v6 address mask to a prefix length.
    #[fail(display = "Invalid prefix length")]
    InvalidPrefixLength,
}

/// Common behaviors for interacting with CIDR ranges.
pub trait Cidr: Sized {
    /// Type of address, i.e. IPv4 or IPv6, associated with the CIDR.
    type Addr;

    /// IP address prefix.
    fn address(&self) -> Self::Addr;
    /// Checks whether an address is contained within the CIDR range.
    fn contains(&self, address: Self::Addr) -> bool;
    /// Checks whether a generic IP address is contained within the CIDR range.
    fn contains_ip(&self, ip: IpAddr) -> bool;
    /// First address in CIDR range.
    fn first(&self) -> Self::Addr;
    /// last address in CIDR range.
    fn last(&self) -> Self::Addr;
    /// CIDR hostmask address.
    fn hostmask(&self) -> Self::Addr;
    /// CIDR prefix length.
    fn length(&self) -> usize;
    /// CIDR netmask.
    fn netmask(&self) -> Self::Addr;
    /// Convert a Ipv4Addr netmask into a prefix length.
    fn netmask_length(netmask: Self::Addr) -> Result<usize, CidrError>;
    /// Creates a new CIDR range from a prefix length.
    fn new(address: Self::Addr, length: usize) -> Result<Self, CidrError>;
    /// Returns number of possible addresses within the CIDR range.
    fn size(&self) -> usize;
    /// Creates a new CIDR range from a netmask.
    fn with_netmask(address: Self::Addr, netmask: Self::Addr) -> Result<Self, CidrError>;
}

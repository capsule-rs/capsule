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

/// Error returned when parsing a malformed CIDR range.
#[derive(Debug, Fail)]
#[fail(display = "Failed to parse CIDR: {}", _0)]
pub struct CidrParseError(String);

/// Common behaviors for interacting with CIDR ranges.
pub trait Cidr: Sized {
    /// Type of address, i.e. IPv4 or IPv6, associated with the CIDR.
    type Addr;

    /// IP address prefix.
    fn address(&self) -> Self::Addr;
    /// CIDR Prefix length.
    fn length(&self) -> usize;
    /// Creates a new CIDR range.
    fn new(address: Self::Addr, length: usize) -> Result<Self, CidrParseError>;
    /// Checks whether an address is contained within the CIDR range.
    fn contains(&self, address: Self::Addr) -> bool;
    /// Checks whether a generic IP address is contained within the CIDR range.
    fn contains_ip(&self, ip: IpAddr) -> bool;
}

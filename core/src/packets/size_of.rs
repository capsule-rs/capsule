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

use crate::net::MacAddr;
use std::mem;
use std::net::{Ipv4Addr, Ipv6Addr};

/// A trait for returning the size of a type in bytes.
///
/// Size of the structs are used for bound checks when reading and writing
/// packets.
///
///
/// # Derivable
///
/// The `SizeOf` trait can be used with `#[derive]` and defaults to
/// `std::mem::size_of::<Self>()`.
///
/// ```
/// #[derive(SizeOf)]
/// pub struct Ipv4Header {
///     ...
/// }
/// ```
pub trait SizeOf {
    /// Returns the size of a type in bytes.
    fn size_of() -> usize;
}

impl SizeOf for () {
    fn size_of() -> usize {
        mem::size_of::<()>()
    }
}

impl SizeOf for u8 {
    fn size_of() -> usize {
        mem::size_of::<u8>()
    }
}

impl SizeOf for [u8; 2] {
    fn size_of() -> usize {
        mem::size_of::<[u8; 2]>()
    }
}

impl SizeOf for [u8; 16] {
    fn size_of() -> usize {
        mem::size_of::<[u8; 16]>()
    }
}

impl SizeOf for MacAddr {
    fn size_of() -> usize {
        mem::size_of::<MacAddr>()
    }
}

impl SizeOf for Ipv4Addr {
    fn size_of() -> usize {
        mem::size_of::<Ipv4Addr>()
    }
}

impl SizeOf for Ipv6Addr {
    fn size_of() -> usize {
        mem::size_of::<Ipv6Addr>()
    }
}

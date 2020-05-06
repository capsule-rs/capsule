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

//! Neighbor Discovery Protocol
//!
//! NDP is a protocol used in IPv6, using ICMPv6 messages and operates at
//! the link layer of the Internet model, as per [`IETF RFC 4861`]. It
//! defines three mechanisms:
//!
//! - Substitute of ARP for use in IPv6 domains.
//! - Stateless auto-configuration, allowing nodes on the local link to
//!   configure their IPv6 addresses by themselves.
//! - Router redirection to IPv6 nodes
//!
//! [`IETF RFC 4861`]: https://tools.ietf.org/html/rfc4861

mod neighbor_advert;
mod neighbor_solicit;
//mod options;
mod router_advert;
mod router_solicit;

pub use self::neighbor_advert::*;
pub use self::neighbor_solicit::*;
//pub use self::options::*;
pub use self::router_advert::*;
pub use self::router_solicit::*;

use crate::dpdk::BufferError;
use crate::packets::Packet;
use crate::{ensure, Mbuf, SizeOf};
use failure::Fallible;
use std::fmt;
use std::ptr::NonNull;

/// A trait for common NDP accessors.
pub trait NdpPacket: Packet {
    /// Returns the buffer offset where the options begin.
    fn options_offset(&self) -> usize;

    /// Returns an iterator that iterates through the options in the packet.
    fn options(&mut self) -> NdpOptionsIterator<'_> {
        let offset = self.options_offset();
        let mbuf = self.mbuf_mut();
        NdpOptionsIterator { mbuf, offset }
    }

    /// Pushes a new option `T` to the end of the packet.
    fn push_option<T: NdpOption>(&mut self) -> Fallible<T> {
        T::try_push(self.mbuf_mut())
    }
}

/// [IANA] assigned neighbor discovery option type.
///
/// A list of supported types is under [`OptionTypes`].
///
/// [IANA]: https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml#icmpv6-parameters-5
/// [`OptionTypes`]: OptionTypes
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(C, packed)]
pub struct OptionType(pub u8);

/// Supported neighbor discovery option types.
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
pub mod OptionTypes {
    use super::OptionType;

    /// Option type for [Source Link-layer Address].
    ///
    /// [Source Link-layer Address]: LinkLayerAddress
    pub const SourceLinkLayerAddress: OptionType = OptionType(1);

    /// Option type for [Target Link-layer Address].
    ///
    /// [Target Link-layer Address]: LinkLayerAddress
    pub const TargetLinkLayerAddress: OptionType = OptionType(2);

    /// Option type for [Prefix Information].
    ///
    /// [Prefix Information]: PrefixInformation
    pub const PrefixInformation: OptionType = OptionType(3);

    /// Option type for [Redirected Header].
    ///
    /// [Redirected Header]: RedirectedHeader
    pub const RedirectedHeader: OptionType = OptionType(4);

    /// Option type for [MTU].
    ///
    /// [MTU]: Mtu
    pub const Mtu: OptionType = OptionType(5);
}

impl fmt::Display for OptionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match *self {
                OptionTypes::SourceLinkLayerAddress => "Source Link-layer Address".to_string(),
                OptionTypes::TargetLinkLayerAddress => "Target Link-layer Address".to_string(),
                OptionTypes::PrefixInformation => "Prefix Information".to_string(),
                OptionTypes::RedirectedHeader => "Redirected Header".to_string(),
                OptionTypes::Mtu => "MTU".to_string(),
                _ => format!("{}", self.0),
            }
        )
    }
}

/// Option type and length fields common in all NDP options.
#[derive(Clone, Copy, Debug, SizeOf)]
#[repr(C, packed)]
struct TypeLengthTuple {
    option_type: u8,
    length: u8,
}

/// An untyped NDP option that can be downcasted to a concrete option.
pub struct AnyOption<'a> {
    mbuf: &'a mut Mbuf,
    tuple: NonNull<TypeLengthTuple>,
    offset: usize,
}

impl<'a> AnyOption<'a> {
    /// Creates a new untyped NDP option.
    #[inline]
    pub fn new(mbuf: &'a mut Mbuf, offset: usize) -> Fallible<Self> {
        let tuple = mbuf.read_data(offset)?;
        let option = AnyOption {
            mbuf,
            tuple,
            offset,
        };

        // make sure that there's enough data for the whole option as indicated
        // by the length field stored in the option itself
        ensure!(
            option.mbuf.len() >= option.end_offset(),
            BufferError::OutOfBuffer(option.end_offset(), option.mbuf.len())
        );

        Ok(option)
    }

    #[inline]
    fn tuple(&self) -> &TypeLengthTuple {
        unsafe { self.tuple.as_ref() }
    }

    /// Returns the option type.
    #[inline]
    pub fn option_type(&self) -> OptionType {
        OptionType(self.tuple().option_type)
    }

    /// Returns the length of the option in units of 8 octets.
    #[inline]
    pub fn length(&self) -> u8 {
        self.tuple().length
    }

    #[inline]
    fn end_offset(&self) -> usize {
        self.offset + self.length() as usize * 8
    }
}

impl fmt::Debug for AnyOption<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AnyOption")
            .field("option_type", &self.option_type())
            .field("length", &self.length())
            .field("$offset", &self.offset)
            .field("$len", &(self.length() * 8))
            .finish()
    }
}

/// An iterator that iterates through the options in the NDP message body.
pub struct NdpOptionsIterator<'a> {
    mbuf: &'a mut Mbuf,
    offset: usize,
}

impl NdpOptionsIterator<'_> {
    /// Advances the iterator and returns the next value.
    ///
    /// Returns `Ok(None)` when iteration is finished; returns `Err` when a
    /// parse error is encountered during iteration.
    pub fn next<'x>(&'x mut self) -> Fallible<Option<AnyOption<'x>>> {
        if self.mbuf.data_len() > self.offset {
            match AnyOption::new(self.mbuf, self.offset) {
                Ok(any) => {
                    // advances the offset to the next option
                    self.offset = any.end_offset();
                    Ok(Some(any))
                }
                Err(e) => Err(e),
            }
        } else {
            Ok(None)
        }
    }
}

impl fmt::Debug for NdpOptionsIterator<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NdpOptionsIterator")
            .field("offset", &self.offset)
            .finish()
    }
}

/// A trait all NDP options must implement.
pub trait NdpOption {
    /// Returns the assigned option type.
    fn option_type() -> OptionType;

    /// Appends a new NDP option to the end of the message body.
    fn try_push(mbuf: &mut Mbuf) -> Fallible<Self>
    where
        Self: Sized;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::MacAddr;
    use crate::packets::ip::v6::Ipv6;
    use crate::packets::{Ethernet, Packet};
    use crate::testils::byte_arrays::ROUTER_ADVERT_PACKET;
    use std::str::FromStr;

    #[capsule::test]
    fn iterate_ndp_options() {
        let packet = Mbuf::from_bytes(&ROUTER_ADVERT_PACKET).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();
        let ipv6 = ethernet.parse::<Ipv6>().unwrap();
        let mut advert = ipv6.parse::<RouterAdvertisement<Ipv6>>().unwrap();

        let mut prefix = false;
        let mut mtu = false;
        let mut source = false;
        let mut other = false;

        let mut iter = advert.options();

        while let Ok(Some(any)) = iter.next() {
            match any.option_type() {
                OptionTypes::PrefixInformation => prefix = true,
                OptionTypes::Mtu => mtu = true,
                OptionTypes::SourceLinkLayerAddress => source = true,
                _ => other = true,
            }
        }

        assert!(prefix);
        assert!(mtu);
        assert!(source);
        assert!(other);
    }

    #[capsule::test]
    fn invalid_ndp_option_length() {
        let packet = Mbuf::from_bytes(&INVALID_OPTION_LENGTH).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();
        let ipv6 = ethernet.parse::<Ipv6>().unwrap();
        let mut advert = ipv6.parse::<RouterAdvertisement<Ipv6>>().unwrap();

        assert!(advert.options().next().is_err());
    }

    /// ICMPv6 packet with invalid MTU-option length.
    #[rustfmt::skip]
    const INVALID_OPTION_LENGTH: [u8;78] = [
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
        // MTU option with invalid length
        0x05, 0x08, 0x00, 0x00, 0x00, 0x00, 0x05, 0xdc,
    ];
}

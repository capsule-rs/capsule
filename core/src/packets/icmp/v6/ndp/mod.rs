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
//! the link layer of the Internet model, as per [IETF RFC 4861]. It
//! defines three mechanisms:
//!
//! - Substitute of ARP for use in IPv6 domains.
//! - Stateless auto-configuration, allowing nodes on the local link to
//!   configure their IPv6 addresses by themselves.
//! - Router redirection to IPv6 nodes.
//!
//! [IETF RFC 4861]: https://tools.ietf.org/html/rfc4861

mod neighbor_advert;
mod neighbor_solicit;
mod options;
mod redirect;
mod router_advert;
mod router_solicit;

pub use self::neighbor_advert::*;
pub use self::neighbor_solicit::*;
pub use self::options::*;
pub use self::redirect::*;
pub use self::router_advert::*;
pub use self::router_solicit::*;

use crate::ensure;
use crate::packets::{Immutable, Internal, Mbuf, Packet, SizeOf};
use anyhow::{anyhow, Result};
use std::fmt;
use std::marker::PhantomData;
use std::ptr::NonNull;

/// A trait for common NDP accessors.
pub trait NdpPacket: Packet {
    /// Returns the buffer offset where the options begin.
    fn options_offset(&self) -> usize;

    /// Returns an iterator to read the options in the packet.
    ///
    /// The options cannot be modified. To modify the values while iterating
    /// over the options, use [`options_mut().iter()`] instead.
    ///
    /// # Example
    ///
    /// ```
    /// let advert = ipv6.parse::<RouterAdvertisement<Ipv6>>()?;
    /// let mut iter = advert.options_iter();
    ///
    /// while let Some(option) = iter.next()? {
    ///     println!("{:?}", option);
    /// }
    /// ```
    ///
    /// [`options_mut().iter()`]: NdpOptions::iter
    #[inline]
    fn options_iter(&self) -> ImmutableNdpOptionsIterator<'_> {
        let mbuf = unsafe { self.mbuf().clone(Internal(())) };
        ImmutableNdpOptionsIterator {
            mbuf,
            offset: self.options_offset(),
            _phantom: PhantomData,
        }
    }

    /// Returns a mutable reference to the options in the packet.
    #[inline]
    fn options_mut(&mut self) -> NdpOptions<'_> {
        let offset = self.options_offset();
        NdpOptions {
            mbuf: self.mbuf_mut(),
            offset,
        }
    }
}

/// [IANA] assigned neighbor discovery option type.
///
/// A list of supported types is under [`NdpOptionTypes`].
///
/// [IANA]: https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml#icmpv6-parameters-5
/// [`NdpOptionTypes`]: NdpOptionTypes
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(C, packed)]
pub struct NdpOptionType(pub u8);

/// Supported neighbor discovery option types.
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
pub mod NdpOptionTypes {
    use super::NdpOptionType;

    /// Option type for [Source Link-layer Address].
    ///
    /// [Source Link-layer Address]: crate::packets::icmp::v6::ndp::LinkLayerAddress
    pub const SourceLinkLayerAddress: NdpOptionType = NdpOptionType(1);

    /// Option type for [Target Link-layer Address].
    ///
    /// [Target Link-layer Address]: crate::packets::icmp::v6::ndp::LinkLayerAddress
    pub const TargetLinkLayerAddress: NdpOptionType = NdpOptionType(2);

    /// Option type for [Prefix Information].
    ///
    /// [Prefix Information]: crate::packets::icmp::v6::ndp::PrefixInformation
    pub const PrefixInformation: NdpOptionType = NdpOptionType(3);

    /// Option type for [Redirected Header].
    ///
    /// [Redirected Header]: crate::packets::icmp::v6::ndp::RedirectedHeader
    pub const RedirectedHeader: NdpOptionType = NdpOptionType(4);

    /// Option type for [MTU].
    ///
    /// [MTU]: crate::packets::icmp::v6::ndp::Mtu
    pub const Mtu: NdpOptionType = NdpOptionType(5);
}

impl fmt::Display for NdpOptionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match *self {
                NdpOptionTypes::SourceLinkLayerAddress => "Source Link-layer Address".to_string(),
                NdpOptionTypes::TargetLinkLayerAddress => "Target Link-layer Address".to_string(),
                NdpOptionTypes::PrefixInformation => "Prefix Information".to_string(),
                NdpOptionTypes::RedirectedHeader => "Redirected Header".to_string(),
                NdpOptionTypes::Mtu => "MTU".to_string(),
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

/// An immutable generic NDP option that can be casted to a more specific
/// option.
pub struct ImmutableNdpOption<'a> {
    mbuf: &'a mut Mbuf,
    tuple: NonNull<TypeLengthTuple>,
    offset: usize,
}

impl<'a> ImmutableNdpOption<'a> {
    /// Creates a new immutable untyped NDP option.
    ///
    /// # Errors
    ///
    /// Returns an error if the buffer does not have enough free space.
    #[inline]
    fn new(mbuf: &'a mut Mbuf, offset: usize) -> Result<Self> {
        let tuple = mbuf.read_data(offset)?;
        let option = ImmutableNdpOption {
            mbuf,
            tuple,
            offset,
        };

        // makes sure that there's enough data for the whole option as
        // indicated by the length field stored in the option itself
        ensure!(
            option.mbuf.len() >= option.end_offset(),
            anyhow!("option size exceeds remaining buffer size.")
        );

        Ok(option)
    }

    #[inline]
    fn tuple(&self) -> &TypeLengthTuple {
        unsafe { self.tuple.as_ref() }
    }

    /// Returns the option type.
    #[inline]
    pub fn option_type(&self) -> NdpOptionType {
        NdpOptionType(self.tuple().option_type)
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

    /// Casts the immutable generic option to a specific option `T`.
    ///
    /// # Example
    ///
    /// ```
    /// let advert = ipv6.parse::<RouterAdvertisement<Ipv6>>()?;
    /// let mut iter = advert.options();
    ///
    /// while let Some(option) = iter.next()? {
    ///     let prefix = option.downcast::<PrefixInformation<'_>>()?;
    ///     println!("{:?}", prefix);
    /// }
    /// ```
    #[inline]
    pub fn downcast<'b, T: NdpOption<'b>>(&'b mut self) -> Result<Immutable<'b, T>> {
        T::try_parse(self.mbuf, self.offset, Internal(())).map(Immutable::new)
    }
}

impl fmt::Debug for ImmutableNdpOption<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ImmutableNdpOption")
            .field("option_type", &self.option_type())
            .field("length", &self.length())
            .field("$offset", &self.offset)
            .field("$len", &(self.length() * 8))
            .finish()
    }
}

/// An iterator that iterates through the options in the NDP message body
/// immutably.
pub struct ImmutableNdpOptionsIterator<'a> {
    mbuf: Mbuf,
    offset: usize,
    _phantom: PhantomData<&'a Mbuf>,
}

impl ImmutableNdpOptionsIterator<'_> {
    /// Advances the iterator and returns the next value.
    ///
    /// Returns `Ok(None)` when iteration is finished; returns `Err` when a
    /// parse error is encountered during iteration.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Result<Option<ImmutableNdpOption<'_>>> {
        if self.mbuf.data_len() > self.offset {
            match ImmutableNdpOption::new(&mut self.mbuf, self.offset) {
                Ok(option) => {
                    // advances the offset to the next option
                    self.offset = option.end_offset();
                    Ok(Some(option))
                }
                Err(e) => Err(e),
            }
        } else {
            Ok(None)
        }
    }
}

impl fmt::Debug for ImmutableNdpOptionsIterator<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ImmutableNdpOptionsIterator")
            .field("offset", &self.offset)
            .finish()
    }
}

/// A mutable generic NDP option that can be casted to a more specific option.
pub struct MutableNdpOption<'a> {
    mbuf: &'a mut Mbuf,
    tuple: NonNull<TypeLengthTuple>,
    offset: usize,
}

impl<'a> MutableNdpOption<'a> {
    /// Creates a new mutable untyped NDP option.
    ///
    /// # Errors
    ///
    /// Returns an error if the buffer does not have enough free space.
    #[inline]
    fn new(mbuf: &'a mut Mbuf, offset: usize) -> Result<Self> {
        let tuple = mbuf.read_data(offset)?;
        let option = MutableNdpOption {
            mbuf,
            tuple,
            offset,
        };

        // makes sure that there's enough data for the whole option as
        // indicated by the length field stored in the option itself
        ensure!(
            option.mbuf.len() >= option.end_offset(),
            anyhow!("option size exceeds remaining buffer size.")
        );

        Ok(option)
    }

    #[inline]
    fn tuple(&self) -> &TypeLengthTuple {
        unsafe { self.tuple.as_ref() }
    }

    /// Returns the option type.
    #[inline]
    pub fn option_type(&self) -> NdpOptionType {
        NdpOptionType(self.tuple().option_type)
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

    /// Casts the mutable generic option to a specific option `T`.
    ///
    /// # Example
    ///
    /// ```
    /// let advert = ipv6.parse::<RouterAdvertisement<Ipv6>>()?;
    /// let mut iter = advert.options_mut().iter();
    ///
    /// while let Some(option) = iter.next()? {
    ///     let mut prefix = option.downcast::<PrefixInformation<'_>>()?;
    ///     prefix.set_prefix_length(64);
    /// }
    /// ```
    #[inline]
    pub fn downcast<'b, T: NdpOption<'b>>(&'b mut self) -> Result<T> {
        T::try_parse(self.mbuf, self.offset, Internal(()))
    }
}

impl fmt::Debug for MutableNdpOption<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MutableNdpOption")
            .field("option_type", &self.option_type())
            .field("length", &self.length())
            .field("$offset", &self.offset)
            .field("$len", &(self.length() * 8))
            .finish()
    }
}

/// An iterator that iterates through the options in the NDP message body
/// mutably.
pub struct MutableNdpOptionsIterator<'a> {
    mbuf: &'a mut Mbuf,
    offset: usize,
}

impl MutableNdpOptionsIterator<'_> {
    /// Advances the iterator and returns the next value.
    ///
    /// Returns `Ok(None)` when iteration is finished; returns `Err` when a
    /// parse error is encountered during iteration.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Result<Option<MutableNdpOption<'_>>> {
        if self.mbuf.data_len() > self.offset {
            match MutableNdpOption::new(&mut self.mbuf, self.offset) {
                Ok(option) => {
                    // advances the offset to the next option
                    self.offset = option.end_offset();
                    Ok(Some(option))
                }
                Err(e) => Err(e),
            }
        } else {
            Ok(None)
        }
    }
}

impl fmt::Debug for MutableNdpOptionsIterator<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MutableNdpOptionsIterator")
            .field("offset", &self.offset)
            .finish()
    }
}

/// Options in the NDP message body.
pub struct NdpOptions<'a> {
    mbuf: &'a mut Mbuf,
    offset: usize,
}

impl NdpOptions<'_> {
    /// Returns an iterator that allows modifying each option.
    ///
    /// # Example
    ///
    /// ```
    /// let advert = ipv6.parse::<RouterAdvertisement<Ipv6>>()?;
    /// let mut options = advert.options_mut();
    /// let mut iter = options.iter();
    ///
    /// while let Some(option) = iter.next()? {
    ///     println!("{:?}", option);
    /// }
    /// ```
    #[inline]
    pub fn iter(&mut self) -> MutableNdpOptionsIterator<'_> {
        MutableNdpOptionsIterator {
            mbuf: self.mbuf,
            offset: self.offset,
        }
    }

    /// Prepends a new option `T` at the beginning of the options.
    ///
    /// # Example
    ///
    /// ```
    /// let advert = ipv6.parse::<RouterAdvertisement<Ipv6>>()?;
    /// let mut options = advert.options_mut();
    /// let mut source = options.prepend::<LinkLayerAddress<'_>>()?;
    /// source.set_option_type_source();
    /// ```
    #[inline]
    pub fn prepend<'a, T: NdpOption<'a>>(&'a mut self) -> Result<T> {
        T::try_push(self.mbuf, self.offset, Internal(()))
    }

    /// Appends a new option `T` at the end of the options.
    ///
    /// # Example
    ///
    /// ```
    /// let advert = ipv6.parse::<RouterAdvertisement<Ipv6>>()?;
    /// let mut options = advert.options_mut();
    /// let mut source = options.append::<LinkLayerAddress<'_>>()?;
    /// source.set_option_type_source();
    /// ```
    #[inline]
    pub fn append<'a, T: NdpOption<'a>>(&'a mut self) -> Result<T> {
        T::try_push(self.mbuf, self.mbuf.data_len(), Internal(()))
    }

    /// Retains only the options specified by the predicate.
    ///
    /// In other words, remove all options `o` such that `f(o)` returns false.
    /// If an error occurs, all removals done prior to the error cannot be
    /// undone.
    ///
    /// # Example
    ///
    /// ```
    /// let advert = ipv6.parse::<RouterAdvertisement<Ipv6>>()?;
    /// let mut options = advert.options_mut();
    /// let _ = options.retain(|option| option.option_type() == NdpOptionTypes::PrefixInformation);
    /// ```
    pub fn retain<F>(&mut self, mut f: F) -> Result<()>
    where
        F: FnMut(&mut ImmutableNdpOption<'_>) -> bool,
    {
        let mut offset = self.offset;
        while self.mbuf.data_len() > offset {
            let mut option = ImmutableNdpOption::new(self.mbuf, offset)?;
            if !f(&mut option) {
                let len = option.length() * 8;
                self.mbuf.shrink(offset, len as usize)?;
            } else {
                offset = option.end_offset();
            }
        }

        Ok(())
    }
}

impl fmt::Debug for NdpOptions<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NdpOptions")
            .field("offset", &self.offset)
            .finish()
    }
}

/// A trait that all NDP options must implement.
///
/// The trait is used for conversion between the generic NDP option
/// and the more specific options. Implementors can use this trait to
/// add custom NDP options. This trait should not be imported and used
/// directly.
pub trait NdpOption<'a> {
    /// Returns the option type.
    fn option_type(&self) -> NdpOptionType;

    /// Returns the length of the option in units of 8 octets.
    fn length(&self) -> u8;

    /// Parses the buffer at offset as this NDP option.
    ///
    /// The buffer offset includes `option_type` and `length` fields. The
    /// implementation should verify that `option_type` matches the expected
    /// type code. Otherwise parse should fail. When applicable, the
    /// implementation should also verify that `length` is consistent with
    /// the expected length for the given option type as well.
    ///
    /// # Remarks
    ///
    /// This function cannot be invoked directly. It is internally used by
    /// [`ImmutableNdpOption::downcast`] and [`MutableNdpOption::downcast`].
    ///
    /// [`ImmutableNdpOption::downcast`]: ImmutableNdpOption::downcast
    /// [`MutableNdpOption::downcast`]: MutableNdpOption::downcast
    fn try_parse(mbuf: &'a mut Mbuf, offset: usize, internal: Internal) -> Result<Self>
    where
        Self: Sized;

    /// Pushes a new NDP option to the buffer at offset.
    ///
    /// # Remarks
    ///
    /// This function cannot be invoked directly. It is internally used by
    /// [`NdpOptions::prepend`] and [`NdpOptions::append`].
    ///
    /// [`NdpOptions::prepend`]: NdpOptions::prepend
    /// [`NdpOptions::append`]: NdpOptions::append
    fn try_push(mbuf: &'a mut Mbuf, offset: usize, internal: Internal) -> Result<Self>
    where
        Self: Sized;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packets::ethernet::Ethernet;
    use crate::packets::ip::v6::Ipv6;
    use crate::testils::byte_arrays::ROUTER_ADVERT_PACKET;

    #[capsule::test]
    fn iterate_immutable_ndp_options() {
        let packet = Mbuf::from_bytes(&ROUTER_ADVERT_PACKET).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();
        let ipv6 = ethernet.parse::<Ipv6>().unwrap();
        let advert = ipv6.parse::<RouterAdvertisement<Ipv6>>().unwrap();

        let mut prefix = false;
        let mut mtu = false;
        let mut source = false;
        let mut other = false;

        let mut iter = advert.options_iter();

        while let Some(option) = iter.next().unwrap() {
            match option.option_type() {
                NdpOptionTypes::PrefixInformation => prefix = true,
                NdpOptionTypes::Mtu => mtu = true,
                NdpOptionTypes::SourceLinkLayerAddress => source = true,
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
        let advert = ipv6.parse::<RouterAdvertisement<Ipv6>>().unwrap();

        assert!(advert.options_iter().next().is_err());
    }

    #[capsule::test]
    fn downcast_immutable_ndp_option() {
        let packet = Mbuf::from_bytes(&ROUTER_ADVERT_PACKET).unwrap();
        let ethernet = packet.peek::<Ethernet>().unwrap();
        let ipv6 = ethernet.peek::<Ipv6>().unwrap();
        let advert = ipv6.peek::<RouterAdvertisement<Ipv6>>().unwrap();

        let mut iter = advert.options_iter();

        // first one is the prefix information option.
        let mut prefix = iter.next().unwrap().unwrap();
        assert!(prefix.downcast::<PrefixInformation<'_>>().is_ok());

        // next one is the MTU option.
        let mut mtu = iter.next().unwrap().unwrap();
        assert!(mtu.downcast::<PrefixInformation<'_>>().is_err());
    }

    #[capsule::test]
    fn iterate_mutable_ndp_options() {
        let packet = Mbuf::from_bytes(&ROUTER_ADVERT_PACKET).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();
        let ipv6 = ethernet.parse::<Ipv6>().unwrap();
        let mut advert = ipv6.parse::<RouterAdvertisement<Ipv6>>().unwrap();

        let mut prefix = false;
        let mut mtu = false;
        let mut source = false;
        let mut unknown = false;

        let mut options = advert.options_mut();
        let mut iter = options.iter();

        while let Some(option) = iter.next().unwrap() {
            match option.option_type() {
                NdpOptionTypes::PrefixInformation => prefix = true,
                NdpOptionTypes::Mtu => mtu = true,
                NdpOptionTypes::SourceLinkLayerAddress => source = true,
                _ => unknown = true, // no support for recursive DNS server option yet
            }
        }

        assert!(prefix);
        assert!(mtu);
        assert!(source);
        assert!(unknown);
    }

    #[capsule::test]
    fn downcast_mutable_ndp_option() {
        let packet = Mbuf::from_bytes(&ROUTER_ADVERT_PACKET).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();
        let ipv6 = ethernet.parse::<Ipv6>().unwrap();
        let mut advert = ipv6.parse::<RouterAdvertisement<Ipv6>>().unwrap();
        let mut options = advert.options_mut();
        let mut iter = options.iter();

        // first one is the prefix information option.
        let mut prefix = iter.next().unwrap().unwrap();
        assert!(prefix.downcast::<PrefixInformation<'_>>().is_ok());

        // next one is the MTU option.
        let mut mtu = iter.next().unwrap().unwrap();
        assert!(mtu.downcast::<PrefixInformation<'_>>().is_err());
    }

    #[capsule::test]
    fn modify_ndp_option() {
        let packet = Mbuf::from_bytes(&ROUTER_ADVERT_PACKET).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();
        let ipv6 = ethernet.parse::<Ipv6>().unwrap();
        let mut advert = ipv6.parse::<RouterAdvertisement<Ipv6>>().unwrap();
        let mut options = advert.options_mut();
        let mut iter = options.iter();

        // first one is the prefix information option.
        let mut option = iter.next().unwrap().unwrap();
        let mut prefix = option.downcast::<PrefixInformation<'_>>().unwrap();

        assert_eq!(64, prefix.prefix_length());

        prefix.set_prefix_length(32);
        assert_eq!(32, prefix.prefix_length());
    }

    #[capsule::test]
    fn prepend_ndp_option() {
        let packet = Mbuf::from_bytes(&ROUTER_ADVERT_PACKET).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();
        let ipv6 = ethernet.parse::<Ipv6>().unwrap();
        let mut advert = ipv6.parse::<RouterAdvertisement<Ipv6>>().unwrap();
        let mut options = advert.options_mut();
        let mut target = options.prepend::<LinkLayerAddress<'_>>().unwrap();
        target.set_option_type_target();

        let mut iter = advert.options_iter();
        let first = iter.next().unwrap().unwrap();

        assert_eq!(NdpOptionTypes::TargetLinkLayerAddress, first.option_type());
    }

    #[capsule::test]
    fn append_ndp_option() {
        let packet = Mbuf::from_bytes(&ROUTER_ADVERT_PACKET).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();
        let ipv6 = ethernet.parse::<Ipv6>().unwrap();
        let mut advert = ipv6.parse::<RouterAdvertisement<Ipv6>>().unwrap();
        let mut options = advert.options_mut();
        let mut target = options.append::<LinkLayerAddress<'_>>().unwrap();
        target.set_option_type_target();

        let mut index = 0;
        let mut iter = advert.options_iter();
        while let Some(option) = iter.next().unwrap() {
            if option.option_type() == NdpOptionTypes::TargetLinkLayerAddress {
                break;
            }

            index += 1;
        }

        // asserts that the new option is at the end
        assert_eq!(4, index);
    }

    #[capsule::test]
    fn retain_ndp_options() {
        let packet = Mbuf::from_bytes(&ROUTER_ADVERT_PACKET).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();
        let ipv6 = ethernet.parse::<Ipv6>().unwrap();
        let mut advert = ipv6.parse::<RouterAdvertisement<Ipv6>>().unwrap();
        let mut options = advert.options_mut();
        let _ = options.retain(|option| option.downcast::<Mtu<'_>>().is_ok());

        // removed all but one option
        let mut iter = advert.options_iter();
        assert!(iter.next().unwrap().is_some());
        assert!(iter.next().unwrap().is_none());
    }

    /// Demonstrates that `NdpPacket::options_iter` behaves as an immutable
    /// borrow on the `NdpPacket`. Compilation will fail because it tries
    /// to have a mutable borrow on `RouterAdvertisement` while there's
    /// already an immutable borrow through the options iterator.
    ///
    /// ```
    /// |         let mut iter = advert.options_iter();
    /// |                        ------ immutable borrow occurs here
    /// |         advert.set_code(0);
    /// |         ^^^^^^^^^^^^^^^^^^ mutable borrow occurs here
    /// |         let _ = iter.next();
    /// |                 ---- immutable borrow later used here
    /// ```
    #[test]
    #[cfg(feature = "compile_failure")]
    fn cannot_mutate_packet_while_iterating_options() {
        use crate::packets::icmp::v6::Icmpv6Packet;

        let packet = Mbuf::from_bytes(&ROUTER_ADVERT_PACKET).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();
        let ipv6 = ethernet.parse::<Ipv6>().unwrap();
        let mut advert = ipv6.parse::<RouterAdvertisement<Ipv6>>().unwrap();

        let mut iter = advert.options_iter();
        advert.set_code(0);
        let _ = iter.next();
    }

    /// Demonstrates that `ImmutableNdpOptionsIterator` returns an immutable
    /// option wrapper. Compilation will fail because it tries to mutate the
    /// `PrefixInformation` option.
    ///
    /// ```
    /// |         prefix.set_prefix_length(64);
    /// |         ^^^^^^ cannot borrow as mutable
    /// ```
    #[test]
    #[cfg(feature = "compile_failure")]
    fn cannot_mutate_immutable_option() {
        let packet = Mbuf::from_bytes(&ROUTER_ADVERT_PACKET).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();
        let ipv6 = ethernet.parse::<Ipv6>().unwrap();
        let advert = ipv6.parse::<RouterAdvertisement<Ipv6>>().unwrap();
        let mut iter = advert.options_iter();

        let mut option = iter.next().unwrap().unwrap();
        let prefix = option.downcast::<PrefixInformation<'_>>().unwrap();
        prefix.set_prefix_length(64);
    }

    /// Demonstrates that `iter`, `prepend`, `append` and `retain` behave as
    /// mutable borrows on `NdpOptions`. Compilation will fail because it
    /// tries to mutate the options through `prepend` while there's already
    /// a mutable borrow through the iterator.
    ///
    /// ```
    /// |         let mut iter = options.iter();
    /// |                        ------- first mutable borrow occurs here
    /// |         let _ = options.prepend::<LinkLayerAddress<'_>>();
    /// |                 ^^^^^^^ second mutable borrow occurs here
    /// |         let _ = iter.next();
    /// |                 ---- first borrow later used here
    /// ```
    #[test]
    #[cfg(feature = "compile_failure")]
    fn cannot_mutate_options_while_iterating_options() {
        let packet = Mbuf::from_bytes(&ROUTER_ADVERT_PACKET).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();
        let ipv6 = ethernet.parse::<Ipv6>().unwrap();
        let mut advert = ipv6.parse::<RouterAdvertisement<Ipv6>>().unwrap();

        let mut options = advert.options_mut();
        let mut iter = options.iter();
        let _ = options.prepend::<LinkLayerAddress<'_>>();
        let _ = iter.next();
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

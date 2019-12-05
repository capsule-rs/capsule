use super::{NdpOption, SOURCE_LINK_LAYER_ADDR, TARGET_LINK_LAYER_ADDR};
use crate::net::MacAddr;
use crate::packets::ParseError;
use crate::{ensure, Mbuf, Result, SizeOf};
use std::fmt;
use std::ptr::NonNull;

/// Source/Target Link-layer Address option defined in [IETF RFC 4861].
///
/// ```
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Type      |    Length     |    Link-Layer Address ...
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// Type            1 for Source Link-layer Address
///                 2 for Target Link-layer Address
///
/// Length          The length of the option (including the type and
///                 length fields) in units of 8 octets.  For example,
///                 the length for IEEE 802 addresses is 1.
///
/// Link-Layer Address
///                 The variable length link-layer address.
///
///                 The content and format of this field (including
///                 byte and bit ordering) is expected to be specified
///                 in specific documents that describe how IPv6
///                 operates over different link layers.
///
/// [IETF RFC 4861]: https://tools.ietf.org/html/rfc4861#section-4.6.1
pub struct LinkLayerAddress {
    fields: NonNull<LinkLayerAddressFields>,
    offset: usize,
}

impl LinkLayerAddress {
    /// Parses the link-layer address option from the message buffer at offset.
    #[inline]
    pub fn parse(mbuf: &Mbuf, offset: usize) -> Result<LinkLayerAddress> {
        let fields = mbuf.read_data::<LinkLayerAddressFields>(offset)?;

        ensure!(
            unsafe { fields.as_ref().length } == (LinkLayerAddressFields::size_of() as u8 / 8),
            ParseError::new("Invalid link-layer address option length.")
        );

        Ok(LinkLayerAddress { fields, offset })
    }

    /// Returns the message buffer offset for this option.
    pub fn offset(&self) -> usize {
        self.offset
    }

    #[inline]
    fn fields(&self) -> &LinkLayerAddressFields {
        unsafe { self.fields.as_ref() }
    }

    #[inline]
    fn fields_mut(&mut self) -> &mut LinkLayerAddressFields {
        unsafe { self.fields.as_mut() }
    }

    /// Returns the option type. `1` for source link-layer address and `2`
    /// for target link-layer address.
    #[inline]
    pub fn option_type(&self) -> u8 {
        self.fields().option_type
    }

    /// Sets the option type.
    #[inline]
    pub fn set_option_type(&mut self, option_type: u8) {
        if option_type == SOURCE_LINK_LAYER_ADDR || option_type == TARGET_LINK_LAYER_ADDR {
            self.fields_mut().option_type = option_type
        } else {
            //TODO: determine what to do when option_type is set incorrectly
        }
    }

    /// Returns the length of the option measured in units of 8 octets.
    #[inline]
    pub fn length(&self) -> u8 {
        self.fields().length
    }

    /// Returns the link-layer address.
    #[inline]
    pub fn addr(&self) -> MacAddr {
        self.fields().addr
    }

    /// Sets the link-layer address.
    #[inline]
    pub fn set_addr(&mut self, addr: MacAddr) {
        self.fields_mut().addr = addr;
    }
}

impl fmt::Debug for LinkLayerAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("link layer address")
            .field("type", &self.option_type())
            .field("length", &self.length())
            .field("addr", &self.addr())
            .finish()
    }
}

impl NdpOption for LinkLayerAddress {
    #[inline]
    fn do_push(mbuf: &mut Mbuf) -> Result<Self>
    where
        Self: Sized,
    {
        let offset = mbuf.data_len();
        mbuf.extend(offset, LinkLayerAddressFields::size_of())?;
        let fields = mbuf.write_data(offset, &LinkLayerAddressFields::default())?;
        Ok(LinkLayerAddress { fields, offset })
    }
}

/// Link-layer address option fields.
#[derive(Clone, Copy, Debug)]
#[repr(C, packed)]
struct LinkLayerAddressFields {
    option_type: u8,
    length: u8,
    addr: MacAddr,
}

impl Default for LinkLayerAddressFields {
    fn default() -> LinkLayerAddressFields {
        LinkLayerAddressFields {
            option_type: 1,
            length: 1,
            addr: MacAddr::UNSPECIFIED,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn size_of_link_layer_address() {
        assert_eq!(8, LinkLayerAddressFields::size_of());
    }
}

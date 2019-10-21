use super::{NdpOption, MTU};
use crate::packets::ParseError;
use crate::{Mbuf, Result, SizeOf};
use std::fmt;
use std::ptr::NonNull;

/*  From https://tools.ietf.org/html/rfc4861#section-4.6.4
    MTU

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Type      |    Length     |           Reserved            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                              MTU                              |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    Type            5

    Length          1

    Reserved        This field is unused.  It MUST be initialized to
                    zero by the sender and MUST be ignored by the
                    receiver.

    MTU             32-bit unsigned integer.  The recommended MTU for
                    the link.
*/

#[derive(Clone, Copy, Debug)]
#[repr(C, packed)]
struct MtuFields {
    option_type: u8,
    length: u8,
    reserved: u16,
    mtu: u32,
}

impl Default for MtuFields {
    fn default() -> MtuFields {
        MtuFields {
            option_type: MTU,
            length: 1,
            reserved: 0,
            mtu: 0,
        }
    }
}

/// Maximum transmission unit option.
pub struct Mtu {
    fields: NonNull<MtuFields>,
    offset: usize,
}

impl Mtu {
    /// Parses the MTU option from the message buffer at offset.
    #[inline]
    pub fn parse(mbuf: &Mbuf, offset: usize) -> Result<Mtu> {
        let fields = mbuf.read_data::<MtuFields>(offset)?;

        ensure!(
            unsafe { fields.as_ref().length } == (MtuFields::size_of() as u8 / 8),
            ParseError::new("Invalid MTU option length.")
        );

        Ok(Mtu { fields, offset })
    }

    /// Returns the message buffer offset for this option
    pub fn offset(&self) -> usize {
        self.offset
    }

    #[inline]
    fn fields(&self) -> &MtuFields {
        unsafe { self.fields.as_ref() }
    }

    #[inline]
    fn fields_mut(&mut self) -> &mut MtuFields {
        unsafe { self.fields.as_mut() }
    }

    #[inline]
    pub fn option_type(&self) -> u8 {
        self.fields().option_type
    }

    pub fn length(&self) -> u8 {
        self.fields().length
    }

    pub fn mtu(&self) -> u32 {
        u32::from_be(self.fields().mtu)
    }

    pub fn set_mtu(&mut self, mtu: u32) {
        self.fields_mut().mtu = u32::to_be(mtu);
    }
}

impl fmt::Debug for Mtu {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("link layer address")
            .field("type", &self.option_type())
            .field("length", &self.length())
            .field("mtu", &self.mtu())
            .finish()
    }
}

impl NdpOption for Mtu {
    #[inline]
    fn do_push(mbuf: &mut Mbuf) -> Result<Self>
    where
        Self: Sized,
    {
        let offset = mbuf.data_len();
        mbuf.extend(offset, MtuFields::size_of())?;
        let fields = mbuf.write_data(offset, &MtuFields::default())?;
        Ok(Mtu { fields, offset })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn size_of_mtu() {
        assert_eq!(8, MtuFields::size_of());
    }
}

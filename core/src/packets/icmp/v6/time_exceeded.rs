use crate::packets::icmp::v6::{
    Icmpv6, Icmpv6Header, Icmpv6Packet, Icmpv6Payload, Icmpv6Type, Icmpv6Types,
};
use crate::packets::ip::v6::{Ipv6Packet, IPV6_MIN_MTU};
use crate::packets::ip::ProtocolNumbers;
use crate::packets::{CondRc, Packet, ParseError};
use crate::{ensure, Result, SizeOf};
use nb2_macros::Icmpv6Packet;
use std::fmt;

/// Time Exceeded Message defined in [IETF RFC 4443].
///
/// ```
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Type      |     Code      |          Checksum             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                             Unused                            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                    As much of invoking packet                 |
/// +               as possible without the ICMPv6 packet           +
/// |               exceeding the minimum IPv6 MTU [IPv6]           |
/// ```
///
/// [IETF RFC 4443]: https://tools.ietf.org/html/rfc4443#section-3.3
#[derive(Clone, Copy, Debug, Default, Icmpv6Packet, SizeOf)]
#[repr(C, packed)]
pub struct TimeExceeded {
    _unused: u32,
}

impl Icmpv6Payload for TimeExceeded {
    fn msg_type() -> Icmpv6Type {
        Icmpv6Types::TimeExceeded
    }
}

impl<E: Ipv6Packet> Icmpv6<E, TimeExceeded> {
    /// See: Packet trait `cascade`
    ///
    /// Implemented here as is required by `Icmpv6Packet` derive-macro.
    #[inline]
    pub fn cascade(&mut self) {
        // keeps as much of the invoking packet without exceeding the
        // minimum MTU, and ignores the error if there's nothing to
        // truncate.
        let _ = self.envelope_mut().truncate(IPV6_MIN_MTU);
        self.compute_checksum();
        self.envelope_mut().cascade();
    }
}

impl<E: Ipv6Packet> fmt::Debug for Icmpv6<E, TimeExceeded> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("icmpv6")
            .field("type", &format!("{}", self.msg_type()))
            .field("code", &self.code())
            .field("checksum", &format!("0x{:04x}", self.checksum()))
            .field("$offset", &self.offset())
            .field("$len", &self.len())
            .field("$header_len", &self.header_len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SizeOf;

    #[test]
    fn size_of_time_exceeded() {
        assert_eq!(4, TimeExceeded::size_of());
    }
}

use std::fmt;
use packets::Packet;

pub mod v4;
pub mod v6;

/// Assigned internet protocol number
/// 
/// From https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
#[derive(Default, Debug, Copy, Clone, PartialEq, Eq)]
#[repr(C, packed)]
pub struct ProtocolNumber(pub u8);

impl ProtocolNumber {
    pub fn new(value: u8) -> Self {
        ProtocolNumber(value)
    }
}

/// Supported protocol numbers
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
pub mod ProtocolNumbers {
    use super::ProtocolNumber;

    // Transmission Control Protocol
    pub const Tcp: ProtocolNumber = ProtocolNumber(0x06);

    // User Datagram Protocol
    pub const Udp: ProtocolNumber = ProtocolNumber(0x11);

    // Routing Header for IPv6
    pub const Ipv6Route: ProtocolNumber = ProtocolNumber(0x2B);

    // Internet Control Message Protocol for IPv6
    pub const Icmpv6: ProtocolNumber = ProtocolNumber(0x3A);
}

impl fmt::Display for ProtocolNumber {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                &ProtocolNumbers::Tcp => "TCP".to_string(),
                &ProtocolNumbers::Udp => "UDP".to_string(),
                &ProtocolNumbers::Ipv6Route => "IPv6 Route".to_string(),
                &ProtocolNumbers::Icmpv6 => "ICMPv6".to_string(),
                _ => format!("0x{:02x}", self.0)
            }
        )
    }
}

/// Common behaviors shared by IPv4 and IPv6 packets
pub trait IpPacket: Packet {
    /// Returns the assigned protocol number of the header immediately follows
    /// 
    /// For IPv4 headers, this should be the `protocol` field.
    /// For IPv6 and extension headers, this should be the `next header` field.
    fn next_proto(&self) -> ProtocolNumber;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_number_to_string() {
        assert_eq!("TCP", ProtocolNumbers::Tcp.to_string());
        assert_eq!("UDP", ProtocolNumbers::Udp.to_string());
        assert_eq!("IPv6 Route", ProtocolNumbers::Ipv6Route.to_string());
        assert_eq!("ICMPv6", ProtocolNumbers::Icmpv6.to_string());
        assert_eq!("0x00", ProtocolNumber::new(0).to_string());
    }
}

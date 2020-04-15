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

use proc_macro::TokenStream;
use quote::quote;

pub fn gen_icmpv6(input: syn::DeriveInput) -> TokenStream {
    let name = input.ident;

    let expanded = quote! {
        impl<E: Ipv6Packet> crate::packets::icmp::v6::Icmpv6Packet<E, #name> for Icmpv6<E, #name> {
            #[inline]
            fn header(&self) -> &crate::packets::icmp::v6::Icmpv6Header {
                unsafe { self.header.as_ref() }
            }

            #[inline]
            fn header_mut(&mut self) -> &mut crate::packets::icmp::v6::Icmpv6Header {
                unsafe { self.header.as_mut() }
            }

            #[inline]
            fn payload(&self) -> &#name {
                unsafe { self.payload.as_ref() }
            }

            #[inline]
            fn payload_mut(&mut self) -> &mut #name {
                unsafe { self.payload.as_mut() }
            }
        }

        impl<E: Ipv6Packet> crate::packets::PacketBase for crate::packets::icmp::v6::Icmpv6<E, #name> {
            type Envelope = E;

            #[inline]
            fn envelope0(&self) -> &Self::Envelope {
                &self.envelope
            }

            #[inline]
            fn envelope_mut0(&mut self) -> &mut Self::Envelope {
                &mut self.envelope
            }

            #[inline]
            fn into_envelope(self) -> Self::Envelope {
                self.envelope
            }

            #[inline]
            fn offset(&self) -> usize {
                self.offset
            }

            #[inline]
            fn header_len(&self) -> usize {
                crate::packets::icmp::v6::Icmpv6Header::size_of()
            }

            #[inline]
            unsafe fn clone(&self, internal: crate::packets::Internal) -> Self {
                Icmpv6::<E, #name> {
                    envelope: self.envelope.clone(internal),
                    header: self.header,
                    payload: self.payload,
                    offset: self.offset,
                }
            }

            #[inline]
            fn try_parse(envelope: Self::Envelope) -> failure::Fallible<Self> {
                use crate::ensure;
                use crate::packets::icmp::v6::Icmpv6Header;
                use crate::packets::ip::{IpPacket, ProtocolNumbers};
                use crate::packets::{PacketBase, ParseError};

                ensure!(
                    envelope.next_protocol() == ProtocolNumbers::Icmpv6,
                    ParseError::new("not an ICMPv6 packet.")
                );

                let mbuf = envelope.mbuf();
                let offset = envelope.payload_offset();
                let header = mbuf.read_data(offset)?;
                let payload = mbuf.read_data(offset + Icmpv6Header::size_of())?;

                Ok(Icmpv6 {
                    envelope,
                    header,
                    payload,
                    offset,
                })
            }

            #[inline]
            fn try_push(mut envelope: Self::Envelope, _internal: crate::packets::Internal) -> failure::Fallible<Self> {
                use crate::packets::icmp::v6::Icmpv6Header;
                use crate::packets::ip::{IpPacket, ProtocolNumbers};
                use crate::packets::PacketBase;

                let offset = envelope.payload_offset();
                let mbuf = envelope.mbuf_mut();

                mbuf.extend(offset, Icmpv6Header::size_of() + #name::size_of())?;
                let header = mbuf.write_data(offset, &Icmpv6Header::default())?;
                let payload = mbuf.write_data(offset + Icmpv6Header::size_of(), &#name::default())?;

                let mut packet = Icmpv6 {
                    envelope,
                    header,
                    payload,
                    offset,
                };

                packet.header_mut().msg_type = #name::msg_type().0;
                packet
                    .envelope_mut0()
                    .set_next_header(ProtocolNumbers::Icmpv6);

                Ok(packet)
            }

            #[inline]
            fn fix_invariants(&mut self, _internal: crate::packets::Internal) {
                self.fix_invariants();
            }
        }
    };

    expanded.into()
}

pub fn gen_icmpv4(input: syn::DeriveInput) -> TokenStream {
    let name = input.ident;

    let expanded = quote! {
        impl crate::packets::icmp::v4::Icmpv4Packet<#name> for crate::packets::icmp::v4::Icmpv4<#name> {
            #[inline]
            fn header(&self) -> &crate::packets::icmp::v4::Icmpv4Header {
                unsafe { self.header.as_ref() }
            }

            #[inline]
            fn header_mut(&mut self) -> &mut crate::packets::icmp::v4::Icmpv4Header {
                unsafe { self.header.as_mut() }
            }

            #[inline]
            fn payload(&self) -> &#name {
                unsafe { self.payload.as_ref() }
            }

            #[inline]
            fn payload_mut(&mut self) -> &mut #name {
                unsafe { self.payload.as_mut() }
            }
        }

        impl crate::packets::PacketBase for Icmpv4<#name> {
            type Envelope = crate::packets::ip::v4::Ipv4;

            #[inline]
            fn envelope0(&self) -> &Self::Envelope {
                &self.envelope
            }

            #[inline]
            fn envelope_mut0(&mut self) -> &mut Self::Envelope {
                &mut self.envelope
            }

            #[inline]
            fn into_envelope(self) -> Self::Envelope {
                self.envelope
            }

            #[inline]
            fn offset(&self) -> usize {
                self.offset
            }

            #[inline]
            fn header_len(&self) -> usize {
                crate::packets::icmp::v4::Icmpv4Header::size_of()
            }

            #[inline]
            unsafe fn clone(&self, internal: crate::packets::Internal) -> Self {
                Icmpv4::<#name> {
                    envelope: self.envelope.clone(internal),
                    header: self.header,
                    payload: self.payload,
                    offset: self.offset,
                }
            }

            #[inline]
            fn try_parse(envelope: Self::Envelope) -> failure::Fallible<Self> {
                use crate::ensure;
                use crate::packets::icmp::v4::Icmpv4Header;
                use crate::packets::ip::{IpPacket, ProtocolNumbers};
                use crate::packets::{PacketBase, ParseError};

                ensure!(
                    envelope.next_protocol() == ProtocolNumbers::Icmpv4,
                    ParseError::new("not an ICMPv4 packet.")
                );

                let mbuf = envelope.mbuf();
                let offset = envelope.payload_offset();
                let header = mbuf.read_data(offset)?;
                let payload = mbuf.read_data(offset + Icmpv4Header::size_of())?;

                Ok(Icmpv4 {
                    envelope,
                    header,
                    payload,
                    offset,
                })
            }

            #[inline]
            fn try_push(mut envelope: Self::Envelope, _internal: crate::packets::Internal) -> failure::Fallible<Self> {
                use crate::packets::icmp::v4::Icmpv4Header;
                use crate::packets::ip::{IpPacket, ProtocolNumbers};
                use crate::packets::PacketBase;

                let offset = envelope.payload_offset();
                let mbuf = envelope.mbuf_mut();

                mbuf.extend(offset, Icmpv4Header::size_of() + #name::size_of())?;
                let header = mbuf.write_data(offset, &Icmpv4Header::default())?;
                let payload = mbuf.write_data(offset + Icmpv4Header::size_of(), &#name::default())?;

                let mut packet = Icmpv4 {
                    envelope,
                    header,
                    payload,
                    offset,
                };

                packet.header_mut().msg_type = #name::msg_type().0;
                packet
                    .envelope_mut0()
                    .set_next_protocol(ProtocolNumbers::Icmpv4);

                Ok(packet)
            }

            #[inline]
            fn fix_invariants(&mut self, _internal: crate::packets::Internal) {
                self.fix_invariants();
            }
        }
    };

    expanded.into()
}

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

        impl<E: Ipv6Packet> crate::packets::Packet for crate::packets::icmp::v6::Icmpv6<E, #name> {
            /// The preceding type for an ICMPv6 packet must be either an [IPv6]
            /// packet or any IPv6 extension packets.
            ///
            /// [IPv6]: crate::packets::ip::v6::Ipv6
            type Envelope = E;

            #[inline]
            fn envelope(&self) -> &Self::Envelope {
                &self.envelope
            }

            #[inline]
            fn envelope_mut(&mut self) -> &mut Self::Envelope {
                &mut self.envelope
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

            /// Parses the envelope's payload as an ICMPv6 packet.
            ///
            /// [`next_header`] must be set to [`ProtocolNumbers::Icmpv6`].
            /// Otherwise, a parsing error is returned.
            ///
            /// [`next_header`]: crate::packets::ip::v6::Ipv6Packet::next_header
            /// [`ProtocolNumbers::Icmpv6`]: crate::packets::ip::ProtocolNumbers::Icmpv6
            #[inline]
            fn try_parse(envelope: Self::Envelope, _internal: crate::packets::Internal) -> failure::Fallible<Self> {
                use crate::ensure;
                use crate::packets::icmp::v6::Icmpv6Header;
                use crate::packets::ip::{IpPacket, ProtocolNumbers};
                use crate::packets::{Packet, ParseError};

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

            /// Prepends an ICMPv6 packet to the beginning of the envelope's payload.
            ///
            /// [`next_header`] is set to [`ProtocolNumbers::Icmpv6`].
            ///
            /// [`next_header`]: crate::packets::ip::v6::Ipv6Packet::next_header
            /// [`ProtocolNumbers::Icmpv6`]: crate::packets::ip::ProtocolNumbers::Icmpv6
            #[inline]
            fn try_push(mut envelope: Self::Envelope, _internal: crate::packets::Internal) -> failure::Fallible<Self> {
                use crate::packets::icmp::v6::Icmpv6Header;
                use crate::packets::ip::{IpPacket, ProtocolNumbers};
                use crate::packets::Packet;

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
                    .envelope_mut()
                    .set_next_header(ProtocolNumbers::Icmpv6);

                Ok(packet)
            }

            #[inline]
            fn deparse(self) -> Self::Envelope {
                self.envelope
            }

            /// Reconciles the derivable header fields against the changes made to the
            /// packet.
            ///
            /// The implementation is delegated to the private `reconcile` function in
            /// the payload struct.
            #[inline]
            fn reconcile(&mut self) {
                self.reconcile();
            }
        }
    };

    expanded.into()
}

pub fn gen_icmpv4(input: syn::DeriveInput) -> TokenStream {
    let name = input.ident;

    let expanded = quote! {
        impl ::capsule::packets::icmp::v4::Icmpv4Packet for #name {
            #[inline]
            fn msg_type(&self) -> ::capsule::packets::icmp::v4::Icmpv4Type {
                self.icmp().msg_type()
            }

            #[inline]
            fn code(&self) -> u8 {
                self.icmp().code()
            }

            #[inline]
            fn set_code(&mut self, code: u8) {
                self.icmp_mut().set_code(code)
            }

            #[inline]
            fn checksum(&self) -> u16 {
                self.icmp().checksum()
            }
        }

        impl ::capsule::packets::Packet for #name {
            type Envelope = ::capsule::packets::ip::v4::Ipv4;

            #[inline]
            fn envelope(&self) -> &Self::Envelope {
                self.icmp().envelope()
            }

            #[inline]
            fn envelope_mut(&mut self) -> &mut Self::Envelope {
                self.icmp_mut().envelope_mut()
            }

            #[inline]
            fn offset(&self) -> usize {
                self.icmp().offset()
            }

            #[inline]
            fn header_len(&self) -> usize {
                self.icmp().header_len()
            }

            #[inline]
            unsafe fn clone(&self, internal: Internal) -> Self {
                ::capsule::packets::icmp::v4::Icmpv4Message::clone(self, internal)
            }

            #[inline]
            fn try_parse(envelope: Self::Envelope, _internal: ::capsule::packets::Internal) -> ::failure::Fallible<Self> {
                envelope.parse::<::capsule::packets::icmp::v4::Icmpv4>()?.downcast::<#name>()
            }

            #[inline]
            fn try_push(mut envelope: Self::Envelope, internal: ::capsule::packets::Internal) -> ::failure::Fallible<Self> {
                use ::capsule::packets::icmp::v4::{Icmpv4, Icmpv4Header, Icmpv4Message};
                use ::capsule::packets::ip::{IpPacket, ProtocolNumbers};

                let offset = envelope.payload_offset();
                let mbuf = envelope.mbuf_mut();

                mbuf.extend(offset, Icmpv4Header::size_of())?;
                let header = mbuf.write_data(offset, &Icmpv4Header::default())?;

                let mut icmp = Icmpv4 {
                    envelope,
                    header,
                    offset,
                };

                icmp.header_mut().msg_type = <#name as Icmpv4Message>::msg_type().0;
                icmp.envelope_mut()
                    .set_next_protocol(ProtocolNumbers::Icmpv4);

                <#name as Icmpv4Message>::try_push(icmp, internal)
            }

            #[inline]
            fn deparse(self) -> Self::Envelope {
                self.into_icmp().deparse()
            }

            #[inline]
            fn reconcile(&mut self) {
                ::capsule::packets::icmp::v4::Icmpv4Message::reconcile(self);
            }
        }
    };

    expanded.into()
}

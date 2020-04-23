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
        impl<E: ::capsule::packets::ip::v6::Ipv6Packet> ::capsule::packets::icmp::v6::Icmpv6Packet for #name<E> {
            #[inline]
            fn msg_type(&self) -> ::capsule::packets::icmp::v6::Icmpv6Type {
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

        impl<E: ::capsule::packets::ip::v6::Ipv6Packet> ::capsule::packets::Packet for #name<E> {
            type Envelope = E;

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
                ::capsule::packets::icmp::v6::Icmpv6Message::clone(self, internal)
            }

            #[inline]
            fn try_parse(envelope: Self::Envelope, _internal: Internal) -> ::failure::Fallible<Self> {
                envelope.parse::<::capsule::packets::icmp::v6::Icmpv6<E>>()?.downcast::<#name<E>>()
            }

            #[inline]
            fn try_push(mut envelope: Self::Envelope, internal: Internal) -> ::failure::Fallible<Self> {
                use ::capsule::packets::icmp::v6::{Icmpv6, Icmpv6Header, Icmpv6Message};
                use ::capsule::packets::ip::{IpPacket, ProtocolNumbers};

                let offset = envelope.payload_offset();
                let mbuf = envelope.mbuf_mut();

                mbuf.extend(offset, Icmpv6Header::size_of())?;
                let header = mbuf.write_data(offset, &Icmpv6Header::default())?;

                let mut icmp = Icmpv6 {
                    envelope,
                    header,
                    offset,
                };

                icmp.header_mut().msg_type = <#name<E> as Icmpv6Message>::msg_type().0;
                icmp.envelope_mut()
                    .set_next_protocol(ProtocolNumbers::Icmpv6);

                <#name<E> as Icmpv6Message>::try_push(icmp, internal)
            }

            #[inline]
            fn deparse(self) -> Self::Envelope {
                self.into_icmp().deparse()
            }

            #[inline]
            fn reconcile(&mut self) {
                ::capsule::packets::icmp::v6::Icmpv6Message::reconcile(self);
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

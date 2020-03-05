use proc_macro::TokenStream;
use quote::quote;
use syn;

pub fn gen_icmpv6(input: syn::DeriveInput) -> TokenStream {
    let name = input.ident;

    let expanded = quote! {
        impl<E: Ipv6Packet> crate::packets::icmp::v6::Icmpv6Packet<E, #name> for Icmpv6<E, #name> {
            fn payload(&self) -> &#name {
                unsafe { self.payload.as_ref() }
            }

            fn payload_mut(&mut self) -> &mut #name {
                unsafe { self.payload.as_mut() }
            }
        }

        impl<E: Ipv6Packet> crate::packets::Packet for Icmpv6<E, #name> {
            type Envelope = E;
            type Header = Icmpv6Header;

            #[inline]
            fn envelope(&self) -> &Self::Envelope {
                &self.envelope
            }

            #[inline]
            fn envelope_mut(&mut self) -> &mut Self::Envelope {
                &mut self.envelope
            }

            #[doc(hidden)]
            #[inline]
            fn header(&self) -> &Self::Header {
                unsafe { self.header.as_ref() }
            }

            #[doc(hidden)]
            #[inline]
            fn header_mut(&mut self) -> &mut Self::Header {
                unsafe { self.header.as_mut() }
            }

            #[inline]
            fn offset(&self) -> usize {
                self.offset
            }

            #[doc(hidden)]
            #[inline]
            fn do_parse(envelope: Self::Envelope) -> Result<Self> {
                ensure!(
                    envelope.next_proto() == ProtocolNumbers::Icmpv6,
                    ParseError::new("not an ICMPv6 packet.")
                );

                let mbuf = envelope.mbuf();
                let offset = envelope.payload_offset();
                let header = mbuf.read_data(offset)?;
                let payload = mbuf.read_data(offset + Self::Header::size_of())?;

                Ok(Icmpv6 {
                    envelope: CondRc::new(envelope),
                    header,
                    payload,
                    offset,
                })
            }

            #[doc(hidden)]
            #[inline]
            fn do_push(mut envelope: Self::Envelope) -> Result<Self> {
                let offset = envelope.payload_offset();
                let mbuf = envelope.mbuf_mut();

                mbuf.extend(offset, Self::Header::size_of() + #name::size_of())?;
                let header = mbuf.write_data(offset, &Self::Header::default())?;
                let payload = mbuf.write_data(offset + Self::Header::size_of(), &#name::default())?;

                let mut packet = Icmpv6 {
                    envelope: CondRc::new(envelope),
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
            fn remove(mut self) -> Result<Self::Envelope> {
                let offset = self.offset();
                let len = self.header_len();
                self.mbuf_mut().shrink(offset, len)?;
                Ok(self.envelope.into_owned())
            }

            // Expected to be implemented within struct impl.
            #[inline]
            fn cascade(&mut self) {
                self.cascade()
            }

            #[inline]
            fn deparse(self) -> Self::Envelope {
                self.envelope.into_owned()
            }
        }
    };

    expanded.into()
}

pub fn gen_icmpv4(input: syn::DeriveInput) -> TokenStream {
    let name = input.ident;

    let expanded = quote! {
        impl crate::packets::icmp::v4::Icmpv4Packet<#name> for Icmpv4<#name> {

            fn payload(&self) -> &#name {
                unsafe { self.payload.as_ref() }
            }

            fn payload_mut(&mut self) -> &mut #name {
                unsafe { self.payload.as_mut() }
            }
        }

        impl crate::packets::Packet for Icmpv4<#name> {
            type Header = Icmpv4Header;
            type Envelope = Ipv4;

            #[inline]
            fn envelope(&self) -> &Self::Envelope {
                    &self.envelope
            }

            #[inline]
            fn envelope_mut(&mut self) -> &mut Self::Envelope {
                &mut self.envelope
            }

            #[doc(hidden)]
            #[inline]
            fn header(&self) -> &Self::Header {
                unsafe { self.header.as_ref() }
            }

            #[doc(hidden)]
            #[inline]
            fn header_mut(&mut self) -> &mut Self::Header {
                unsafe { self.header.as_mut() }
            }

            #[inline]
            fn offset(&self) -> usize {
                self.offset
            }

            #[doc(hidden)]
            #[inline]
            fn do_parse(envelope: Self::Envelope) -> Result<Self> {
                ensure!(
                    envelope.next_proto() == ProtocolNumbers::Icmpv4,
                    ParseError::new("not an ICMPv4 packet.")
                );

                let mbuf = envelope.mbuf();
                let offset = envelope.payload_offset();
                let header = mbuf.read_data(offset)?;
                let payload = mbuf.read_data(offset + Self::Header::size_of())?;

                Ok(Icmpv4 {
                    envelope: CondRc::new(envelope),
                    header,
                    payload,
                    offset,
                })
            }

            #[doc(hidden)]
            #[inline]
            fn do_push(mut envelope: Self::Envelope) -> Result<Self> {
                let offset = envelope.payload_offset();
                let mbuf = envelope.mbuf_mut();

                mbuf.extend(offset, Self::Header::size_of() + #name::size_of())?;
                let header = mbuf.write_data(offset, &Self::Header::default())?;
                let payload = mbuf.write_data(offset + Self::Header::size_of(), &#name::default())?;

                let mut packet = Icmpv4 {
                    envelope: CondRc::new(envelope),
                    header,
                    payload,
                    offset,
                };

                packet.header_mut().msg_type = #name::msg_type().0;
                packet
                    .envelope_mut()
                    .set_next_proto(ProtocolNumbers::Icmpv4);

                Ok(packet)
            }

            #[inline]
            fn remove(mut self) -> Result<Self::Envelope> {
                let offset = self.offset();
                let len = self.header_len();
                self.mbuf_mut().shrink(offset, len)?;
                Ok(self.envelope.into_owned())
            }

            // Expected to be implemented within struct impl.
            #[inline]
            fn cascade(&mut self) {
                self.cascade()
            }

            #[inline]
            fn deparse(self) -> Self::Envelope {
                self.envelope.into_owned()
            }
        };
    };

    expanded.into()
}

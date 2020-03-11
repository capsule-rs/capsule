use proc_macro::TokenStream;
use quote::quote;
use syn;

#[derive(Default)]
struct Assocs<'a> {
    envelope_ty: Option<&'a syn::Type>,
    header_ty: Option<&'a syn::Type>,
}

pub fn gen_icmpv6(input: syn::DeriveInput) -> TokenStream {
    let name = input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    let assocs = if let syn::Data::Struct(syn::DataStruct { ref fields, .. }) = input.data {
        extract_assocs(fields)
    } else {
        panic!("Only implemented for structs!")
    };

    let envelope = assocs.envelope_ty.expect("");
    let header = assocs.header_ty.expect("");

    let expanded = quote! {
        impl #impl_generics Icmpv6Packet #ty_generics for #name #ty_generics #where_clause {

            fn payload(&self) -> &P {
                unsafe { self.payload.as_ref() }
            }

            fn payload_mut(&mut self) -> &mut P {
                unsafe { self.payload.as_mut() }
            }
        }

        impl #impl_generics Packet for #name #ty_generics #where_clause {
            type Envelope = #envelope;
            type Header = #header;

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

                mbuf.extend(offset, Self::Header::size_of() + P::size_of())?;
                let header = mbuf.write_data(offset, &Self::Header::default())?;
                let payload = mbuf.write_data(offset + Self::Header::size_of(), &P::default())?;

                let mut packet = Icmpv6 {
                    envelope: CondRc::new(envelope),
                    header,
                    payload,
                    offset,
                };

                packet.header_mut().msg_type = P::msg_type().0;
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
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    let assocs = if let syn::Data::Struct(syn::DataStruct { ref fields, .. }) = input.data {
        extract_assocs(fields)
    } else {
        panic!("Only implemented for structs!")
    };

    let envelope = assocs.envelope_ty.expect("");
    let header = assocs.header_ty.expect("");

    let expanded = quote! {
        impl #impl_generics Icmpv4Packet #ty_generics for #name #ty_generics #where_clause {

            fn payload(&self) -> &P {
                unsafe { self.payload.as_ref() }
            }

            fn payload_mut(&mut self) -> &mut P {
                unsafe { self.payload.as_mut() }
            }
        }

        impl #impl_generics Packet for #name #ty_generics #where_clause {
            type Envelope = #envelope;
            type Header = #header;

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

                mbuf.extend(offset, Self::Header::size_of() + P::size_of())?;
                let header = mbuf.write_data(offset, &Self::Header::default())?;
                let payload = mbuf.write_data(offset + Self::Header::size_of(), &P::default())?;

                let mut packet = Icmpv4 {
                    envelope: CondRc::new(envelope),
                    header,
                    payload,
                    offset,
                };

                packet.header_mut().msg_type = P::msg_type().0;
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

#[allow(clippy::needless_lifetimes)]
fn extract_assocs<'a>(fields: &'a syn::Fields) -> Assocs<'a> {
    fields.iter().fold(Assocs::default(), |mut acc, field| {
        if is_header(field) {
            acc.header_ty = extract(&field.ty);
            acc
        } else if is_envelope(field) {
            acc.envelope_ty = extract(&field.ty);
            acc
        } else {
            acc
        }
    })
}

fn is_header(field: &syn::Field) -> bool {
    field.ident.is_some() && field.ident.as_ref().unwrap() == "header"
}

fn is_envelope(field: &syn::Field) -> bool {
    field.ident.is_some() && field.ident.as_ref().unwrap() == "envelope"
}

fn extract(ty: &syn::Type) -> Option<&syn::Type> {
    if let syn::Type::Path(syn::TypePath {
        path: syn::Path { segments: segs, .. },
        ..
    }) = ty
    {
        if let Some(relative_ty) = segs.last() {
            if relative_ty.ident == "NonNull" || relative_ty.ident == "CondRc" {
                if let syn::PathArguments::AngleBracketed(ref a) = relative_ty.arguments {
                    if let Some(arg) = a.args.first() {
                        if let syn::GenericArgument::Type(ref inner_ty) = arg {
                            return Some(inner_ty);
                        }
                    }
                }
            } else {
                return Some(&ty);
            }
        } else {
            return Some(&ty);
        }
    }

    None
}
